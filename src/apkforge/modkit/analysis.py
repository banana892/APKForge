"""Post-ModKit analysis hooks: everything reuses the existing engines.

A published ModKit output is still untrusted. These hooks feed it, together with
the original, into the existing infrastructure - nothing here re-implements a
diff, a privacy rule or a verification invariant:

- Phase E :class:`~apkforge.diff.engine.DiffEngine` - raw/semantic diff,
- Phase F :class:`~apkforge.privacy.service.PrivacyAnalysisService` - before/after
  privacy findings,
- Phase B/F :class:`~apkforge.security.engine.SecurityEngine` - before/after
  security findings,
- H.4 :meth:`~apkforge.transformation.verifier.TransformationVerifier.verify_external`
  - control-rebuild noise floor, every difference classified.

Downstream build/signing stays with :class:`~apkforge.builders.BuildService`; a
ModKit result's ``published.path`` is an ordinary APK path for it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from apkforge.core.models import AnalysisStatus

if TYPE_CHECKING:
    from apkforge.diff.engine import DiffEngine
    from apkforge.diff.expectations import ExpectedChange
    from apkforge.diff.models import DiffResult
    from apkforge.diff.normalization import ToolchainIdentity
    from apkforge.modkit.models import ModKitExecutionResult
    from apkforge.transformation.verification import TransformationVerificationResult
    from apkforge.transformation.verifier import TransformationVerifier

__all__ = [
    "FindingDelta",
    "ModKitAnalysisReport",
    "ModKitPostAnalysis",
    "compare_findings",
    "output_path",
]


class FindingDelta(BaseModel):
    """Before/after comparison of one analysis' findings (ids, multiset-aware)."""

    model_config = ConfigDict(frozen=True)

    source: str
    status_before: str
    status_after: str
    findings_before: tuple[str, ...] = ()
    findings_after: tuple[str, ...] = ()
    introduced: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    retained: tuple[str, ...] = ()
    #: Retained ids whose severity/confidence/evidence changed.
    changed: tuple[str, ...] = ()
    #: False when either analysis was not COMPLETE: the delta is partial/unknown.
    complete: bool = True
    limitations: tuple[str, ...] = ()


class ModKitAnalysisReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    modkit_id: str
    original_sha256: str
    output_sha256: str
    diff_status: str | None = None
    diff_summary: dict[str, Any] | None = None
    privacy: FindingDelta | None = None
    security: FindingDelta | None = None
    verification_status: str | None = None
    verification_reason: str | None = None
    limitations: tuple[str, ...] = ()


def _fingerprint(f: Any) -> tuple[str, str, tuple[str, ...]]:  # noqa: ANN401 - finding models
    evidence = getattr(f, "evidence_values", None)
    if evidence is None:
        evidence = [
            f"{getattr(e, 'location', '')}={getattr(e, 'snippet', '')}"
            for e in getattr(f, "evidence", [])
        ]
    return (str(f.severity), str(f.confidence), tuple(sorted(str(v) for v in evidence)))


def _keyed(findings: list[Any]) -> dict[str, tuple[str, str, tuple[str, ...]]]:
    """Finding id -> fingerprint; an id occurring n times is keyed ``id``, ``id#2``, ..."""
    seen: Counter[str] = Counter()
    out = {}
    for f in sorted(findings, key=lambda f: (f.id, _fingerprint(f))):
        seen[f.id] += 1
        out[f.id if seen[f.id] == 1 else f"{f.id}#{seen[f.id]}"] = _fingerprint(f)
    return out


def compare_findings(
    source: str,
    before: list[Any],
    after: list[Any],
    *,
    status_before: AnalysisStatus | str,
    status_after: AnalysisStatus | str,
) -> FindingDelta:
    """Classify findings as introduced / removed / retained (/ changed)."""
    fp_b, fp_a = _keyed(before), _keyed(after)
    ids_b, ids_a = sorted(fp_b), sorted(fp_a)
    retained = sorted(set(ids_b) & set(ids_a))
    complete = str(status_before) == str(status_after) == AnalysisStatus.COMPLETE.value
    limitations = (
        ()
        if complete
        else (
            f"{source} analysis was {status_before} before and {status_after} after: "
            "introduced/removed findings may be incomplete (partial/unknown change)",
        )
    )
    return FindingDelta(
        source=source,
        status_before=str(status_before),
        status_after=str(status_after),
        findings_before=tuple(ids_b),
        findings_after=tuple(ids_a),
        introduced=tuple(sorted(set(ids_a) - set(ids_b))),
        removed=tuple(sorted(set(ids_b) - set(ids_a))),
        retained=tuple(retained),
        changed=tuple(i for i in retained if fp_b[i] != fp_a[i]),
        complete=complete,
        limitations=limitations,
    )


def output_path(result: ModKitExecutionResult) -> Path:
    """The published APK of a successful execution (ValueError otherwise)."""
    if result.published is None or result.original is None:
        raise ValueError(
            f"ModKit execution {result.execution_id} published no output ({result.status})"
        )
    return Path(result.published.path)


class ModKitPostAnalysis:
    """Runs the standard post-ModKit analyses on ``original -> published output``."""

    def __init__(
        self,
        *,
        diff_engine: DiffEngine | None = None,
        verifier: TransformationVerifier | None = None,
    ) -> None:
        self._engine = diff_engine
        self._verifier = verifier

    @property
    def engine(self) -> DiffEngine:
        if self._engine is None:
            from apkforge.diff.engine import DiffEngine

            self._engine = DiffEngine()
        return self._engine

    def diff(self, result: ModKitExecutionResult) -> DiffResult:
        out = output_path(result)
        assert result.original is not None
        return self.engine.diff(Path(result.original.path), out)

    def privacy(self, result: ModKitExecutionResult) -> FindingDelta:
        from apkforge.privacy.service import PrivacyAnalysisService

        out = output_path(result)
        assert result.original is not None
        svc = PrivacyAnalysisService()
        before = svc.run_analysis(Path(result.original.path))
        after = svc.run_analysis(out)
        return compare_findings(
            "privacy",
            list(before.findings),
            list(after.findings),
            status_before=before.status,
            status_after=after.status,
        )

    def security(self, result: ModKitExecutionResult) -> FindingDelta:
        from apkforge.security.engine import SecurityEngine

        out = output_path(result)
        assert result.original is not None
        engine = SecurityEngine()
        before = engine.analyze(Path(result.original.path))
        after = engine.analyze(out)
        return compare_findings(
            "security",
            list(before.findings),
            list(after.findings),
            status_before=before.status,
            status_after=after.status,
        )

    def verify(
        self,
        result: ModKitExecutionResult,
        control: Path | None,
        *,
        expected: list[ExpectedChange] | None = None,
        toolchain: ToolchainIdentity | None = None,
    ) -> TransformationVerificationResult:
        """H.4 verification of the ModKit output with *control* (an unmodified
        rebuild of the original) as the measured noise floor."""
        if self._verifier is None:
            from apkforge.transformation.verifier import TransformationVerifier

            self._verifier = TransformationVerifier(None, diff_engine=self._engine)
        out = output_path(result)
        assert result.original is not None
        return self._verifier.verify_external(
            Path(result.original.path), control, out, expected=expected, toolchain=toolchain
        )

    def run(
        self,
        result: ModKitExecutionResult,
        *,
        diff: bool = True,
        privacy: bool = True,
        security: bool = True,
        control: Path | None = None,
        verify: bool = False,
        expected: list[ExpectedChange] | None = None,
    ) -> ModKitAnalysisReport:
        out = output_path(result)
        assert result.original is not None and result.published is not None
        report: dict[str, Any] = {
            "execution_id": result.execution_id,
            "modkit_id": result.identity.modkit_id,
            "original_sha256": result.original.sha256,
            "output_sha256": result.published.sha256,
        }
        limitations = [
            "Post-ModKit analysis is static: it reports what changed, not whether the "
            "ModKit's transformation is semantically safe."
        ]
        if diff:
            d = self.diff(result)
            report["diff_status"] = str(d.status)
            report["diff_summary"] = d.summary.model_dump(mode="json", exclude={"text_lines"})
        if privacy:
            report["privacy"] = self.privacy(result)
        if security:
            report["security"] = self.security(result)
        if verify:
            v = self.verify(result, control, expected=expected)
            report["verification_status"] = str(v.status)
            report["verification_reason"] = v.status_reason
        if not out.is_file():
            limitations.append("the published output no longer exists")
        return ModKitAnalysisReport(**report, limitations=tuple(limitations))
