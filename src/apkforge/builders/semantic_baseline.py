"""C.5 precondition: semantic no-op baseline.

C.4 proved that every corpus APK survives decode -> build -> align -> sign -> verify.
This module answers the next question: does an *unmodified* round trip produce only
acceptable rebuild noise? Each APK is rebuilt through ``BuildService.build_pipeline``
with no modification, compared with the original by ``DiffEngine``, and every
observation is classified with :func:`apkforge.diff.expectations.verify_expectations`
(no expected changes).

The result per APK is one of:

- ``EQUIVALENT``: every observation is explained by a documented noise rule
- ``EQUIVALENT_WITH_RESIDUE``: additionally, unpaired resource renames remain whose
  removed and added sizes correspond exactly (known-limitations §2); they are recorded
  per APK and accepted for that APK only, by exact path
- ``NOT_EQUIVALENT``: any other unexplained observation
- ``UNDETERMINED``: the diff was not complete, so equivalence could not be established
- ``BUILD_FAILED``: the no-op rebuild itself failed

This is a separate, explicitly named result; it never rewrites the C.4 build baseline.

Schema versions:

- 1 (Phase C.5): noise rule ids and residue per APK. Noise is accepted by path rule;
  content is not compared. Still loadable; reported as a *legacy* baseline.
- 2 (Phase E): adds the toolchain identity the baseline was measured with and, per APK,
  a content-aware :class:`~apkforge.diff.normalization.NoiseFingerprint`. A v2 baseline
  is only used when the current toolchain identity matches exactly
  (:meth:`NoopSemanticBaseline.check`); otherwise it is ``INCOMPATIBLE``.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.builders.models import BuildOptions
from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import (
    NOISE_RULES,
    Observation,
    ObservationClass,
    verify_expectations,
)
from apkforge.diff.normalization import NoiseFingerprint, ToolchainIdentity

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.builders.service import BuildService
    from apkforge.diff.models import DiffResult

__all__ = [
    "BaselineCheck",
    "BaselineStatus",
    "NoopSemanticBaseline",
    "NoopSemanticEntry",
    "SemanticResult",
    "classify_noop_diff",
    "current_toolchain_identity",
    "run_semantic_noop",
]

SCHEMA_VERSION = 2


class BaselineStatus(StrEnum):
    """Whether a baseline can establish the noise floor for one APK and toolchain."""

    COMPATIBLE = "COMPATIBLE"  # v2, same toolchain identity, usable entry
    #: v2, same toolchain, but the APK's no-op diff itself was incomplete (UNDETERMINED);
    #: the fingerprint is used, the noise floor is only partially established
    PARTIAL = "BASELINE_PARTIAL"
    LEGACY_PATH_RULES = "LEGACY_PATH_RULES"  # v1: usable, but content is not compared
    INCOMPATIBLE = "BASELINE_INCOMPATIBLE"  # toolchain/schema identity differs
    TOOLCHAIN_UNKNOWN = "TOOLCHAIN_UNKNOWN"  # the build toolchain could not be identified
    NO_ENTRY = "NO_ENTRY"  # no entry for this APK SHA-256
    NOT_EQUIVALENT = "NOT_EQUIVALENT"  # the APK's no-op rebuild was not equivalent
    MISSING = "MISSING"  # no baseline given


class BaselineCheck(BaseModel):
    status: BaselineStatus
    usable: bool
    content_aware: bool = False
    reasons: list[str] = Field(default_factory=list)
    entry_id: str | None = None
    schema_version: int | None = None
    baseline_toolchain: ToolchainIdentity | None = None
    current_toolchain: ToolchainIdentity | None = None


class SemanticResult(StrEnum):
    EQUIVALENT = "EQUIVALENT"
    EQUIVALENT_WITH_RESIDUE = "EQUIVALENT_WITH_RESIDUE"
    NOT_EQUIVALENT = "NOT_EQUIVALENT"
    UNDETERMINED = "UNDETERMINED"
    BUILD_FAILED = "BUILD_FAILED"


class NoopSemanticEntry(BaseModel):
    id: str
    filename: str
    sha256: str
    package_name: str | None = None
    build_success: bool
    build_failure: str | None = None
    input_unchanged: bool | None = None
    rebuilt_sha256: str | None = None
    signer_sha256: str | None = None
    diff_status: str | None = None
    observation_counts: dict[str, int] = Field(default_factory=dict)
    noise_rule_counts: dict[str, int] = Field(default_factory=dict)
    residue: list[Observation] = Field(default_factory=list)
    unexpected: list[Observation] = Field(default_factory=list)
    unknown: list[Observation] = Field(default_factory=list)
    diff_failures: list[str] = Field(default_factory=list)
    result: SemanticResult
    notes: list[str] = Field(default_factory=list)
    #: v2: content-aware accepted differences (None in a v1 baseline)
    fingerprint: NoiseFingerprint | None = None
    #: v2: comparator -> status of the no-op diff (what was / was not comparable)
    comparisons: dict[str, str] = Field(default_factory=dict)
    raw_counts: dict[str, int] = Field(default_factory=dict)


class NoopSemanticBaseline(BaseModel):
    schema_version: int = SCHEMA_VERSION
    name: str = "C.5 precondition semantic no-op baseline"
    purpose: str = (
        "Records what an unmodified BuildService round trip changes, classified by the "
        "documented rebuild-noise rules. Separate from the C.4 build baseline."
    )
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    toolchain: dict[str, Any] = Field(default_factory=dict)
    #: v2: what must match for this baseline to be reused (None in a v1 baseline)
    toolchain_identity: ToolchainIdentity | None = None
    noise_rules: dict[str, str] = Field(default_factory=lambda: dict(NOISE_RULES))
    entries: list[NoopSemanticEntry] = Field(default_factory=list)

    def entry_for(self, sha256: str) -> NoopSemanticEntry | None:
        return next((e for e in self.entries if e.sha256 == sha256.lower()), None)

    def check(self, sha256: str, current: ToolchainIdentity | None) -> BaselineCheck:
        """Can this baseline establish the noise floor of *sha256* built with *current*?

        A v2 baseline is used only with an identical toolchain identity; no
        cross-toolchain compatibility rule has been validated, so a mismatch is
        ``BASELINE_INCOMPATIBLE`` (never silently reinterpreted as noise). A v1
        baseline has no toolchain identity or content and is ``LEGACY_PATH_RULES``.
        """
        e = self.entry_for(sha256)

        def result(
            status: BaselineStatus, usable: bool, reasons: list[str], content_aware: bool = False
        ) -> BaselineCheck:
            return BaselineCheck(
                status=status,
                usable=usable,
                content_aware=content_aware,
                reasons=reasons,
                entry_id=e.id if e else None,
                schema_version=self.schema_version,
                baseline_toolchain=self.toolchain_identity,
                current_toolchain=current,
            )

        if e is None:
            return result(
                BaselineStatus.NO_ENTRY, False, [f"no baseline entry for SHA-256 {sha256}"]
            )
        partial = (
            e.result == SemanticResult.UNDETERMINED
            and not e.unexpected
            and e.fingerprint is not None
            and self.toolchain_identity is not None
        )
        if not partial and e.result not in (
            SemanticResult.EQUIVALENT,
            SemanticResult.EQUIVALENT_WITH_RESIDUE,
        ):
            return result(
                BaselineStatus.NOT_EQUIVALENT,
                False,
                [f"the no-op rebuild of this APK was {e.result}"],
            )
        if self.toolchain_identity is None or e.fingerprint is None:
            return result(
                BaselineStatus.LEGACY_PATH_RULES,
                True,
                [
                    f"schema {self.schema_version} baseline: no toolchain identity or content "
                    "fingerprint; noise is accepted by path rule without comparing content"
                ],
            )
        if current is None or not current.known:
            # Content identity with the baseline toolchain's own output is still
            # evidence; anything that differs cannot be attributed (-> UNKNOWN).
            return result(
                BaselineStatus.TOOLCHAIN_UNKNOWN,
                True,
                [
                    "the toolchain that built the APK under test is not identified; noise is "
                    "accepted only on exact content identity, other rebuild differences are "
                    "UNKNOWN"
                ],
                content_aware=True,
            )
        diffs = self.toolchain_identity.differences(current)
        if diffs:
            return result(BaselineStatus.INCOMPATIBLE, False, diffs)
        if partial:
            return result(
                BaselineStatus.PARTIAL,
                True,
                [
                    "the no-op diff of this APK was incomplete "
                    f"({'; '.join(e.diff_failures) or e.result}); noise is accepted by content, "
                    "but the noise floor is not fully established"
                ],
                content_aware=True,
            )
        return result(BaselineStatus.COMPATIBLE, True, [], content_aware=True)

    def allowances(self, sha256: str) -> tuple[set[str], set[tuple[str, str, str]]] | None:
        """Noise rules and residue established for this APK, or None if not usable."""
        e = self.entry_for(sha256)
        if e is None or e.result not in (
            SemanticResult.EQUIVALENT,
            SemanticResult.EQUIVALENT_WITH_RESIDUE,
        ):
            return None
        return set(e.noise_rule_counts), {(o.category, o.kind, o.identifier) for o in e.residue}


def _is_resource_file(o: Observation) -> bool:
    return (
        o.category == "file"
        and o.kind in ("added", "removed")
        and o.detail.get("file_category") == "resource"
        and o.identifier.startswith("res/")
    )


def classify_noop_diff(
    diff: DiffResult,
) -> tuple[SemanticResult, dict[str, Any]]:
    """Classify an original-vs-no-op-rebuild diff."""
    verdict = verify_expectations(diff, [])
    unexpected = [c.observation for c in verdict.of(ObservationClass.UNEXPECTED)]
    unknown = [c.observation for c in verdict.of(ObservationClass.UNKNOWN)]

    residue: list[Observation] = []
    candidates = [o for o in unexpected if _is_resource_file(o)]
    removed = Counter(o.detail.get("size") for o in candidates if o.kind == "removed")
    added = Counter(o.detail.get("size") for o in candidates if o.kind == "added")
    # Unpaired renames: accept only when removed and added sizes correspond exactly.
    if candidates and removed == added:
        residue = candidates
        unexpected = [o for o in unexpected if o not in residue]

    fingerprint = NoiseFingerprint.from_verdict(verdict)
    fingerprint.add_residue(residue)
    counts = Counter(f"{c.observation.category}:{c.observation.kind}" for c in verdict.observations)
    diff_failures = [
        f for f in verdict.failures if not f.endswith(("unexpected change(s)", "be classified"))
    ]
    if unexpected:
        result = SemanticResult.NOT_EQUIVALENT
    elif unknown or diff_failures:
        result = SemanticResult.UNDETERMINED
    elif residue:
        result = SemanticResult.EQUIVALENT_WITH_RESIDUE
    else:
        result = SemanticResult.EQUIVALENT
    return result, {
        "diff_status": verdict.diff_status,
        "observation_counts": dict(sorted(counts.items())),
        "noise_rule_counts": dict(sorted(verdict.noise_rule_counts.items())),
        "residue": residue,
        "unexpected": unexpected,
        "unknown": unknown,
        "diff_failures": diff_failures,
        "fingerprint": fingerprint,
        "comparisons": {k: str(v.status) for k, v in diff.comparisons.items()},
        "raw_counts": dict(diff.raw.counts) if diff.raw else {},
    }


def current_toolchain_identity(service: Any) -> ToolchainIdentity | None:  # noqa: ANN401
    """Toolchain identity of a BuildService (None if it cannot be determined)."""
    from apkforge.builders.corpus import toolchain_versions

    check_fn = getattr(service, "check_toolchain", None)
    if check_fn is None:
        return None
    try:
        check = check_fn()
    except Exception:
        return None
    if hasattr(check, "to_dict"):
        versions = toolchain_versions(check.to_dict())
    else:
        tools = getattr(check, "tools", {}) or {}
        versions = {
            k: (getattr(v, "version", None) if not isinstance(v, dict) else v.get("version"))
            for k, v in tools.items()
        }
    ident = ToolchainIdentity.from_versions(versions)
    return ident if ident.known else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_semantic_noop(
    service: BuildService,
    apk: Path,
    *,
    entry_id: str,
    work_dir: Path,
    diff_engine: DiffEngine | None = None,
) -> NoopSemanticEntry:
    """No-op round trip of *apk* through BuildService, then classify the semantic diff."""
    sha = _sha256(apk)
    out = work_dir / f"{apk.stem}.noop.apk"
    res = service.build_pipeline(
        apk, BuildOptions(output_apk=out, overwrite_output=True, work_dir=work_dir / "builds")
    )
    base: dict[str, Any] = {
        "id": entry_id,
        "filename": apk.name,
        "sha256": sha,
        "build_success": res.success,
        "input_unchanged": res.input_unchanged,
        "signer_sha256": res.certificate.sha256_digest if res.certificate else None,
    }
    if not res.success or res.output_apk is None:
        return NoopSemanticEntry(
            **base,
            build_failure=f"{res.failure_stage}: {res.failure_category}: {res.failure_cause}",
            result=SemanticResult.BUILD_FAILED,
        )
    diff = (diff_engine or DiffEngine()).diff(apk, res.output_apk)
    result, detail = classify_noop_diff(diff)
    return NoopSemanticEntry(
        **base,
        package_name=diff.apk_a.package_name,
        rebuilt_sha256=_sha256(res.output_apk),
        result=result,
        **detail,
    )
