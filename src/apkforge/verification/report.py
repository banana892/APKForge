"""Diff + verification report (Phase E, sections per the evidence discipline).

:class:`VerificationReport` is the stable JSON document (``schema_version``) produced by
``apkforge verify`` and attached to a modification pipeline run. It is self-describing:
it can be read without the Python source. :func:`render_markdown` renders the same
content as text, section by section:

RAW DIFF, NORMALIZED DIFF, SEMANTIC DIFF, SECURITY-RELEVANT DIFF, EXPECTED CHANGES,
ACTUAL CHANGES, UNEXPECTED CHANGES, UNKNOWN / UNDETERMINED, VERIFICATION, LIMITATIONS —
and a closing statement that separates observed facts, inferences, risk assessment and
unknowns.

No absolute local paths are embedded: APKs are identified by file name and SHA-256.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

# Runtime imports: pydantic resolves these field annotations when the model is built.
from apkforge.builders.semantic_baseline import BaselineCheck  # noqa: TC001
from apkforge.diff.expectations import ExpectedChange, ObservationClass
from apkforge.diff.normalization import ToolchainIdentity  # noqa: TC001
from apkforge.diff.security import SecurityDiff  # noqa: TC001
from apkforge.verification.models import VerificationMatrix  # noqa: TC001

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.diff.expectations import ClassifiedObservation, ExpectationVerdict
    from apkforge.diff.models import DiffResult

__all__ = ["REPORT_SCHEMA_VERSION", "VerificationReport", "build_report", "render_markdown"]

REPORT_SCHEMA_VERSION = 1


class APKRef(BaseModel):
    file_name: str | None = None
    sha256: str | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None


def _obs(c: ClassifiedObservation) -> dict[str, Any]:
    o = c.observation
    d: dict[str, Any] = {
        "category": o.category,
        "kind": o.kind,
        "identifier": o.identifier,
        "classification": str(c.classification),
        "reason": c.reason,
    }
    if c.rule:
        d["rule"] = c.rule
    if c.assurance:
        d["assurance"] = c.assurance
    if o.detail:
        d["detail"] = o.detail
    if o.content_before or o.content_after:
        d["content_before"], d["content_after"] = o.content_before, o.content_after
    return d


class VerificationReport(BaseModel):
    schema_version: int = REPORT_SCHEMA_VERSION
    kind: str = "apkforge.verification_report"
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    original: APKRef
    modified: APKRef
    toolchain: ToolchainIdentity | None = None
    baseline: BaselineCheck | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    normalized: dict[str, Any] = Field(default_factory=dict)
    semantic: dict[str, Any] = Field(default_factory=dict)
    security: SecurityDiff | None = None
    requested: list[str] = Field(default_factory=list)
    expected: list[ExpectedChange] = Field(default_factory=list)
    actual: list[dict[str, Any]] = Field(default_factory=list)
    unexpected: list[dict[str, Any]] = Field(default_factory=list)
    unknown: list[dict[str, Any]] = Field(default_factory=list)
    verification: VerificationMatrix
    limitations: list[str] = Field(default_factory=list)
    statements: dict[str, list[str]] = Field(default_factory=dict)


def _ref(identity: Any, path: Path | None = None) -> APKRef:  # noqa: ANN401
    return APKRef(
        file_name=getattr(identity, "file_name", None) or (path.name if path else None),
        sha256=getattr(identity, "sha256", None),
        package_name=getattr(identity, "package_name", None),
        version_name=getattr(identity, "version_name", None),
        version_code=getattr(identity, "version_code", None),
    )


def build_report(
    *,
    diff: DiffResult | None,
    verdict: ExpectationVerdict | None,
    security: SecurityDiff | None,
    matrix: VerificationMatrix,
    baseline: BaselineCheck | None,
    toolchain: ToolchainIdentity | None,
    expected: list[ExpectedChange],
    requested: list[str] | None = None,
    original: Path | None = None,
    modified: Path | None = None,
) -> VerificationReport:
    raw: dict[str, Any] = {}
    if diff is not None and diff.raw is not None:
        raw = {
            "schema_version": diff.raw.schema_version,
            "sha256_before": diff.raw.sha256_before,
            "sha256_after": diff.raw.sha256_after,
            "counts": diff.raw.counts,
            "counts_by_kind": diff.raw.counts_by_kind,
            "metadata_only_changes": diff.raw.metadata_only_changes,
            "problems": diff.raw.problems,
            "changed": [e.model_dump(mode="json") for e in diff.raw.changed()],
        }
    elif diff is not None:
        raw = {"available": False, "reason": "APK files were not available to the diff"}
    normalized: dict[str, Any] = {}
    actual: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    if verdict is not None:
        assurance: dict[str, int] = {}
        for c in verdict.of(ObservationClass.REBUILD_NOISE):
            assurance[c.assurance or "none"] = assurance.get(c.assurance or "none", 0) + 1
        normalized = {
            "mode": verdict.mode,
            "counts": verdict.counts,
            "noise_by_rule": verdict.noise_rule_counts,
            "noise_by_assurance": dict(sorted(assurance.items())),
            "failures": verdict.failures,
        }
        actual = [
            _obs(c)
            for c in verdict.observations
            if c.classification
            in (ObservationClass.EXPECTED_MODIFICATION, ObservationClass.PLANNED_ENTRY)
        ]
        unexpected = [_obs(c) for c in verdict.of(ObservationClass.UNEXPECTED)]
        unknown = [_obs(c) for c in verdict.of(ObservationClass.UNKNOWN)]
    semantic: dict[str, Any] = {}
    if diff is not None:
        semantic = {
            "diff_status": str(diff.status),
            "comparisons": {k: v.model_dump(mode="json") for k, v in diff.comparisons.items()},
            "manifest_tree": {
                "status": diff.manifest_tree.status,
                "elements_before": diff.manifest_tree.elements_before,
                "elements_after": diff.manifest_tree.elements_after,
                "changes": len(diff.manifest_tree.changes),
            },
            "summary": diff.summary.model_dump(mode="json", exclude={"text_lines"}),
        }
    observed = [f"{row['check']}: {row['status']} — {row['summary']}" for row in matrix.table()]
    statements = {
        "observed": observed,
        "inference": [
            "Differences classified as rebuild noise are inferred to be caused by the "
            "rebuild because they are identical to this APK's measured no-op rebuild "
            "(content assurance) or match a documented path rule (path_rule assurance)."
        ],
        "risk_assessment": [
            "None. This report describes changes; it does not assess whether a change "
            "is malicious. A clean diff does not prove an APK is malware-free, and a "
            "verified signature proves structural/signing validity, not safety."
        ],
        "unknown": [f"{u['category']} {u['kind']} {u['identifier']}" for u in unknown]
        + [f"limitation: {x}" for x in matrix.limitations if "not" in x or "partial" in x][:50],
    }
    return VerificationReport(
        original=_ref(diff.apk_a if diff else None, original),
        modified=_ref(diff.apk_b if diff else None, modified),
        toolchain=toolchain,
        baseline=baseline,
        raw=raw,
        normalized=normalized,
        semantic=semantic,
        security=security,
        requested=requested or [],
        expected=expected,
        actual=actual,
        unexpected=unexpected,
        unknown=unknown,
        verification=matrix,
        limitations=matrix.limitations,
        statements=statements,
    )


def _line(o: dict[str, Any]) -> str:
    extra = f" [{o.get('rule')}]" if o.get("rule") else ""
    return f"- {o['category']} {o['kind']} `{o['identifier']}`{extra} — {o['reason']}"


def render_markdown(r: VerificationReport) -> str:
    """Render *r* as Markdown, one section per diff/verification layer."""
    out: list[str] = []
    w = out.append
    v = r.verification
    w(f"# APKForge verification: {v.overall}\n")
    w(f"- original: `{r.original.file_name}` sha256 `{r.original.sha256}`")
    w(f"- modified: `{r.modified.file_name}` sha256 `{r.modified.sha256}`")
    if r.original.package_name:
        w(f"- package: {r.original.package_name} {r.original.version_name}")
    if r.toolchain:
        t = r.toolchain
        w(f"- toolchain: apktool {t.apktool}, build-tools {t.build_tools}, java {t.java}")
    w(f"- overall: **{v.overall}** ({v.overall_reason})\n")

    w("## RAW DIFF\n")
    if r.raw.get("counts"):
        w(
            f"Entries: {r.raw['counts']}; metadata-only differences: "
            f"{r.raw.get('metadata_only_changes', 0)}\n"
        )
        for kind, counts in r.raw.get("counts_by_kind", {}).items():
            changed = {k: n for k, n in counts.items() if k != "unchanged"}
            if changed:
                w(f"- {kind}: {changed}")
        w("")
    else:
        w(f"Not available: {r.raw.get('reason', 'no diff')}\n")

    w("## NORMALIZED DIFF\n")
    if r.normalized:
        w(f"Mode: {r.normalized['mode']}; classification: {r.normalized['counts']}")
        w(f"Noise by rule: {r.normalized['noise_by_rule']}")
        w(f"Noise by assurance: {r.normalized['noise_by_assurance']}\n")
    else:
        w("Not classified.\n")

    w("## SEMANTIC DIFF\n")
    w("| comparator | status | changes | level | note |")
    w("|---|---|---:|---|---|")
    for name, c in r.semantic.get("comparisons", {}).items():
        w(f"| {name} | {c['status']} | {c['changes']} | {c['level']} | {c.get('reason') or ''} |")
    w("")

    w("## SECURITY-RELEVANT DIFF\n")
    if r.security is not None:
        w(f"_{r.security.disclaimer}_\n")
        for sec in r.security.sections.values():
            w(f"### {sec.title} ({sec.availability})\n")
            if not sec.items:
                w(
                    "- no change observed"
                    + ("" if sec.availability == "complete" else " (comparison incomplete)")
                )
            for i in sec.items:
                cls = f" [{i.classification}]" if i.classification else ""
                w(f"- {i.change} {i.subject}{cls} — evidence: {i.evidence}")
            w("")
    else:
        w("Not computed.\n")

    w("## REQUESTED\n")
    w("\n".join(f"- {x}" for x in r.requested) or "- (none: pair verification)")
    w("\n## EXPECTED CHANGES\n")
    w(
        "\n".join(f"- {e.category} {e.kind} `{e.identifier}` {e.detail or ''}" for e in r.expected)
        or "- none declared"
    )
    w("\n## ACTUAL CHANGES\n")
    w("\n".join(_line(o) for o in r.actual) or "- none (beyond rebuild noise)")
    w("\n## UNEXPECTED CHANGES\n")
    w("\n".join(_line(o) for o in r.unexpected) or "- none")
    w("\n## UNKNOWN / UNDETERMINED\n")
    w("\n".join(_line(o) for o in r.unknown) or "- none")

    w("\n## VERIFICATION\n")
    w("| check | status | summary |")
    w("|---|---|---|")
    for row in v.table():
        w(f"| {row['check']} | {row['status']} | {row['summary']} |")
    w(f"\nOverall: **{v.overall}** — {v.overall_reason}\n")

    w("## LIMITATIONS\n")
    w("\n".join(f"- {x}" for x in r.limitations) or "- none recorded")
    w("\n## EVIDENCE DISCIPLINE\n")
    for k, title in (
        ("observed", "Observed fact"),
        ("inference", "Inference"),
        ("risk_assessment", "Risk assessment"),
        ("unknown", "Unknown"),
    ):
        w(f"**{title}**\n")
        w("\n".join(f"- {x}" for x in r.statements.get(k, [])) or "- none")
        w("")
    w(f"_{v.statement}_")
    return "\n".join(out) + "\n"
