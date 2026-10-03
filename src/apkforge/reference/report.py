"""Markdown report for an H.1 reference analysis (deterministic, no timestamps)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkforge.reference.models import (
        AbsenceAssessment,
        ComponentAnalysis,
        Evidence,
        ReferenceAnalysisResult,
    )

__all__ = ["format_reference_report"]

_MAX_ROWS = 50


def _loc(ev: Evidence) -> str:
    loc = ev.source_file + (f":{ev.source_line}" if ev.source_line else "")
    return loc + (f" ({ev.xml_location})" if ev.xml_location else "")


def _components(lines: list[str], comps: list[ComponentAnalysis], depth: int = 0) -> None:
    for c in comps:
        pad = "&nbsp;&nbsp;" * depth
        notes = "; ".join(c.notes)
        lines.append(
            f"| {pad}{c.component} | {c.state.value} | {c.inputs_analyzed}/{c.inputs_total} "
            f"| {c.issue_count} | {notes} |"
        )
        _components(lines, c.subcomponents, depth + 1)


def _evidence_table(lines: list[str], title: str, evs: list[Evidence]) -> None:
    lines += ["", f"## {title} ({len(evs)})", ""]
    if not evs:
        lines.append("_None observed (see component states before reading this as absence)._")
        return
    lines += ["| Kind | Target | Source | Location | Basis |", "|---|---|---|---|---|"]
    for ev in evs[:_MAX_ROWS]:
        src = ev.source_class or ""
        if ev.source_method:
            src += f".{ev.source_method}"
        extra = ev.string_use or ev.resolution or ev.native_resolution or ev.match_basis or ""
        basis = f"{extra} {ev.confidence_basis}".strip().replace("|", "\\|")
        target = ev.target.replace("|", "\\|")
        lines.append(f"| {ev.kind.value} | `{target}` | {src} | {_loc(ev)} | {basis} |")
    if len(evs) > _MAX_ROWS:
        lines.append(f"| … | {len(evs) - _MAX_ROWS} more (see JSON) | | | |")


def format_reference_report(
    result: ReferenceAnalysisResult,
    assessments: list[AbsenceAssessment] | None = None,
    *,
    verbose: bool = False,
) -> str:
    a = result.apk
    lines = [
        "# APKForge H.1 Reference Analysis",
        "",
        "> Read-only evidence. H.1 does not transform APKs and does not state that an APK "
        "or class is safe, unused or malicious.",
        "",
        f"- APK: `{a.file_name}` (sha256 `{a.sha256}`)",
        f"- Package: `{a.package_name}` version `{a.version_name}` ({a.version_code})",
        f"- Overall analysis state: **{result.analysis_state.value}**",
        f"- Original APK unchanged: {result.original_unchanged}",
        f"- Classes defined: {len(result.defined_classes)}",
        "",
        "## Component states",
        "",
        "| Component | State | Analysed/Total | Issues | Notes |",
        "|---|---|---|---|---|",
    ]
    _components(lines, result.components)
    lines += ["", "## Evidence counts", "", "| Kind | Count |", "|---|---|"]
    lines += [f"| {k} | {n} |" for k, n in result.summary().items()]

    for title, aa in ((f"Absence assessment: `{x.target}`", x) for x in assessments or []):
        lines += [
            "",
            f"## {title}",
            "",
            f"- Conclusion: **{aa.conclusion.value}** (absence established: "
            f"{aa.absence_established})",
            f"- Analysis state: {aa.analysis_state.value}",
            f"- {aa.statement}",
        ]
        lines += [f"- Reason: {r}" for r in aa.reasons]
        _evidence_table(lines, "Structural references", aa.definitive_references)
        _evidence_table(lines, "Indirect evidence", aa.indirect_evidence)

    _evidence_table(lines, "Reflection indicators", result.reflection)
    _evidence_table(lines, "Native evidence", result.native)
    _evidence_table(lines, "Manifest references", result.manifest)
    _evidence_table(lines, "Resource / asset references", result.resources)
    if verbose:
        _evidence_table(lines, "Code references", result.references)

    issues = [(c.component, i) for c in result.components for i in c.issues] + [
        (s.component, i) for c in result.components for s in c.subcomponents for i in s.issues
    ]
    if issues:
        lines += ["", "## Analysis issues", "", "| Component | Code | Location | Message |"]
        lines.append("|---|---|---|---|")
        for comp, i in issues[: _MAX_ROWS * 2]:
            msg = i.message.replace("|", "\\|")
            lines.append(f"| {comp} | {i.code} | {i.location} | {msg} |")
    if result.errors:
        lines += ["", "## Errors", ""] + [f"- {e}" for e in result.errors]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in result.limitations]
    return "\n".join(lines) + "\n"
