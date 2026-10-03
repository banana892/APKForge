"""Markdown report for an H.2 :class:`PlanningResult` (deterministic, planning only)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkforge.transformation.models import PlanningResult, TransformationDecision

__all__ = ["format_planning_report"]


def _decision(d: TransformationDecision, verbose: bool) -> list[str]:
    target = d.target.canonical if d.target else "(unparsed target)"
    lines = [f"### {d.transformation_id} `{target}` — **{d.eligibility.value}**", ""]
    lines += [f"- Decision id: `{d.decision_id}`", f"- {d.statement}"]
    if d.plan is not None:
        lines.append(f"- Plan id: `{d.plan.plan_id}` (not applied)")
    lines.append("")
    if d.reasons:
        lines += ["| Reason | State | Requirement | Evidence | Explanation |"]
        lines += ["|---|---|---|---|---|"]
        for r in d.reasons:
            msg = r.message.replace("|", "\\|")
            lines.append(
                f"| `{r.code.value}` | {r.state.value} | {r.requirement} | "
                f"{r.evidence_count} | {msg} |"
            )
        lines.append("")
    if verbose and d.requirements:
        lines += ["| Precondition | Status | Reasons |", "|---|---|---|"]
        for c in d.requirements:
            codes = ", ".join(x.value for x in c.reasons)
            lines.append(f"| {c.id} | {c.status.value} | {codes} |")
        lines.append("")
    if verbose and d.target_evidence_summary is not None:
        lines += ["| Evidence category | Count | Absence | State |", "|---|---|---|---|"]
        for cat in d.target_evidence_summary.categories:
            lines.append(
                f"| {cat.category} | {cat.count} | {cat.absence.value} "
                f"| {cat.analysis_state.value} |"
            )
        lines.append("")
    if d.plan is not None:
        lines += ["Planned changes (not applied):", ""]
        for ch in d.plan.planned_changes:
            lines.append(f"- `{ch.type}` {ch.target} ({ch.artifact})")
        for cond in d.plan.conditions:
            lines.append(f"- Condition `{cond.code.value}`: {cond.description}")
        lines.append("")
    return lines


def format_planning_report(result: PlanningResult, *, verbose: bool = False) -> str:
    a = result.apk
    lines = ["# APKForge transformation planning (Phase H.2, planning only)", ""]
    lines += [
        f"- APK: `{a.file_name}` ({a.package_name or '?'} {a.version_name or ''})",
        f"- SHA-256: `{a.sha256}`",
        f"- Overall H.1 analysis: {result.analysis_state.value}",
        f"- Input unchanged: {result.original_unchanged}",
        f"- Applied: {result.applied}",
        "",
        "| Component | State |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v.value} |" for k, v in result.component_states.items()]
    lines += ["", "| State | Decisions |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in result.counts().items()]
    lines.append("")
    if result.conflicts:
        lines += ["## Conflicts", ""]
        lines += [f"- `{c.kind}`: {c.message}" for c in result.conflicts]
        lines.append("")
    lines += ["## Decisions", ""]
    for d in result.decisions:
        lines += _decision(d, verbose)
    if result.errors:
        lines += ["## Errors", ""] + [f"- {e}" for e in result.errors] + [""]
    lines += ["## Limitations", ""] + [f"- {x}" for x in result.limitations]
    return "\n".join(lines) + "\n"
