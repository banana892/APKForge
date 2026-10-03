"""Markdown reports for H.2 planning, H.3 application and H.4 verification results."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkforge.transformation.application import TransformationApplicationResult
    from apkforge.transformation.models import PlanningResult, TransformationDecision
    from apkforge.transformation.verification import (
        ClassifiedDifference,
        TransformationVerificationResult,
    )

__all__ = [
    "format_application_report",
    "format_planning_report",
    "format_verification_report",
]


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


def format_application_report(result: TransformationApplicationResult) -> str:
    """Markdown report for an H.3 application (or plan validation)."""
    mode = "plan validation, nothing applied" if result.dry_run else "application"
    history = " -> ".join(s.value for s in result.status_history)
    lines = [f"# APKForge controlled transformation (Phase H.3, {mode})", ""]
    lines += [
        f"- Status: **{result.status.value}** ({history})",
        f"- Transformation: {result.transformation_id or '?'}",
        f"- Plan id: `{result.plan_id or '?'}`",
        f"- Target: `{result.target.get('class', '?')}` ({result.target.get('file', '?')})",
        f"- Source SHA-256: `{result.source_apk_sha256}` (unchanged: {result.original_unchanged})",
    ]
    if result.output_apk:
        lines.append(f"- Output: `{result.output_apk}` (SHA-256 `{result.output_apk_sha256}`)")
    if result.failure is not None:
        f = result.failure
        lines += ["", f"**{f.code.value}** at stage `{f.stage.value}`: {f.message}"]
    lines.append("")
    if result.planned_changes:
        verb = "Applied" if result.status.value == "VERIFIED" else "Planned"
        lines += [f"{verb} changes:", ""]
        lines += [
            f"- `{c['type']}` {c['target']} ({c.get('artifact')})" for c in result.planned_changes
        ]
        lines.append("")
    if result.mutation is not None:
        m = result.mutation
        lines += [
            "| Mutation | Value |",
            "|---|---|",
            f"| operation | {m.operation} |",
            f"| target file | {m.target_file} |",
            f"| pre-transform SHA-256 | `{m.pre_transform_sha256}` |",
            f"| post-transform SHA-256 | {m.post_transform_sha256 or '(file removed)'} |",
            f"| classes | {m.classes_before} -> {m.classes_after} |",
            f"| removed | {', '.join(m.removed_classes) or '-'} |",
            "",
        ]
    if result.expected_changes:
        lines += ["Expected semantic changes (declared before mutation):", ""]
        lines += [f"- {e.category} {e.kind} `{e.identifier}`" for e in result.expected_changes]
        lines.append("")
    if result.diff.get("unexpected"):
        lines += ["Unexpected changes:", ""]
        lines += [f"- {u}" for u in result.diff["unexpected"]]
        lines.append("")
    if result.verification:
        lines += ["| Check | Expected | Actual | Status |", "|---|---|---|---|"]
        for row in result.verification:
            actual = row.actual.replace("|", "\\|")
            lines.append(f"| {row.check} | {row.expected} | {actual} | {row.status.value} |")
        lines.append("")
    lines += ["## Limitations", ""] + [f"- {x}" for x in result.limitations]
    return "\n".join(lines) + "\n"


def _esc(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _diff_rows(items: list[ClassifiedDifference]) -> list[str]:
    lines = ["| Domain | Leg | Difference | In control | In signal | Rule | Reason |"]
    lines.append("|---|---|---|---|---|---|---|")
    for d in items:
        o = d.observation
        lines.append(
            f"| {d.domain} | {d.leg} | {o.category} {o.kind} `{_esc(o.identifier)}` | "
            f"{d.in_control} | {d.in_signal} | {d.rule or '-'} | {_esc(d.reason)} |"
        )
    return [*lines, ""]


def format_verification_report(result: TransformationVerificationResult) -> str:
    """Markdown report for an H.4 transformation verification."""
    r = result
    lines = ["# APKForge transformation verification (Phase H.4)", ""]
    lines += [
        f"- Status: **{r.status.value}** — {r.status_reason}",
        f"- Completeness (weakest mandatory domain): **{r.completeness.value}**",
        f"- Mode: {r.mode}; transformation: {r.transformation_id or '-'}; plan id: "
        f"`{r.plan_id or '-'}`; target: `{r.target.get('class', '-')}`",
        f"- Original SHA-256: `{r.source_apk_sha256}` (unchanged: {r.original_unchanged})",
    ]
    for rb in (r.control_rebuild, r.transformed_rebuild):
        extra = f", no-op {rb.noop_result}, baseline {rb.baseline_status}" if rb.noop_result else ""
        lines.append(
            f"- {rb.role.capitalize()} rebuild: available {rb.available}, SHA-256 "
            f"`{rb.sha256 or '-'}`, signature {rb.signature or '-'}{extra}"
            + (f" ({'; '.join(rb.reasons)})" if rb.reasons else "")
        )
    lines.append("")
    if r.legs:
        lines += ["## Legs", ""]
        lines += [
            "| Leg | Diff | Observations | Phase E classes | Raw entries | ZIP metadata-only "
            "| Order changed |",
            "|---|---|---|---|---|---|---|",
        ]
        for leg in r.legs.values():
            pe = ", ".join(f"{k} {v}" for k, v in leg.phase_e_counts.items() if v) or "-"
            raw = ", ".join(f"{k} {v}" for k, v in leg.raw_counts.items() if v) or "-"
            lines.append(
                f"| {leg.leg} | {leg.diff_status} | {leg.observations} | {_esc(pe)} | {raw} | "
                f"{leg.metadata_only_changes} | {leg.entry_order_changed} |"
            )
        lines.append("")
    if r.noise_floor:
        nf = r.noise_floor
        lines += ["## Noise floor (measured by the control rebuild)", ""]
        lines += [
            f"- No-op result: {nf.get('noop_result')}; baseline status: "
            f"{nf.get('baseline_status')}",
            f"- Accepted noise rules: {nf.get('accepted_rule_counts') or '{}'}",
            f"- Packaging (ZIP metadata-only) entries: {nf.get('packaging_metadata_only_entries')}",
            "",
        ]
    if r.domains:
        lines += ["## Domains", ""]
        lines += [
            "| Domain | Completeness | Status | Expected | Noise | Unexpected | Unknown "
            "| Reasons |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for d in r.domains.values():
            c = d.counts
            lines.append(
                f"| {d.domain} | {d.completeness} | {d.status} | "
                f"{c.get('EXPECTED_TRANSFORMATION', 0)} | {c.get('NOISE', 0)} | "
                f"{c.get('UNEXPECTED_CHANGE', 0)} | {c.get('UNKNOWN', 0)} | "
                f"{_esc('; '.join(d.reasons[:4]) or '-')} |"
            )
        lines.append("")
    if r.invariants:
        lines += ["## Invariants", ""]
        lines += ["| Invariant | Expected | Actual | Status |", "|---|---|---|---|"]
        for i in r.invariants:
            lines.append(f"| {i.name} | {_esc(i.expected)} | {_esc(i.actual)} | {i.status} |")
        lines.append("")
    for title, items in (
        ("Expected transformation", r.expected_changes),
        ("Noise", r.noise_changes),
        ("Unexpected changes", r.unexpected_changes),
        ("Unknown / unexplained", r.unknown_changes),
    ):
        if items:
            lines += [f"## {title} ({len(items)})", "", *_diff_rows(items)]
    if r.declared_missing:
        lines += ["## Declared but not observed", ""]
        lines += [f"- {m}" for m in r.declared_missing] + [""]
    if r.errors:
        lines += ["## Errors", ""] + [f"- {e}" for e in r.errors] + [""]
    lines += ["## Limitations", ""] + [f"- {x}" for x in r.limitations] + [""]
    lines += [f"> {r.statement}"]
    return "\n".join(lines) + "\n"
