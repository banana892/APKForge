"""Remediation Diff Report Formatter for Phase G.

Generates structured markdown and JSON reports for remediation plans and execution results,
containing:
1. Original APK Metadata
2. Target Finding & Evidence
3. Planned / Applied Remediation
4. Verification & Integrity Checks
5. Privacy Before/After Intelligence
6. Limitations & Unresolved States
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkforge.remediation.models import (
        RemediationExecutionResult,
        RemediationPlan,
    )

__all__ = ["format_remediation_diff_report", "format_remediation_plan_report"]

SAFETY_DISCLAIMER = (
    "> [!IMPORTANT]\n"
    "> **Safety Notice**: APKForge remediation is evidence-driven transformation and "
    "verification. Successful rebuilding or removal of an indicator does not establish that "
    "an APK is malware-free, spyware-free, or safe."
)


def format_remediation_plan_report(plan: RemediationPlan) -> str:
    """Format a dry-run / planned remediation as readable Markdown."""
    lines: list[str] = [
        f"# Remediation Plan: {plan.plan_id}",
        "",
        SAFETY_DISCLAIMER,
        "",
        "## 1. Target Finding",
        f"- **Finding ID**: `{plan.finding_id}`",
        f"- **Title**: {plan.finding_title}",
        f"- **Category**: `{plan.finding_category}`",
        f"- **Evidence State**: `{plan.finding_state}`",
        f"- **Evidence Locations**: {', '.join(plan.finding_evidence_locations) or 'None'}",
        f"- **Evidence Values**: {', '.join(plan.finding_evidence_values) or 'None'}",
        "",
        "## 2. Remediation Strategy",
        f"- **Remediation ID**: `{plan.remediation_id}`",
        f"- **Name**: {plan.remediation_name}",
        f"- **Plan Readiness**: `{plan.state}` (ready: {plan.ready})",
        "",
        "### Preconditions Checked",
    ]
    for pre in plan.preconditions:
        mark = "✓" if pre.satisfied else "✗"
        lines.append(f"- [{mark}] **{pre.name}**: expected `{pre.expected}`, found `{pre.actual}`")

    lines.extend(
        [
            "",
            "### Planned Modifications",
        ]
    )
    for ch in plan.planned_changes:
        lines.append(f"- {ch}")

    lines.extend(
        [
            "",
            "### Expected Diff",
        ]
    )
    for ed in plan.expected_diff:
        lines.append(f"- `{ed}`")

    lines.extend(
        [
            "",
            "## 3. Verification Plan",
        ]
    )
    for vr in plan.verification_plan:
        lines.append(f"- {vr}")

    lines.extend(
        [
            "",
            "## 4. Warnings & Compatibility Notes",
        ]
    )
    for warn in plan.warnings:
        lines.append(f"- {warn}")

    lines.extend(
        [
            "",
            "## 5. Limitations",
        ]
    )
    for lim in plan.limitations:
        lines.append(f"- {lim}")

    return "\n".join(lines) + "\n"


def format_remediation_diff_report(result: RemediationExecutionResult) -> str:
    """Format a complete execution result and before/after report as Markdown."""
    plan = result.plan
    comp = result.comparison

    lines: list[str] = [
        f"# Remediation Diff Report: {plan.plan_id}",
        "",
        SAFETY_DISCLAIMER,
        "",
        f"- **Overall Outcome**: `{result.state}`",
        f"- **Approval Granted**: `{result.approved}`",
        f"- **Target Finding Resolution**: `{comp.target_finding.resolution if comp else 'N/A'}`",
        "",
        "## 1. APK Metadata & Integrity",
        f"- **Source APK**: `{plan.source_apk_path}`",
        f"- **Original SHA-256**: `{result.original_apk_sha256_before}`",
        f"- **Original Preserved**: `{result.original_apk_preserved}`",
        f"- **Output APK**: `{result.output_apk_path or 'None'}`",
        f"- **Output SHA-256**: `{result.output_apk_sha256 or 'None'}`",
        "",
        "## 2. Target Finding",
        f"- **Finding ID**: `{plan.finding_id}`",
        f"- **Title**: {plan.finding_title}",
        f"- **Category**: `{plan.finding_category}`",
        f"- **Remediation ID**: `{plan.remediation_id}` ({plan.remediation_name})",
    ]

    if comp:
        lines.extend(
            [
                f"- **Resolution**: `{comp.target_finding.resolution}`",
                f"- **Resolution Details**: {comp.target_finding.explanation}",
            ]
        )

    lines.extend(
        [
            "",
            "## 3. Applied Modifications",
        ]
    )
    for ch in plan.planned_changes:
        lines.append(f"- {ch}")

    lines.extend(
        [
            "",
            "## 4. Verification & Pipeline Results",
            f"- **Pipeline Status**: `{result.pipeline_status or 'N/A'}`",
            f"- **Build Passed**: `{result.build_passed}`",
            f"- **APK Verified**: `{result.apk_verified}`",
            f"- **Modification Verified**: `{result.verification_passed}`",
        ]
    )

    if result.errors:
        lines.extend(["", "### Execution Errors"])
        for err in result.errors:
            lines.append(f"- ⚠️ {err}")

    if comp:
        f_rem = ", ".join(comp.findings_removed) or "none"
        f_ret = f"{len(comp.findings_retained)} findings"
        f_intro = ", ".join(comp.findings_introduced) or "none"
        p_rem = ", ".join(comp.permission_changes.get("removed", [])) or "none"
        c_dis = ", ".join(comp.component_changes.get("disabled", [])) or "none"
        lines.extend(
            [
                "",
                "## 5. Privacy Intelligence Before / After",
                f"- **Findings Removed ({len(comp.findings_removed)})**: {f_rem}",
                f"- **Findings Retained ({len(comp.findings_retained)})**: {f_ret}",
                f"- **Findings Introduced ({len(comp.findings_introduced)})**: {f_intro}",
                f"- **Permissions Removed**: {p_rem}",
                f"- **Components Disabled**: {c_dis}",
            ]
        )

    lines.extend(
        [
            "",
            "## 6. Limitations & Unresolved States",
        ]
    )
    for lim in result.limitations:
        lines.append(f"- {lim}")

    return "\n".join(lines) + "\n"
