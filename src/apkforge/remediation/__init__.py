"""Phase G: Controlled Privacy/Security Remediation module.

Builds APKForge's first dedicated controlled remediation layer, bridging
evidence-backed Phase F privacy findings, Phase D modifiers, BuildService,
Phase E verification, and post-remediation privacy diffing.
"""

from __future__ import annotations

from apkforge.remediation.catalog import (
    BOOT_RECEIVER_REMEDIATION,
    DISABLE_COMPONENT_REMEDIATION,
    REMOVE_PERMISSION_REMEDIATION,
    REMOVE_TRACKER_SDK_REMEDIATION,
    RemediationCatalog,
    default_remediation_catalog,
)
from apkforge.remediation.compare import compare_privacy_before_after
from apkforge.remediation.execution import RemediationExecutor
from apkforge.remediation.mapping import (
    RemediationCandidate,
    find_remediations_for_finding,
    map_finding_to_remediations,
)
from apkforge.remediation.models import (
    BeforeAfterComparison,
    FindingResolution,
    PreconditionCheck,
    RemediationDefinition,
    RemediationExecutionResult,
    RemediationPlan,
    RemediationRisk,
    RemediationState,
    SupportedStatus,
    TargetFindingComparison,
)
from apkforge.remediation.modifiers import (
    DisableComponentModifier,
    RemovePermissionModifier,
    remediation_modifier_catalog,
)
from apkforge.remediation.planner import RemediationPlanner
from apkforge.remediation.report import (
    format_remediation_diff_report,
    format_remediation_plan_report,
)
from apkforge.remediation.service import RemediationService

__all__ = [
    "BOOT_RECEIVER_REMEDIATION",
    "DISABLE_COMPONENT_REMEDIATION",
    "REMOVE_PERMISSION_REMEDIATION",
    "REMOVE_TRACKER_SDK_REMEDIATION",
    "BeforeAfterComparison",
    "DisableComponentModifier",
    "FindingResolution",
    "PreconditionCheck",
    "RemediationCandidate",
    "RemediationCatalog",
    "RemediationDefinition",
    "RemediationExecutionResult",
    "RemediationExecutor",
    "RemediationPlan",
    "RemediationPlanner",
    "RemediationRisk",
    "RemediationService",
    "RemediationState",
    "RemovePermissionModifier",
    "SupportedStatus",
    "TargetFindingComparison",
    "compare_privacy_before_after",
    "default_remediation_catalog",
    "find_remediations_for_finding",
    "format_remediation_diff_report",
    "format_remediation_plan_report",
    "map_finding_to_remediations",
    "remediation_modifier_catalog",
]
