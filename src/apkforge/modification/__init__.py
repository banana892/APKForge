"""APKForge Phase 6 & 7 Modification subsystem.

Phase 6: Modification Planning (non-destructive static proposals).
Phase 7: Modification Framework (approved change execution).
"""

from __future__ import annotations

from apkforge.modification.framework import ModificationFramework
from apkforge.modification.models import (
    ChangeConflict,
    ChangeDependency,
    ChangeStatus,
    ChangeType,
    ConflictType,
    DependencyType,
    ImpactAssessment,
    ModificationPlan,
    ModificationRisk,
    PlannedChange,
    PlanStatus,
    Reversibility,
)
from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationResult,
    ModificationStepResult,
    Modifier,
    StepStatus,
)
from apkforge.modification.modifiers.registry import ModifierRegistry
from apkforge.modification.planner import ModificationPlanner
from apkforge.modification.registry import ModificationRuleRegistry
from apkforge.modification.rules import (
    DiffRegressionMitigationRule,
    EmbeddedPayloadRemovalRule,
    InsecureManifestHardeningRule,
    ModificationContext,
    ModificationRule,
    TrackerRemovalRule,
    UnprotectedExportedComponentRule,
    UnusedPermissionRule,
)
from apkforge.modification.serialization import (
    load_plan,
    plan_from_json,
    plan_from_yaml,
    plan_to_json,
    plan_to_yaml,
    save_plan,
)

__all__ = [
    # Phase 6 — Planning
    "ChangeConflict",
    "ChangeDependency",
    "ChangeStatus",
    "ChangeType",
    "ConflictType",
    "DependencyType",
    "DiffRegressionMitigationRule",
    "EmbeddedPayloadRemovalRule",
    "ImpactAssessment",
    "InsecureManifestHardeningRule",
    "ModificationContext",
    "ModificationExecutionContext",
    "ModificationFramework",
    "ModificationPlan",
    "ModificationPlanner",
    "ModificationResult",
    "ModificationRisk",
    "ModificationRule",
    "ModificationRuleRegistry",
    "ModificationStepResult",
    # Phase 7 — Framework
    "Modifier",
    "ModifierRegistry",
    "PlanStatus",
    "PlannedChange",
    "Reversibility",
    "StepStatus",
    "TrackerRemovalRule",
    "UnprotectedExportedComponentRule",
    "UnusedPermissionRule",
    "load_plan",
    "plan_from_json",
    "plan_from_yaml",
    "plan_to_json",
    "plan_to_yaml",
    "save_plan",
]
