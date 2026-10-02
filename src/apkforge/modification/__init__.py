"""APKForge Phase 6 & 7 Modification subsystem.

Phase 6: Modification Planning (non-destructive static proposals).
Phase 7: Modification Framework (approved change execution).
Phase D: Modification pipeline (modifier contract, catalog, plan -> apply -> BuildService
-> expected-vs-actual verification); see docs/modification-framework.md.
"""

from __future__ import annotations

from apkforge.modification.catalog import (
    DuplicateModifierError,
    ModifierCatalog,
    UnknownModifierError,
    default_catalog,
)
from apkforge.modification.contract import (
    APKModifier,
    ApplyOutcome,
    ModifierInfo,
    ModifierPlan,
    ProjectContext,
    VerificationOutcome,
)
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
from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
    PipelineStatus,
)
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
    "APKModifier",
    "ApplyOutcome",
    # Phase 6 — Planning
    "ChangeConflict",
    "ChangeDependency",
    "ChangeStatus",
    "ChangeType",
    "ConflictType",
    "DependencyType",
    "DiffRegressionMitigationRule",
    "DuplicateModifierError",
    "EmbeddedPayloadRemovalRule",
    "ImpactAssessment",
    "InsecureManifestHardeningRule",
    "ModificationContext",
    "ModificationExecutionContext",
    "ModificationFramework",
    "ModificationPipeline",
    "ModificationPlan",
    "ModificationPlanner",
    "ModificationResult",
    "ModificationRisk",
    "ModificationRule",
    "ModificationRuleRegistry",
    "ModificationStepResult",
    # Phase 7 — Framework
    "Modifier",
    "ModifierCatalog",
    "ModifierInfo",
    "ModifierPlan",
    "ModifierRegistry",
    "ModifierRequest",
    "PipelineResult",
    "PipelineStatus",
    "PlanStatus",
    "PlannedChange",
    "ProjectContext",
    "Reversibility",
    "StepStatus",
    "TrackerRemovalRule",
    "UnknownModifierError",
    "UnprotectedExportedComponentRule",
    "UnusedPermissionRule",
    "VerificationOutcome",
    "default_catalog",
    "load_plan",
    "plan_from_json",
    "plan_from_yaml",
    "plan_to_json",
    "plan_to_yaml",
    "save_plan",
]
