"""Phase H.2: transformation eligibility & deterministic planning (planning only).

Consumes H.1 reference evidence and answers "is this proposed transformation supported
by the available static evidence?". Eligible requests get a deterministic plan that a
future H.3 engine may apply. Nothing in this package modifies, rebuilds, aligns, signs or
installs an APK, and no decision establishes that a target is malicious or that an app is
safe.

::

    Phase F/G evidence -> H.1 reference analysis -> H.2 eligibility -> plan [STOP]
"""

from __future__ import annotations

from apkforge.transformation.catalog import CATALOG, H_TRANS_001, H_TRANS_002, get_spec, list_specs
from apkforge.transformation.eligibility import EligibilityEvaluator
from apkforge.transformation.models import (
    PLANNING_SCHEMA_VERSION,
    REASON_STATES,
    AbsenceStatus,
    CategorySummary,
    ConflictRecord,
    DecisionReason,
    EligibilityState,
    PlanCondition,
    PlannedTransformChange,
    PlanningResult,
    ReasonDetail,
    RequirementCheck,
    RequirementStatus,
    TargetEvidenceSummary,
    TargetKind,
    TransformationDecision,
    TransformationPlan,
    TransformationRequest,
    TransformationSpec,
    TransformationTarget,
)
from apkforge.transformation.planner import (
    H2_STATEMENT,
    TransformationPlanner,
    TransformationPlanningService,
)
from apkforge.transformation.report import format_planning_report
from apkforge.transformation.selector import TargetEvidenceSelector, TargetEvidenceSet

__all__ = [
    "CATALOG",
    "H2_STATEMENT",
    "H_TRANS_001",
    "H_TRANS_002",
    "PLANNING_SCHEMA_VERSION",
    "REASON_STATES",
    "AbsenceStatus",
    "CategorySummary",
    "ConflictRecord",
    "DecisionReason",
    "EligibilityEvaluator",
    "EligibilityState",
    "PlanCondition",
    "PlannedTransformChange",
    "PlanningResult",
    "ReasonDetail",
    "RequirementCheck",
    "RequirementStatus",
    "TargetEvidenceSelector",
    "TargetEvidenceSet",
    "TargetEvidenceSummary",
    "TargetKind",
    "TransformationDecision",
    "TransformationPlan",
    "TransformationPlanner",
    "TransformationPlanningService",
    "TransformationRequest",
    "TransformationSpec",
    "TransformationTarget",
    "format_planning_report",
    "get_spec",
    "list_specs",
]
