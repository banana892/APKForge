"""Phase H.2 transformation eligibility & planning, and H.3 controlled application.

H.2 consumes H.1 reference evidence and answers "is this proposed transformation supported
by the available static evidence?"; eligible requests get a deterministic plan. Planning
never modifies, rebuilds, aligns, signs or installs an APK.

H.3 (:class:`TransformationExecutor`) applies exactly one validated, ``ELIGIBLE`` H.2 plan
of ``H-TRANS-001`` (remove isolated class) to a copy of the APK and verifies the result
(BuildService, H.1 re-analysis, Phase E diff). No decision or result establishes that a
target is malicious or that an app is safe.

::

    H.1 reference analysis -> H.2 eligibility -> plan -> H.3 apply + verify
"""

from __future__ import annotations

from apkforge.transformation.application import (
    APPLICATION_SCHEMA_VERSION,
    SUPPORTED_TRANSFORMATIONS,
    ApplicationFailure,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CheckOutcome,
    MatrixRow,
    MutationRecord,
    PostAnalysis,
    TransformationApplicationResult,
)
from apkforge.transformation.catalog import CATALOG, H_TRANS_001, H_TRANS_002, get_spec, list_specs
from apkforge.transformation.eligibility import EligibilityEvaluator
from apkforge.transformation.executor import H3_LIMITATIONS, TransformationExecutor, load_plan
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
from apkforge.transformation.modifier import H3_MODIFIER_ID, RemoveIsolatedClassModifier
from apkforge.transformation.planner import (
    H2_STATEMENT,
    TransformationPlanner,
    TransformationPlanningService,
)
from apkforge.transformation.report import format_application_report, format_planning_report
from apkforge.transformation.selector import TargetEvidenceSelector, TargetEvidenceSet

__all__ = [
    "APPLICATION_SCHEMA_VERSION",
    "CATALOG",
    "H2_STATEMENT",
    "H3_LIMITATIONS",
    "H3_MODIFIER_ID",
    "H_TRANS_001",
    "H_TRANS_002",
    "PLANNING_SCHEMA_VERSION",
    "REASON_STATES",
    "SUPPORTED_TRANSFORMATIONS",
    "AbsenceStatus",
    "ApplicationFailure",
    "ApplicationReason",
    "ApplicationStage",
    "ApplicationStatus",
    "CategorySummary",
    "CheckOutcome",
    "ConflictRecord",
    "DecisionReason",
    "EligibilityEvaluator",
    "EligibilityState",
    "MatrixRow",
    "MutationRecord",
    "PlanCondition",
    "PlannedTransformChange",
    "PlanningResult",
    "PostAnalysis",
    "ReasonDetail",
    "RemoveIsolatedClassModifier",
    "RequirementCheck",
    "RequirementStatus",
    "TargetEvidenceSelector",
    "TargetEvidenceSet",
    "TargetEvidenceSummary",
    "TargetKind",
    "TransformationApplicationResult",
    "TransformationDecision",
    "TransformationExecutor",
    "TransformationPlan",
    "TransformationPlanner",
    "TransformationPlanningService",
    "TransformationRequest",
    "TransformationSpec",
    "TransformationTarget",
    "format_application_report",
    "format_planning_report",
    "get_spec",
    "list_specs",
    "load_plan",
]
