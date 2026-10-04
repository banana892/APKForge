"""Phase H.2 transformation eligibility & planning, and H.3 controlled application.

H.2 consumes H.1 reference evidence and answers "is this proposed transformation supported
by the available static evidence?"; eligible requests get a deterministic plan. Planning
never modifies, rebuilds, aligns, signs or installs an APK.

H.3 (:class:`TransformationExecutor`) applies exactly one validated, ``ELIGIBLE`` H.2 plan
of ``H-TRANS-001`` (remove isolated class; H.5 adds ``H-TRANS-002`` remove isolated method,
H.6 ``H-TRANS-003`` replace one call site) to a copy of the APK and verifies the result
(BuildService, H.1 re-analysis, Phase E diff). No decision or result establishes that a
target is malicious or that an app is safe.

H.4 (:class:`TransformationVerifier`) verifies a transformed rebuild against its original
*and* an unmodified control rebuild of it (the measured noise floor), per verification
domain, with explicit completeness; :class:`ControlExperiment` produces the three APKs.

::

    H.1 reference analysis -> H.2 eligibility -> plan -> H.3 apply + verify
      -> H.4 control experiment (original, control rebuild, transformed rebuild)
"""

from __future__ import annotations

from apkforge.transformation.application import (
    APPLICATION_SCHEMA_VERSION,
    SUPPORTED_TRANSFORMATIONS,
    ApplicationFailure,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CallSitePostAnalysis,
    CheckOutcome,
    MatrixRow,
    MethodPostAnalysis,
    MutationRecord,
    PostAnalysis,
    TransformationApplicationResult,
)
from apkforge.transformation.catalog import (
    CATALOG,
    H_TRANS_001,
    H_TRANS_002,
    H_TRANS_003,
    get_spec,
    list_specs,
)
from apkforge.transformation.eligibility import EligibilityEvaluator
from apkforge.transformation.executor import H3_LIMITATIONS, TransformationExecutor, load_plan
from apkforge.transformation.experiment import (
    ControlExperiment,
    ExperimentResult,
    NoiseFloorExperiment,
)
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
from apkforge.transformation.modifier import (
    H3_MODIFIER_ID,
    H5_MODIFIER_ID,
    H6_MODIFIER_ID,
    RemoveIsolatedClassModifier,
    RemoveIsolatedMethodModifier,
    ReplaceCallSiteModifier,
)
from apkforge.transformation.planner import (
    H2_STATEMENT,
    TransformationPlanner,
    TransformationPlanningService,
)
from apkforge.transformation.report import (
    format_application_report,
    format_planning_report,
    format_verification_report,
)
from apkforge.transformation.selector import TargetEvidenceSelector, TargetEvidenceSet
from apkforge.transformation.verification import (
    H4_LIMITATIONS,
    H4_STATEMENT,
    MANDATORY_DOMAINS,
    VERIFICATION_RESULT_SCHEMA_VERSION,
    ClassifiedDifference,
    Completeness,
    ControlPresence,
    DifferenceClass,
    DomainReport,
    InvariantCheck,
    LegSummary,
    RebuildRecord,
    TransformationVerificationResult,
    TransformationVerificationStatus,
    VerificationDomain,
)
from apkforge.transformation.verifier import TransformationVerifier

__all__ = [
    "APPLICATION_SCHEMA_VERSION",
    "CATALOG",
    "H2_STATEMENT",
    "H3_LIMITATIONS",
    "H3_MODIFIER_ID",
    "H4_LIMITATIONS",
    "H4_STATEMENT",
    "H5_MODIFIER_ID",
    "H6_MODIFIER_ID",
    "H_TRANS_001",
    "H_TRANS_002",
    "H_TRANS_003",
    "MANDATORY_DOMAINS",
    "PLANNING_SCHEMA_VERSION",
    "REASON_STATES",
    "SUPPORTED_TRANSFORMATIONS",
    "VERIFICATION_RESULT_SCHEMA_VERSION",
    "AbsenceStatus",
    "ApplicationFailure",
    "ApplicationReason",
    "ApplicationStage",
    "ApplicationStatus",
    "CallSitePostAnalysis",
    "CategorySummary",
    "CheckOutcome",
    "ClassifiedDifference",
    "Completeness",
    "ConflictRecord",
    "ControlExperiment",
    "ControlPresence",
    "DecisionReason",
    "DifferenceClass",
    "DomainReport",
    "EligibilityEvaluator",
    "EligibilityState",
    "ExperimentResult",
    "InvariantCheck",
    "LegSummary",
    "MatrixRow",
    "MethodPostAnalysis",
    "MutationRecord",
    "NoiseFloorExperiment",
    "PlanCondition",
    "PlannedTransformChange",
    "PlanningResult",
    "PostAnalysis",
    "ReasonDetail",
    "RebuildRecord",
    "RemoveIsolatedClassModifier",
    "RemoveIsolatedMethodModifier",
    "ReplaceCallSiteModifier",
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
    "TransformationVerificationResult",
    "TransformationVerificationStatus",
    "TransformationVerifier",
    "VerificationDomain",
    "format_application_report",
    "format_planning_report",
    "format_verification_report",
    "get_spec",
    "list_specs",
    "load_plan",
]
