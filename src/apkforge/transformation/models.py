"""Phase H.2 transformation-eligibility and planning models.

H.2 decides whether a proposed transformation is supported by the available static
evidence (H.1) and, when it is, produces a deterministic plan describing what a future
H.3 engine would do. Nothing here modifies, rebuilds, signs or installs an APK, and no
decision states that an application is safe, benign, malware-free or spyware-free.

Central rules
-------------
- Every decision other than ``ELIGIBLE`` carries machine-readable :class:`DecisionReason`
  codes; human-readable messages only accompany them.
- ``UNDETERMINED`` is never converted into ``ELIGIBLE``.
- A decision is never stronger than the H.1 analysis it rests on: an empty evidence list
  only satisfies a requirement when the relevant components are ``COMPLETE``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# pydantic field types: needed at runtime
from apkforge.modification.models import ModificationRisk, Reversibility  # noqa: TC001
from apkforge.reference.models import AnalysisState, ApkIdentity  # noqa: TC001

__all__ = [
    "PLANNING_SCHEMA_VERSION",
    "AbsenceStatus",
    "CategorySummary",
    "ConflictRecord",
    "DecisionReason",
    "EligibilityState",
    "PlanCondition",
    "PlannedTransformChange",
    "PlanningResult",
    "ReasonDetail",
    "RequirementCheck",
    "RequirementStatus",
    "TargetEvidenceSummary",
    "TargetKind",
    "TransformationDecision",
    "TransformationPlan",
    "TransformationRequest",
    "TransformationSpec",
    "TransformationTarget",
]

#: version of the H.2 decision/plan format (part of every plan id)
PLANNING_SCHEMA_VERSION = 1


class EligibilityState(StrEnum):
    """Outcome of an eligibility evaluation.

    ELIGIBLE                every required evidence item and precondition is satisfied
    CONDITIONALLY_ELIGIBLE  satisfied, but an explicit documented condition must be met
                            before application (never a disguised approval)
    REFUSED                 conflicts with evidence or violates a defined safety rule
    UNSUPPORTED             APKForge does not support this transformation/target shape
    UNDETERMINED            the available analysis cannot establish eligibility
    """

    ELIGIBLE = "ELIGIBLE"
    CONDITIONALLY_ELIGIBLE = "CONDITIONALLY_ELIGIBLE"
    REFUSED = "REFUSED"
    UNSUPPORTED = "UNSUPPORTED"
    UNDETERMINED = "UNDETERMINED"

    @property
    def plannable(self) -> bool:
        return self in (EligibilityState.ELIGIBLE, EligibilityState.CONDITIONALLY_ELIGIBLE)


#: precedence when several requirements fail: the strongest finding decides
STATE_PRECEDENCE = (
    EligibilityState.REFUSED,
    EligibilityState.UNSUPPORTED,
    EligibilityState.UNDETERMINED,
    EligibilityState.CONDITIONALLY_ELIGIBLE,
    EligibilityState.ELIGIBLE,
)


class DecisionReason(StrEnum):
    """Machine-readable reason codes. Each code maps to exactly one eligibility state
    (see :data:`REASON_STATES`)."""

    # target resolution
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    TARGET_NOT_FULLY_QUALIFIED = "TARGET_NOT_FULLY_QUALIFIED"
    UNSUPPORTED_TARGET_TYPE = "UNSUPPORTED_TARGET_TYPE"
    UNKNOWN_TRANSFORMATION = "UNKNOWN_TRANSFORMATION"
    # completeness
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    DEX_ANALYSIS_INCOMPLETE = "DEX_ANALYSIS_INCOMPLETE"
    TARGET_DEFINITION_INCOMPLETE = "TARGET_DEFINITION_INCOMPLETE"
    REFLECTION_ANALYSIS_INCOMPLETE = "REFLECTION_ANALYSIS_INCOMPLETE"
    MANIFEST_ANALYSIS_INCOMPLETE = "MANIFEST_ANALYSIS_INCOMPLETE"
    RESOURCE_ANALYSIS_INCOMPLETE = "RESOURCE_ANALYSIS_INCOMPLETE"
    # code references
    CLASS_CALLER_PRESENT = "CLASS_CALLER_PRESENT"
    TYPE_REFERENCE_PRESENT = "TYPE_REFERENCE_PRESENT"
    METHOD_CALLER_PRESENT = "METHOD_CALLER_PRESENT"
    FIELD_REFERENCE_PRESENT = "FIELD_REFERENCE_PRESENT"
    CONSTRUCTOR_REFERENCE_PRESENT = "CONSTRUCTOR_REFERENCE_PRESENT"
    CONST_CLASS_REFERENCE_PRESENT = "CONST_CLASS_REFERENCE_PRESENT"
    STRING_REFERENCE_UNRESOLVED = "STRING_REFERENCE_UNRESOLVED"
    # reflection / dynamic
    REFLECTION_TARGET_PRESENT = "REFLECTION_TARGET_PRESENT"
    REFLECTION_TARGET_UNKNOWN = "REFLECTION_TARGET_UNKNOWN"
    DYNAMIC_CODE_LOADING_PRESENT = "DYNAMIC_CODE_LOADING_PRESENT"
    ANNOTATION_DRIVEN_ACCESS_POSSIBLE = "ANNOTATION_DRIVEN_ACCESS_POSSIBLE"
    # native
    NATIVE_METHOD_DECLARED = "NATIVE_METHOD_DECLARED"
    NATIVE_DEPENDENCY_UNKNOWN = "NATIVE_DEPENDENCY_UNKNOWN"
    # manifest / resources
    MANIFEST_COMPONENT_REFERENCE = "MANIFEST_COMPONENT_REFERENCE"
    MANIFEST_REFERENCE_PRESENT = "MANIFEST_REFERENCE_PRESENT"
    MANIFEST_TEXTUAL_MATCH = "MANIFEST_TEXTUAL_MATCH"
    RESOURCE_REFERENCE_PRESENT = "RESOURCE_REFERENCE_PRESENT"
    RESOURCE_TEXTUAL_MATCH = "RESOURCE_TEXTUAL_MATCH"
    RESOURCE_METHOD_REFERENCE_NOT_ANALYZED = "RESOURCE_METHOD_REFERENCE_NOT_ANALYZED"
    # method shape / hierarchy
    CONSTRUCTOR_METHOD = "CONSTRUCTOR_METHOD"
    CLASS_INITIALIZER = "CLASS_INITIALIZER"
    ABSTRACT_METHOD = "ABSTRACT_METHOD"
    INTERFACE_METHOD = "INTERFACE_METHOD"
    NATIVE_METHOD = "NATIVE_METHOD"
    SYNTHETIC_METHOD = "SYNTHETIC_METHOD"
    ENUM_IMPLICIT_METHOD = "ENUM_IMPLICIT_METHOD"
    SERIALIZATION_HOOK_METHOD = "SERIALIZATION_HOOK_METHOD"
    METHOD_OVERRIDES = "METHOD_OVERRIDES"
    METHOD_OVERRIDDEN = "METHOD_OVERRIDDEN"
    OVERRIDE_RELATIONSHIP_UNRESOLVED = "OVERRIDE_RELATIONSHIP_UNRESOLVED"
    # call sites (H-TRANS-003)
    CALL_SITE_NOT_FOUND = "CALL_SITE_NOT_FOUND"
    CALL_SITE_AMBIGUOUS = "CALL_SITE_AMBIGUOUS"
    CALL_SITE_MULTIPLE_MATCHES = "CALL_SITE_MULTIPLE_MATCHES"
    CALL_SITE_ALREADY_REPLACED = "CALL_SITE_ALREADY_REPLACED"
    CALLER_ANALYSIS_INCOMPLETE = "CALLER_ANALYSIS_INCOMPLETE"
    UNSUPPORTED_INVOKE_OPCODE = "UNSUPPORTED_INVOKE_OPCODE"
    CONSTRUCTOR_INVOCATION = "CONSTRUCTOR_INVOCATION"
    POLYMORPHIC_INVOCATION = "POLYMORPHIC_INVOCATION"
    INVOKE_CUSTOM_UNSUPPORTED = "INVOKE_CUSTOM_UNSUPPORTED"
    INVOKE_POLYMORPHIC_UNSUPPORTED = "INVOKE_POLYMORPHIC_UNSUPPORTED"
    TARGET_METHOD_NOT_FOUND = "TARGET_METHOD_NOT_FOUND"
    TARGET_RELATIONSHIP_UNRESOLVED = "TARGET_RELATIONSHIP_UNRESOLVED"
    PARAMETER_INVALID = "PARAMETER_INVALID"
    REPLACEMENT_METHOD_NOT_FOUND = "REPLACEMENT_METHOD_NOT_FOUND"
    REPLACEMENT_SIGNATURE_MISMATCH = "REPLACEMENT_SIGNATURE_MISMATCH"
    REPLACEMENT_INACCESSIBLE = "REPLACEMENT_INACCESSIBLE"
    REGISTER_TYPE_MISMATCH = "REGISTER_TYPE_MISMATCH"
    RESULT_TYPE_MISMATCH = "RESULT_TYPE_MISMATCH"
    # request set
    CONFLICTING_TRANSFORMATION = "CONFLICTING_TRANSFORMATION"
    # conditions (CONDITIONALLY_ELIGIBLE)
    KOTLIN_METADATA_UPDATE_REQUIRED = "KOTLIN_METADATA_UPDATE_REQUIRED"


_R = DecisionReason
_E = EligibilityState

#: the eligibility state each reason code imposes
REASON_STATES: dict[DecisionReason, EligibilityState] = {
    _R.TARGET_NOT_FOUND: _E.REFUSED,
    _R.TARGET_AMBIGUOUS: _E.REFUSED,
    _R.TARGET_NOT_FULLY_QUALIFIED: _E.REFUSED,
    _R.UNSUPPORTED_TARGET_TYPE: _E.UNSUPPORTED,
    _R.UNKNOWN_TRANSFORMATION: _E.UNSUPPORTED,
    _R.ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.DEX_ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.TARGET_DEFINITION_INCOMPLETE: _E.UNDETERMINED,
    _R.REFLECTION_ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.MANIFEST_ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.RESOURCE_ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.CLASS_CALLER_PRESENT: _E.REFUSED,
    _R.TYPE_REFERENCE_PRESENT: _E.REFUSED,
    _R.METHOD_CALLER_PRESENT: _E.REFUSED,
    _R.FIELD_REFERENCE_PRESENT: _E.REFUSED,
    _R.CONSTRUCTOR_REFERENCE_PRESENT: _E.REFUSED,
    _R.CONST_CLASS_REFERENCE_PRESENT: _E.REFUSED,
    _R.STRING_REFERENCE_UNRESOLVED: _E.UNDETERMINED,
    _R.REFLECTION_TARGET_PRESENT: _E.REFUSED,
    _R.REFLECTION_TARGET_UNKNOWN: _E.UNDETERMINED,
    _R.DYNAMIC_CODE_LOADING_PRESENT: _E.UNDETERMINED,
    _R.ANNOTATION_DRIVEN_ACCESS_POSSIBLE: _E.UNDETERMINED,
    _R.NATIVE_METHOD_DECLARED: _E.UNSUPPORTED,
    _R.NATIVE_DEPENDENCY_UNKNOWN: _E.UNDETERMINED,
    _R.MANIFEST_COMPONENT_REFERENCE: _E.REFUSED,
    _R.MANIFEST_REFERENCE_PRESENT: _E.REFUSED,
    _R.MANIFEST_TEXTUAL_MATCH: _E.UNDETERMINED,
    _R.RESOURCE_REFERENCE_PRESENT: _E.REFUSED,
    _R.RESOURCE_TEXTUAL_MATCH: _E.UNDETERMINED,
    _R.RESOURCE_METHOD_REFERENCE_NOT_ANALYZED: _E.UNDETERMINED,
    _R.CONSTRUCTOR_METHOD: _E.UNSUPPORTED,
    _R.CLASS_INITIALIZER: _E.UNSUPPORTED,
    _R.ABSTRACT_METHOD: _E.UNSUPPORTED,
    _R.INTERFACE_METHOD: _E.UNSUPPORTED,
    _R.NATIVE_METHOD: _E.UNSUPPORTED,
    _R.SYNTHETIC_METHOD: _E.UNSUPPORTED,
    _R.ENUM_IMPLICIT_METHOD: _E.UNSUPPORTED,
    _R.SERIALIZATION_HOOK_METHOD: _E.UNSUPPORTED,
    _R.METHOD_OVERRIDES: _E.UNSUPPORTED,
    _R.METHOD_OVERRIDDEN: _E.UNSUPPORTED,
    _R.OVERRIDE_RELATIONSHIP_UNRESOLVED: _E.UNDETERMINED,
    _R.CALL_SITE_NOT_FOUND: _E.REFUSED,
    _R.CALL_SITE_AMBIGUOUS: _E.REFUSED,
    _R.CALL_SITE_MULTIPLE_MATCHES: _E.REFUSED,
    _R.CALL_SITE_ALREADY_REPLACED: _E.REFUSED,
    _R.CALLER_ANALYSIS_INCOMPLETE: _E.UNDETERMINED,
    _R.UNSUPPORTED_INVOKE_OPCODE: _E.UNSUPPORTED,
    _R.CONSTRUCTOR_INVOCATION: _E.UNSUPPORTED,
    _R.POLYMORPHIC_INVOCATION: _E.UNSUPPORTED,
    _R.INVOKE_CUSTOM_UNSUPPORTED: _E.UNSUPPORTED,
    _R.INVOKE_POLYMORPHIC_UNSUPPORTED: _E.UNSUPPORTED,
    _R.TARGET_METHOD_NOT_FOUND: _E.REFUSED,
    _R.TARGET_RELATIONSHIP_UNRESOLVED: _E.UNDETERMINED,
    _R.PARAMETER_INVALID: _E.REFUSED,
    _R.REPLACEMENT_METHOD_NOT_FOUND: _E.REFUSED,
    _R.REPLACEMENT_SIGNATURE_MISMATCH: _E.REFUSED,
    _R.REPLACEMENT_INACCESSIBLE: _E.REFUSED,
    _R.REGISTER_TYPE_MISMATCH: _E.REFUSED,
    _R.RESULT_TYPE_MISMATCH: _E.REFUSED,
    _R.CONFLICTING_TRANSFORMATION: _E.REFUSED,
    _R.KOTLIN_METADATA_UPDATE_REQUIRED: _E.CONDITIONALLY_ELIGIBLE,
}
assert set(REASON_STATES) == set(DecisionReason)


class TargetKind(StrEnum):
    CLASS = "class"
    METHOD = "method"
    #: H.6: one invocation inside one method (``CALLER@INVOKED[#N]``)
    CALL_SITE = "call_site"


class TransformationTarget(BaseModel):
    """A normalised transformation target.

    Classes are dotted (``com.example.Foo``). Methods carry the class, the name and the
    smali proto (``(I)V``); ``descriptor`` is None when the request omitted it.

    A call site (H.6) is the *caller* method (``class_name`` / ``method_name`` /
    ``descriptor``) plus the invoked method it calls (``invoked_*``) and, when the caller
    invokes it more than once, the 1-based ``occurrence`` in source order. The ``invoked_*``
    fields and ``occurrence`` are None for class and method targets (omitted from JSON).
    """

    kind: TargetKind
    class_name: str
    method_name: str | None = None
    descriptor: str | None = None
    invoked_class: str | None = None
    invoked_name: str | None = None
    invoked_descriptor: str | None = None
    occurrence: int | None = None
    #: the request as given (before normalisation)
    raw: str

    @property
    def caller(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.descriptor or ''}"

    @property
    def invoked(self) -> str:
        return f"{self.invoked_class}->{self.invoked_name}{self.invoked_descriptor or ''}"

    @property
    def canonical(self) -> str:
        if self.kind is TargetKind.CLASS:
            return self.class_name
        if self.kind is TargetKind.CALL_SITE:
            nth = f"#{self.occurrence}" if self.occurrence is not None else ""
            return f"{self.caller}@{self.invoked}{nth}"
        return f"{self.class_name}->{self.method_name}{self.descriptor or ''}"


class TransformationSpec(BaseModel):
    """Catalog entry: what a transformation is and what it requires (no executor)."""

    id: str
    name: str
    description: str
    category: str
    target_type: TargetKind
    required_evidence: list[str]
    preconditions: list[str]
    eligibility_rules: list[str]
    planned_changes: list[str]
    verification_requirements: list[str]
    risk: ModificationRisk
    reversibility: Reversibility
    compatibility_constraints: list[str]
    limitations: list[str] = Field(default_factory=list)


class TransformationRequest(BaseModel):
    transformation_id: str
    target: str
    parameters: dict[str, str] = Field(default_factory=dict)


class ReasonDetail(BaseModel):
    """One reason code with its evidence and a human-readable explanation."""

    code: DecisionReason
    state: EligibilityState
    requirement: str
    message: str
    #: ids of the underlying H.1 evidence records (first few; see ``evidence_count``)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_count: int = 0


class RequirementStatus(StrEnum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    UNSUPPORTED = "UNSUPPORTED"
    CONDITIONAL = "CONDITIONAL"
    NOT_EVALUATED = "NOT_EVALUATED"


class RequirementCheck(BaseModel):
    """One precondition of a transformation and how the evidence answered it."""

    id: str
    description: str
    status: RequirementStatus
    reasons: list[DecisionReason] = Field(default_factory=list)


class AbsenceStatus(StrEnum):
    """H.1 absence semantics applied to one evidence category."""

    #: structural references were observed
    REFERENCES_PRESENT = "REFERENCES_PRESENT"
    #: no structural reference; only strings / textual / unresolved hints
    ONLY_INDIRECT_EVIDENCE = "ONLY_INDIRECT_EVIDENCE"
    #: nothing observed, but the relevant analysis is not COMPLETE
    ABSENCE_NOT_ESTABLISHED = "ABSENCE_NOT_ESTABLISHED"
    #: nothing observed and the relevant analysis is COMPLETE (static scope only)
    ABSENCE_ESTABLISHED = "ABSENCE_ESTABLISHED"


class CategorySummary(BaseModel):
    """Compact summary of one evidence category of a target evidence set."""

    category: str
    count: int
    absence: AbsenceStatus
    analysis_state: AnalysisState
    #: first evidence ids (deterministic order); ``truncated`` when more exist
    evidence_ids: list[str] = Field(default_factory=list)
    truncated: bool = False
    #: distinct source classes (first few) for code evidence
    source_classes: list[str] = Field(default_factory=list)


class TargetEvidenceSummary(BaseModel):
    target: str
    component_states: dict[str, AnalysisState]
    categories: list[CategorySummary]
    total_evidence: int


class PlannedTransformChange(BaseModel):
    """A change a future H.3 engine would make. Never executed by H.2."""

    type: str
    target: str
    artifact: str | None = None
    details: dict[str, str] = Field(default_factory=dict)


class PlanCondition(BaseModel):
    """An explicit condition that must be satisfied before a conditional plan applies."""

    code: DecisionReason
    description: str
    satisfied: bool = False


class ConflictRecord(BaseModel):
    code: DecisionReason = DecisionReason.CONFLICTING_TRANSFORMATION
    kind: str
    requests: list[str]
    message: str


class TransformationPlan(BaseModel):
    """Deterministic plan for an ELIGIBLE / CONDITIONALLY_ELIGIBLE decision (not applied)."""

    plan_id: str
    planning_schema: int = PLANNING_SCHEMA_VERSION
    analysis_schema: int
    transformation_id: str
    apk: ApkIdentity
    target: TransformationTarget
    parameters: dict[str, str] = Field(default_factory=dict)
    eligibility: EligibilityState
    decision_reasons: list[ReasonDetail] = Field(default_factory=list)
    target_evidence_summary: TargetEvidenceSummary
    preconditions: list[RequirementCheck]
    conditions: list[PlanCondition] = Field(default_factory=list)
    planned_changes: list[PlannedTransformChange]
    expected_changes: list[str]
    verification_requirements: list[str]
    risk: ModificationRisk
    reversibility: Reversibility
    compatibility_constraints: list[str]
    limitations: list[str]
    applied: bool = False


class TransformationDecision(BaseModel):
    """Eligibility decision for one request; ``plan`` only when plannable."""

    decision_id: str
    transformation_id: str
    target: TransformationTarget | None
    parameters: dict[str, str] = Field(default_factory=dict)
    eligibility: EligibilityState
    reasons: list[ReasonDetail] = Field(default_factory=list)
    requirements: list[RequirementCheck] = Field(default_factory=list)
    target_evidence_summary: TargetEvidenceSummary | None = None
    plan: TransformationPlan | None = None
    statement: str


class PlanningResult(BaseModel):
    """H.2 output for one APK and one request set. Planning only: nothing is applied."""

    planning_schema: int = PLANNING_SCHEMA_VERSION
    analysis_schema: int
    apk: ApkIdentity
    analysis_state: AnalysisState
    component_states: dict[str, AnalysisState]
    decisions: list[TransformationDecision]
    conflicts: list[ConflictRecord] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    #: SHA-256 of the input APK identical before and after (None: no APK given)
    original_unchanged: bool | None = None
    applied: bool = False

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in EligibilityState}
        for d in self.decisions:
            out[d.eligibility.value] += 1
        return out

    @property
    def plans(self) -> list[TransformationPlan]:
        return [d.plan for d in self.decisions if d.plan is not None]

    def to_json(self, *, indent: int | None = 2) -> str:
        """Deterministic JSON (no timestamps, absolute paths or random ids)."""
        return self.model_dump_json(indent=indent, exclude_none=True)
