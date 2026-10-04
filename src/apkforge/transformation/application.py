"""Phase H.3 application models: the result of applying one H.2 plan.

H.3 applies exactly one ``ELIGIBLE`` H.2 plan of a supported transformation (only
``H-TRANS-001``, remove isolated class) to a copy of the APK, rebuilds, aligns, signs and
verifies it with the existing BuildService, re-analyses the output with H.1 and compares
original vs transformed with the Phase E diff machinery. Nothing here states that an
application is safe, benign or malware-free.

Central rules
-------------
- Only a complete, unmodified H.2 plan whose eligibility is ``ELIGIBLE`` reaches the
  mutation stage; there is no override.
- Every outcome other than ``VERIFIED`` / ``PLANNED`` carries one machine-readable
  :class:`ApplicationReason` and the stage it was decided at.
- ``VERIFIED`` requires every mandatory row of the verification matrix to pass; a
  successful build alone is never a verified transformation.
- The source APK is never written; its SHA-256 is compared before and after.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.diff.expectations import ExpectedChange  # noqa: TC001 - pydantic field

__all__ = [
    "APPLICATION_SCHEMA_VERSION",
    "SUPPORTED_TRANSFORMATIONS",
    "ApplicationFailure",
    "ApplicationReason",
    "ApplicationStage",
    "ApplicationStatus",
    "CheckOutcome",
    "MatrixRow",
    "MethodPostAnalysis",
    "MutationRecord",
    "PostAnalysis",
    "TransformationApplicationResult",
]

#: version of the H.3 result format
APPLICATION_SCHEMA_VERSION = 1

#: transformations the controlled executor can apply (H.3 remove class, H.5 remove method)
SUPPORTED_TRANSFORMATIONS = ("H-TRANS-001", "H-TRANS-002")


class ApplicationStatus(StrEnum):
    """State of one H.3 application.

    PLANNED   plan validated (dry run); nothing was mutated, built or signed
    APPLYING  the plan passed every integrity check and mutation started (transient)
    BUILT     the mutated project was built, aligned, signed and verified (transient)
    VERIFIED  every mandatory verification passed; the output APK was published
    REFUSED   rejected before any mutation (plan, source, eligibility or target checks)
    FAILED    a stage or a mandatory verification failed; nothing was published
    UNKNOWN   the verification could not establish the expected state (e.g. the
              post-transform analysis is incomplete); nothing was published
    """

    PLANNED = "PLANNED"
    APPLYING = "APPLYING"
    BUILT = "BUILT"
    VERIFIED = "VERIFIED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ApplicationReason(StrEnum):
    """Machine-readable reason for a refusal or failure."""

    PLAN_NOT_FOUND = "PLAN_NOT_FOUND"
    PLAN_INVALID = "PLAN_INVALID"
    PLAN_ID_MISMATCH = "PLAN_ID_MISMATCH"
    #: the plan is not what H.2 produces for this APK today (edited or stale)
    PLAN_MISMATCH = "PLAN_MISMATCH"
    SOURCE_SHA_MISMATCH = "SOURCE_SHA_MISMATCH"
    PLAN_NOT_ELIGIBLE = "PLAN_NOT_ELIGIBLE"
    UNSUPPORTED_TRANSFORMATION = "UNSUPPORTED_TRANSFORMATION"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    TARGET_STATE_MISMATCH = "TARGET_STATE_MISMATCH"
    #: the plan targets a member shape the controlled executor does not remove
    UNSUPPORTED_TARGET_TYPE = "UNSUPPORTED_TARGET_TYPE"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    TRANSFORMATION_PRECONDITION_FAILED = "TRANSFORMATION_PRECONDITION_FAILED"
    #: the mutation changed something other than exactly the planned class / method
    UNEXPECTED_MUTATION = "UNEXPECTED_MUTATION"
    NOISE_BASELINE_UNAVAILABLE = "NOISE_BASELINE_UNAVAILABLE"
    POST_TRANSFORMATION_VERIFICATION_FAILED = "POST_TRANSFORMATION_VERIFICATION_FAILED"
    UNEXPECTED_DIFF = "UNEXPECTED_DIFF"
    DECODE_FAILED = "DECODE_FAILED"
    BUILD_FAILED = "BUILD_FAILED"
    ALIGN_FAILED = "ALIGN_FAILED"
    SIGN_FAILED = "SIGN_FAILED"
    SIGNATURE_VERIFICATION_FAILED = "SIGNATURE_VERIFICATION_FAILED"
    ORIGINAL_CHANGED = "ORIGINAL_CHANGED"
    OUTPUT_INVALID = "OUTPUT_INVALID"


class ApplicationStage(StrEnum):
    """Where an outcome was decided (in pipeline order)."""

    PLAN_LOAD = "plan_load"
    PLAN_INTEGRITY = "plan_integrity"
    ELIGIBILITY = "eligibility"
    PREPARE = "prepare"
    DECODE = "decode"
    PRE_TRANSFORM = "pre_transform"
    MUTATION = "mutation"
    BUILD = "build"
    ALIGN = "align"
    SIGN = "sign"
    VERIFY = "verify"
    DIFF = "diff"
    POST_ANALYSIS = "post_analysis"
    PUBLISH = "publish"


class ApplicationFailure(BaseModel):
    code: ApplicationReason
    stage: ApplicationStage
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class MutationRecord(BaseModel):
    """What the mutation did to the decoded project (machine-readable).

    For ``REMOVE_CLASS`` (H-TRANS-001) the target smali file is deleted and the class
    census shrinks by one. For ``REMOVE_METHOD`` (H-TRANS-002) the file is *modified*
    (one ``.method`` block removed), the class census is unchanged and the method fields
    describe the single removed declaration.
    """

    transformation_id: str
    operation: str = "REMOVE_CLASS"
    target: str
    target_file: str
    target_dex: str
    count: int
    #: SHA-256 of the target smali file before the mutation; for REMOVE_CLASS it does not
    #: exist afterwards (``post_transform_sha256`` None), for REMOVE_METHOD it is modified
    pre_transform_sha256: str
    post_transform_sha256: str | None = None
    classes_before: int
    classes_after: int
    removed_classes: list[str] = Field(default_factory=list)
    added_classes: list[str] = Field(default_factory=list)
    #: SHA-256 over the sorted defined-class list before / after the mutation
    census_before_sha256: str
    census_after_sha256: str
    # -- REMOVE_METHOD only (the containing class survives) --
    method_name: str | None = None
    descriptor: str | None = None
    #: ``name`` + smali proto, e.g. ``foo(I)V``
    method_signature: str | None = None
    #: the identity the Phase E DEX differ reports, e.g. ``foo(int)V``
    method_key: str | None = None
    methods_before: int | None = None
    methods_after: int | None = None
    #: method signatures removed / added / with a changed body in the target class
    removed_methods: list[str] = Field(default_factory=list)
    added_methods: list[str] = Field(default_factory=list)
    changed_methods: list[str] = Field(default_factory=list)


class CheckOutcome(StrEnum):
    PASS = "PASS"  # noqa: S105 - a check outcome, not a password
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


class MatrixRow(BaseModel):
    """One row of the expected-vs-actual transformation verification matrix."""

    check: str
    expected: str
    actual: str
    status: CheckOutcome
    mandatory: bool = True


class PostAnalysis(BaseModel):
    """H.1 re-analysis of the transformed APK, compared with the original analysis."""

    analysis_schema: int
    analysis_state: str
    component_states: dict[str, str]
    #: components whose state is weaker than in the original analysis
    weakened_components: list[str] = Field(default_factory=list)
    defined_classes_before: int
    defined_classes_after: int
    target_defined: bool
    #: other classes defined before but not after / after but not before
    other_classes_removed: list[str] = Field(default_factory=list)
    classes_added: list[str] = Field(default_factory=list)
    #: H.1 absence assessment of the removed class in the transformed APK
    absence_conclusion: str
    definitive_references: int
    indirect_references: int
    sufficient: bool
    errors: list[str] = Field(default_factory=list)


class MethodPostAnalysis(BaseModel):
    """H.1 re-analysis of a method removal: the class survives, the method is gone."""

    analysis_schema: int
    analysis_state: str
    component_states: dict[str, str]
    #: components whose state is weaker than in the original analysis
    weakened_components: list[str] = Field(default_factory=list)
    class_name: str
    class_defined: bool
    method_signature: str
    target_method_present: bool
    methods_before: int
    methods_after: int
    #: method signatures of the class removed besides the target / added
    other_methods_removed: list[str] = Field(default_factory=list)
    methods_added: list[str] = Field(default_factory=list)
    #: remaining call sites / resolved reflection reaching the method (must be 0)
    definitive_references: int = 0
    #: remaining name-only / string / unresolved hints (indirect; must be 0 to verify)
    indirect_references: int = 0
    sufficient: bool
    errors: list[str] = Field(default_factory=list)


class TransformationApplicationResult(BaseModel):
    """H.3 / H.5 output for one plan application (or dry run)."""

    schema_version: int = APPLICATION_SCHEMA_VERSION
    phase: str = "H.3"
    planning_schema: int | None = None
    analysis_schema: int | None = None
    transformation_id: str | None = None
    plan_id: str | None = None
    #: SHA-256 recorded in the plan (None when the plan could not be read)
    plan_source_sha256: str | None = None
    source_apk: str
    source_apk_sha256: str
    source_apk_sha256_after: str | None = None
    original_unchanged: bool | None = None
    target: dict[str, str] = Field(default_factory=dict)
    status: ApplicationStatus
    status_history: list[ApplicationStatus] = Field(default_factory=list)
    dry_run: bool = False
    workspace_id: str | None = None
    workspace: str | None = None
    workspace_kept: bool = False
    #: what would be / was applied (H.2 planned changes, verbatim)
    planned_changes: list[dict[str, Any]] = Field(default_factory=list)
    #: semantic changes declared before mutation (Phase E expected changes)
    expected_changes: list[ExpectedChange] = Field(default_factory=list)
    mutation: MutationRecord | None = None
    build: dict[str, Any] = Field(default_factory=dict)
    diff: dict[str, Any] = Field(default_factory=dict)
    analysis: PostAnalysis | None = None
    #: H.5 (REMOVE_METHOD): method-level re-analysis in place of ``analysis``
    method_analysis: MethodPostAnalysis | None = None
    verification: list[MatrixRow] = Field(default_factory=list)
    output_apk: str | None = None
    output_apk_sha256: str | None = None
    #: SHA-256 over the sorted (entry name, entry content SHA-256) list of the output APK
    output_content_sha256: str | None = None
    failure: ApplicationFailure | None = None
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.status is ApplicationStatus.VERIFIED

    def advance(self, status: ApplicationStatus) -> None:
        self.status = status
        self.status_history.append(status)

    def comparable(self) -> dict[str, Any]:
        """Run-independent content (no paths, workspace ids or archive timestamps)."""
        return self.model_dump(
            mode="json",
            exclude={
                "source_apk",
                "workspace_id",
                "workspace",
                "workspace_kept",
                "output_apk",
                "output_apk_sha256",
            },
        )

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent, exclude_none=False)
