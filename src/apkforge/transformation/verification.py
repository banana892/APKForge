"""Phase H.4 transformation verification models (schema 1).

H.4 hardens the verification of an applied ``H-TRANS-001`` transformation by comparing
*three* APKs instead of two::

    A = original APK
    B = unmodified (control) rebuild of A     A -> B   toolchain / build noise
    C = transformed rebuild of A              A -> C   complete observed transformation
                                              B -> C   transformation signal

Every difference observed between A and C is classified with the Phase E
expected-vs-actual machinery against the noise floor *measured by B* (never assumed) and
then cross-checked against B -> C:

- ``NOISE``                    the same difference, with the same content, occurs in the
                               unmodified rebuild B (Phase E ``REBUILD_NOISE``) and B and C
                               agree on it
- ``EXPECTED_TRANSFORMATION``  declared before verification from the plan and the
                               original APK (Phase E ``EXPECTED_MODIFICATION`` /
                               ``PLANNED_ENTRY``) *and* present in the B -> C signal
- ``UNEXPECTED_CHANGE``        neither (Phase E ``UNEXPECTED``)
- ``UNKNOWN``                  the comparison could not establish the facts, or the legs
                               disagree (Phase E ``UNKNOWN``, or an inconsistency)

Completeness is reported per verification domain; the overall result is never stronger
than the weakest mandatory domain. Static verification does not establish that the
transformed application is safe, malware-free, spyware-free or functionally correct.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.diff.expectations import ExpectedChange, Observation  # noqa: TC001 - pydantic
from apkforge.diff.normalization import ToolchainIdentity  # noqa: TC001 - pydantic field
from apkforge.transformation.application import (  # noqa: TC001 - pydantic field
    CallSitePostAnalysis,
    MethodPostAnalysis,
    PostAnalysis,
)
from apkforge.verification.models import CheckStatus, VerificationCheck  # noqa: TC001

__all__ = [
    "COMPLETENESS_ORDER",
    "DOMAIN_COMPARATORS",
    "H4_LIMITATIONS",
    "H4_STATEMENT",
    "MANDATORY_DOMAINS",
    "VERIFICATION_RESULT_SCHEMA_VERSION",
    "ClassifiedDifference",
    "Completeness",
    "ControlPresence",
    "DifferenceClass",
    "DomainReport",
    "InvariantCheck",
    "LegSummary",
    "RebuildRecord",
    "TransformationVerificationResult",
    "TransformationVerificationStatus",
    "VerificationDomain",
    "weakest",
]

#: version of the H.4 verification result format
VERIFICATION_RESULT_SCHEMA_VERSION = 1

H4_STATEMENT = (
    "Static verification does not establish that the transformed application is safe, "
    "malware-free, spyware-free, or functionally correct when executed. APK byte "
    "differences between independent rebuilds are not automatically treated as "
    "transformation differences; the control rebuild establishes the observed toolchain "
    "noise floor."
)

H4_LIMITATIONS = [
    "Verification is static: the APKs are compared and re-analysed, never installed or run.",
    "Noise is accepted only when the unmodified control rebuild of the same APK, built by "
    "the same toolchain, produces the same difference with the same content.",
    "Native libraries are compared by content hash and ELF metadata only; native code is "
    "not analysed, so a changed library can be detected but not interpreted.",
    "res/ binary XML and resources.arsc entries are compared by content hash, not decoded; "
    "byte identity with the control rebuild is established, semantic identity with the "
    "original is not when the toolchain re-encodes them.",
    "v1 signature files are accepted between control and transformed rebuild by path and "
    "change kind only; their correctness is established by apksigner, not by this rule.",
]


class DifferenceClass(StrEnum):
    NOISE = "NOISE"
    EXPECTED_TRANSFORMATION = "EXPECTED_TRANSFORMATION"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"
    UNKNOWN = "UNKNOWN"


class Completeness(StrEnum):
    """How much of a domain's verification claim could be established.

    COMPLETE      every comparator of the domain completed on every leg
    PARTIAL       a comparator compared only part of the data, or compares at a level
                  below semantics (e.g. resources.arsc bytes); the limitation is listed
    UNKNOWN       a comparator failed / could not run; nothing can be claimed
    NOT_ANALYZED  the domain was not analysed (inputs unavailable)
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOT_ANALYZED = "NOT_ANALYZED"


#: strongest first
COMPLETENESS_ORDER = [
    Completeness.COMPLETE,
    Completeness.PARTIAL,
    Completeness.UNKNOWN,
    Completeness.NOT_ANALYZED,
]


def weakest(values: list[Completeness]) -> Completeness:
    """The weakest completeness (NOT_ANALYZED for an empty list)."""
    if not values:
        return Completeness.NOT_ANALYZED
    return max(values, key=COMPLETENESS_ORDER.index)


class TransformationVerificationStatus(StrEnum):
    """Overall H.4 result.

    VERIFIED                   every mandatory domain COMPLETE, every invariant passed,
                               every difference NOISE or EXPECTED_TRANSFORMATION
    VERIFIED_WITH_LIMITATIONS  as VERIFIED, but at least one mandatory domain is PARTIAL;
                               ``limitations`` enumerates exactly what is not established
    UNVERIFIED                 the verification could not be performed (plan invalid,
                               control or transformed rebuild missing / unusable, no
                               usable noise floor, expectations not derivable)
    FAILED                     an unexpected change, a failed invariant or a changed
                               original
    UNKNOWN                    performed, but a mandatory domain is UNKNOWN or a
                               difference could not be classified
    """

    VERIFIED = "VERIFIED"
    VERIFIED_WITH_LIMITATIONS = "VERIFIED_WITH_LIMITATIONS"
    UNVERIFIED = "UNVERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class VerificationDomain(StrEnum):
    DEX = "dex"
    MANIFEST = "manifest"
    RESOURCES = "resources"
    ASSETS = "assets"
    NATIVE = "native"
    ARCHIVE = "archive"
    SIGNING = "signing"
    ENDPOINTS = "endpoints"


#: every domain is mandatory for H-TRANS-001
MANDATORY_DOMAINS: tuple[VerificationDomain, ...] = tuple(VerificationDomain)

#: domain -> Phase E comparators (:data:`apkforge.diff.comparisons.COMPARATORS`)
DOMAIN_COMPARATORS: dict[VerificationDomain, tuple[str, ...]] = {
    VerificationDomain.DEX: ("dex", "strings"),
    VerificationDomain.MANIFEST: (
        "identity",
        "manifest",
        "manifest_tree",
        "permissions",
        "components",
        "intent_filters",
    ),
    VerificationDomain.RESOURCES: ("resources", "resource_table"),
    VerificationDomain.ASSETS: ("assets",),
    VerificationDomain.NATIVE: ("native",),
    VerificationDomain.ARCHIVE: ("files", "embedded"),
    VerificationDomain.SIGNING: ("certificate",),
    VerificationDomain.ENDPOINTS: ("network",),
}


class ControlPresence(StrEnum):
    """Does the unmodified control rebuild (A -> B) show the same difference?"""

    SAME_CONTENT = "same_content"
    DIFFERENT_CONTENT = "different_content"
    ABSENT = "absent"
    NOT_ANALYZED = "not_analyzed"


class ClassifiedDifference(BaseModel):
    """One observed difference and how it was explained (or not).

    Answers, in order: what was observed (``observation``, on ``leg``); does it exist in
    the unmodified rebuild (``in_control``); is it attributable to the requested
    transformation (``attributable``, ``in_signal``); does it remain unexplained
    (``classification`` UNEXPECTED_CHANGE / UNKNOWN).
    """

    domain: VerificationDomain
    #: ``original->transformed`` or, for a difference only the signal shows,
    #: ``control->transformed``
    leg: str
    observation: Observation
    classification: DifferenceClass
    #: Phase E classification on that leg (ObservationClass value)
    phase_e_class: str
    rule: str | None = None
    assurance: str | None = None
    in_control: ControlPresence
    #: present in the control -> transformed signal (None: signal leg not analysed)
    in_signal: bool | None = None
    attributable: bool = False
    reason: str


class LegSummary(BaseModel):
    """One DiffEngine comparison of the experiment."""

    leg: str
    before_sha256: str | None = None
    after_sha256: str | None = None
    diff_status: str | None = None
    observations: int = 0
    #: Phase E ObservationClass -> count (classified legs only)
    phase_e_counts: dict[str, int] = Field(default_factory=dict)
    #: raw archive diff: added / removed / modified / unchanged entries (content)
    raw_counts: dict[str, int] = Field(default_factory=dict)
    #: entries with identical content but different ZIP metadata (packaging noise)
    metadata_only_changes: int = 0
    #: the archive entry order differs (packaging; content is compared per entry)
    entry_order_changed: bool | None = None
    comparators: dict[str, str] = Field(default_factory=dict)
    failures: list[str] = Field(default_factory=list)
    seconds: float | None = None


class RebuildRecord(BaseModel):
    """The control (B) or transformed (C) rebuild used by the verification."""

    role: str  # control | transformed
    path: str | None = None
    sha256: str | None = None
    #: SHA-256 over the sorted (entry name, entry content SHA-256) list
    content_sha256: str | None = None
    available: bool = False
    #: control: Phase E no-op result of A -> B (EQUIVALENT, NOT_EQUIVALENT, ...)
    noop_result: str | None = None
    #: control: Phase E baseline status built from A -> B (COMPATIBLE, ...)
    baseline_status: str | None = None
    structural: str | None = None
    signature: str | None = None
    signer_sha256: str | None = None
    reasons: list[str] = Field(default_factory=list)


class DomainReport(BaseModel):
    domain: VerificationDomain
    mandatory: bool = True
    completeness: Completeness
    status: CheckStatus
    #: leg -> comparator -> Phase E ComparisonStatus value
    comparators: dict[str, dict[str, str]] = Field(default_factory=dict)
    #: DifferenceClass -> count (original -> transformed, plus signal-only differences)
    counts: dict[str, int] = Field(default_factory=dict)
    facts: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class InvariantCheck(BaseModel):
    """One H-TRANS-001 verification invariant (Section 6 of the H.4 design)."""

    name: str
    domain: VerificationDomain | None = None
    expected: str
    actual: str
    status: CheckStatus


class TransformationVerificationResult(BaseModel):
    """H.4 verification of one transformed APK against its original and a control."""

    schema_version: int = VERIFICATION_RESULT_SCHEMA_VERSION
    phase: str = "H.4"
    mode: str = "transformation"  # transformation | noop (control experiment, no plan)
    transformation_id: str | None = None
    plan_id: str | None = None
    target: dict[str, str] = Field(default_factory=dict)
    source_apk: str | None = None
    source_apk_sha256: str
    source_apk_sha256_after: str | None = None
    original_unchanged: bool | None = None
    control_rebuild: RebuildRecord
    transformed_rebuild: RebuildRecord
    toolchain: ToolchainIdentity | None = None
    #: original->control, original->transformed, control->transformed
    legs: dict[str, LegSummary] = Field(default_factory=dict)
    #: the measured noise floor (A -> B): result, baseline status, accepted rule counts
    noise_floor: dict[str, Any] = Field(default_factory=dict)
    #: changes declared before verification (from the plan and the original APK)
    declared_changes: list[ExpectedChange] = Field(default_factory=list)
    declared_missing: list[str] = Field(default_factory=list)
    expected_changes: list[ClassifiedDifference] = Field(default_factory=list)
    noise_changes: list[ClassifiedDifference] = Field(default_factory=list)
    unexpected_changes: list[ClassifiedDifference] = Field(default_factory=list)
    unknown_changes: list[ClassifiedDifference] = Field(default_factory=list)
    domains: dict[str, DomainReport] = Field(default_factory=dict)
    invariants: list[InvariantCheck] = Field(default_factory=list)
    signature: VerificationCheck | None = None
    post_analysis: PostAnalysis | None = None
    #: H-TRANS-002 (method removal): method-level re-analysis in place of ``post_analysis``
    method_post_analysis: MethodPostAnalysis | None = None
    #: H-TRANS-003 (call-site replacement): call-site re-analysis in place of ``post_analysis``
    call_site_post_analysis: CallSitePostAnalysis | None = None
    completeness: Completeness = Completeness.NOT_ANALYZED
    status: TransformationVerificationStatus = TransformationVerificationStatus.UNVERIFIED
    status_reason: str = ""
    #: every limitation bounding the result (domain-qualified), always enumerated
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    statement: str = H4_STATEMENT
    timings: dict[str, float] = Field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return self.status is TransformationVerificationStatus.VERIFIED

    def differences(self) -> list[ClassifiedDifference]:
        return [
            *self.expected_changes,
            *self.noise_changes,
            *self.unexpected_changes,
            *self.unknown_changes,
        ]

    def comparable(self) -> dict[str, Any]:
        """Run-independent content: no paths, rebuild archive bytes, ZIP metadata or
        timings (independent rebuilds differ there by design)."""
        data = self.model_dump(
            mode="json",
            exclude={"source_apk": True, "timings": True},
        )
        for key in ("control_rebuild", "transformed_rebuild"):
            data[key].pop("path", None)
            data[key].pop("sha256", None)
        for leg in data["legs"].values():
            for k in ("before_sha256", "after_sha256", "metadata_only_changes", "seconds"):
                leg.pop(k, None)
            leg.pop("entry_order_changed", None)
        archive = data["domains"].get("archive")
        if archive:
            archive["facts"].pop("packaging", None)
        return data

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)
