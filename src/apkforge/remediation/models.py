"""Phase G: Controlled Privacy/Security Remediation models.

Defines the core data structures for remediation definitions, plans,
precondition checks, before/after comparisons, and execution results.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.modification.models import ModificationRisk
from apkforge.privacy.models import PrivacyResult  # noqa: TC001 - pydantic field type


class RemediationRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SupportedStatus(StrEnum):
    SUPPORTED = "supported"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"


class RemediationState(StrEnum):
    PLANNED = "planned"
    APPROVAL_REQUIRED = "approval_required"
    APPLIED = "applied"
    VERIFIED = "verified"
    PARTIALLY_REMEDIATED = "partially_remediated"
    FAILED = "failed"
    SKIPPED = "skipped"
    REFUSED = "refused"
    UNDETERMINED = "undetermined"
    ROLLBACK_FAILED = "rollback_failed"


class FindingResolution(StrEnum):
    REMEDIATED = "remediated"
    PARTIALLY_REMEDIATED = "partially_remediated"
    STILL_PRESENT = "still_present"
    NO_LONGER_COMPARABLE = "no_longer_comparable"
    UNKNOWN = "unknown"


class PreconditionCheck(BaseModel):
    """One checked precondition for a remediation plan."""

    name: str
    satisfied: bool
    expected: str
    actual: str
    reason: str = ""


class RemediationDefinition(BaseModel):
    """Metadata describing a supported remediation type."""

    id: str  # e.g. G-REM-001
    name: str
    description: str
    target_categories: list[str] = Field(default_factory=list)
    target_finding_ids: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    affected_structures: list[str] = Field(default_factory=list)
    planned_modifications: list[str] = Field(default_factory=list)
    risk: ModificationRisk = ModificationRisk.MEDIUM
    reversible: bool = True
    verification_requirements: list[str] = Field(default_factory=list)
    compatibility_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    can_apply_after_approval: bool = True
    manual_review_required: bool = False
    status: SupportedStatus = SupportedStatus.SUPPORTED


class RemediationPlan(BaseModel):
    """Deterministic, machine-readable plan for applying a remediation."""

    plan_id: str
    source_apk_path: str
    source_apk_sha256: str
    package_name: str | None = None
    finding_id: str
    finding_category: str
    finding_title: str
    finding_evidence_locations: list[str] = Field(default_factory=list)
    finding_evidence_values: list[str] = Field(default_factory=list)
    finding_state: str = "OBSERVED"
    remediation_id: str
    remediation_name: str
    state: RemediationState = RemediationState.PLANNED
    preconditions: list[PreconditionCheck] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    planned_changes: list[str] = Field(default_factory=list)
    expected_diff: list[str] = Field(default_factory=list)
    verification_plan: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    compatibility_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    modifier_requests: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = ""

    @property
    def ready(self) -> bool:
        return (
            self.state in (RemediationState.PLANNED, RemediationState.APPROVAL_REQUIRED)
            and bool(self.preconditions)
            and all(p.satisfied for p in self.preconditions)
        )


class TargetFindingComparison(BaseModel):
    """Before/after comparison for the specific target finding."""

    finding_id: str
    resolution: FindingResolution
    before_evidence: list[str] = Field(default_factory=list)
    after_evidence: list[str] = Field(default_factory=list)
    explanation: str = ""


class BeforeAfterComparison(BaseModel):
    """Comprehensive comparison between pre- and post-remediation privacy states."""

    target_finding: TargetFindingComparison
    findings_removed: list[str] = Field(default_factory=list)
    findings_retained: list[str] = Field(default_factory=list)
    findings_changed: list[str] = Field(default_factory=list)
    findings_introduced: list[str] = Field(default_factory=list)
    sdk_changes: dict[str, Any] = Field(default_factory=dict)
    endpoint_changes: dict[str, Any] = Field(default_factory=dict)
    permission_changes: dict[str, Any] = Field(default_factory=dict)
    component_changes: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class RemediationExecutionResult(BaseModel):
    """Complete result of executing a remediation plan."""

    plan: RemediationPlan
    state: RemediationState
    approved: bool
    output_apk_path: str | None = None
    output_apk_sha256: str | None = None
    original_apk_sha256_before: str
    original_apk_sha256_after: str | None = None
    original_apk_preserved: bool = False
    pipeline_status: str | None = None
    build_passed: bool | None = None
    apk_verified: bool | None = None
    verification_passed: bool = False
    verification_details: dict[str, Any] = Field(default_factory=dict)
    comparison: BeforeAfterComparison | None = None
    post_analysis: PrivacyResult | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rollback_occurred: bool = False
    rollback_success: bool | None = None

    @property
    def success(self) -> bool:
        """True if the remediation applied and verified successfully."""
        return self.state in (RemediationState.VERIFIED, RemediationState.PARTIALLY_REMEDIATED)
