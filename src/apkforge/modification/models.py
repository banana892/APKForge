"""Domain models for APKForge Phase 6 Modification Planning subsystem."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import Confidence, Evidence


class PlanStatus(StrEnum):
    """Lifecycle status of a modification plan."""

    DRAFT = "draft"
    REVIEW_REQUIRED = "review_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    STALE = "stale"
    INVALID = "invalid"


class ChangeType(StrEnum):
    """Supported types of planned modifications."""

    REMOVE_PERMISSION = "remove_permission"
    MODIFY_PERMISSION = "modify_permission"
    DISABLE_COMPONENT = "disable_component"
    REMOVE_COMPONENT = "remove_component"
    MODIFY_COMPONENT = "modify_component"
    REMOVE_TRACKER = "remove_tracker"
    REMOVE_AD_COMPONENT = "remove_ad_component"
    REMOVE_RESOURCE = "remove_resource"
    REMOVE_ASSET = "remove_asset"
    REMOVE_EMBEDDED_PAYLOAD = "remove_embedded_payload"
    MODIFY_MANIFEST = "modify_manifest"
    MODIFY_CONFIGURATION = "modify_configuration"
    DEX_MODIFICATION = "dex_modification"
    NATIVE_MODIFICATION = "native_modification"
    EXTERNAL_TOOL_PATCH = "external_tool_patch"


class ModificationRisk(StrEnum):
    """Estimated risk level of applying a modification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Reversibility(StrEnum):
    """Degree of reversibility for a planned change."""

    REVERSIBLE = "reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    NOT_REVERSIBLE = "not_reversible"
    UNKNOWN = "unknown"


class ChangeStatus(StrEnum):
    """State of an individual proposed change."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    APPLIED = "applied"
    FAILED = "failed"


class ConflictType(StrEnum):
    """Classification of conflicts between planned changes."""

    TARGET_CONFLICT = "target_conflict"
    OPERATION_CONFLICT = "operation_conflict"
    DEPENDENCY_CONFLICT = "dependency_conflict"
    MUTUALLY_EXCLUSIVE = "mutually_exclusive"


class DependencyType(StrEnum):
    """Type of dependency relationship between planned changes."""

    REQUIRED = "required"
    RECOMMENDED_COMPANION = "recommended_companion"


class ChangeDependency(BaseModel):
    """A structural dependency relationship between two planned changes."""

    change_id: str
    depends_on_id: str
    dependency_type: DependencyType = DependencyType.REQUIRED
    description: str = ""


class ChangeConflict(BaseModel):
    """A structural conflict identified between two planned changes."""

    change_id_a: str
    change_id_b: str
    conflict_type: ConflictType
    reason: str
    resolution_guidance: str = ""


class ImpactAssessment(BaseModel):
    """Detailed impact analysis for a planned change."""

    direct_effects: list[str] = Field(default_factory=list)
    potential_functional_effects: list[str] = Field(default_factory=list)
    potential_side_effects: list[str] = Field(default_factory=list)
    expected_file_changes: list[str] = Field(default_factory=list)
    expected_manifest_changes: list[str] = Field(default_factory=list)
    expected_dex_changes: list[str] = Field(default_factory=list)
    expected_resource_changes: list[str] = Field(default_factory=list)
    expected_native_changes: list[str] = Field(default_factory=list)
    rebuild_required: bool = True
    resign_required: bool = True
    verification_required: bool = True


class PlannedChange(BaseModel):
    """A single, reviewable modification proposed by the planner."""

    id: str
    change_type: ChangeType
    target: str
    operation: str = ""
    reason: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    risk: ModificationRisk = ModificationRisk.MEDIUM
    risk_explanation: str = ""
    impact: ImpactAssessment = Field(default_factory=ImpactAssessment)
    prerequisites: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    reversibility: Reversibility = Reversibility.REVERSIBLE
    reversibility_explanation: str = ""
    validation_steps: list[str] = Field(default_factory=list)
    status: ChangeStatus = ChangeStatus.PROPOSED
    tags: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    backend: str | None = None


class ModificationPlan(BaseModel):
    """A structured, reviewable plan containing proposed changes for an APK."""

    plan_id: str
    source_apk: str
    source_sha256: str
    created_at: str
    planner_version: str = "0.1.0"
    analysis_references: dict[str, str] = Field(default_factory=dict)
    changes: list[PlannedChange] = Field(default_factory=list)
    dependencies: list[ChangeDependency] = Field(default_factory=list)
    conflicts: list[ChangeConflict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status: PlanStatus = PlanStatus.REVIEW_REQUIRED

    @property
    def is_empty(self) -> bool:
        """Return True if the plan contains no proposed changes."""
        return len(self.changes) == 0

    @property
    def change_count(self) -> int:
        """Return total number of proposed changes."""
        return len(self.changes)

    @property
    def has_conflicts(self) -> bool:
        """Return True if any conflicts are detected between changes."""
        return len(self.conflicts) > 0

    def is_stale(self, current_sha256: str) -> bool:
        """Check whether this plan is stale compared to a given APK SHA-256."""
        return self.source_sha256.lower() != current_sha256.lower()

    def mark_stale_if_mismatched(self, current_sha256: str) -> bool:
        """If source hash does not match current APK hash, update status to STALE."""
        if self.is_stale(current_sha256):
            self.status = PlanStatus.STALE
            self.warnings.append(
                f"Plan source SHA-256 ({self.source_sha256[:12]}...) does not match "
                f"current target ({current_sha256[:12]}...). Plan is STALE."
            )
            return True
        return False

    def get_change(self, change_id: str) -> PlannedChange | None:
        """Look up a planned change by its ID."""
        for c in self.changes:
            if c.id == change_id:
                return c
        return None

    def to_serializable_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return self.model_dump(mode="json")
