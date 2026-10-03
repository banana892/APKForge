"""Finding-to-Remediation Mapping layer for Phase G.

Maps Phase F privacy findings and Phase B security findings to candidate
remediation definitions in an auditable, explicit manner. Findings without a safe
remediation candidate yield an empty candidate list, reporting NO_SUPPORTED_REMEDIATION.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.remediation.catalog import (
    BOOT_RECEIVER_REMEDIATION,
    DISABLE_COMPONENT_REMEDIATION,
    REMOVE_PERMISSION_REMEDIATION,
    REMOVE_TRACKER_SDK_REMEDIATION,
    RemediationCatalog,
    default_remediation_catalog,
)
from apkforge.remediation.models import RemediationDefinition  # noqa: TC001 - pydantic field type

if TYPE_CHECKING:
    from apkforge.privacy.models import PrivacyFinding

__all__ = [
    "RemediationCandidate",
    "find_remediations_for_finding",
    "map_finding_to_remediations",
]


class RemediationCandidate(BaseModel):
    """An eligible remediation candidate for a specific finding."""

    remediation: RemediationDefinition
    parameters: dict[str, str] = Field(default_factory=dict)
    rationale: str
    target_summary: str
    is_supported: bool = True
    unsupported_reason: str = ""


def map_finding_to_remediations(
    finding: PrivacyFinding | dict[str, Any],
    catalog: RemediationCatalog | None = None,
) -> list[RemediationCandidate]:
    """Map a finding to eligible remediation candidates."""
    catalog = catalog or default_remediation_catalog()
    candidates: list[RemediationCandidate] = []

    # Normalize fields from PrivacyFinding or dict
    if isinstance(finding, dict):
        fid = finding.get("id", "")
        category = finding.get("category", "")
        title = finding.get("title", "")
        desc = finding.get("description", "")
        perms = finding.get("related_permissions", [])
        component = finding.get("source_component")
        sdks = finding.get("related_sdks", [])
        sdk = sdks[0] if sdks else None
        ev_locs = finding.get("evidence_locations", [])
        ev_vals = finding.get("evidence_values", [])
    else:
        fid = finding.id
        category = finding.category
        title = finding.title
        desc = finding.description
        perms = finding.related_permissions
        component = finding.source_component
        sdks = finding.related_sdks
        sdk = sdks[0] if sdks else None
        ev_locs = finding.evidence_locations
        ev_vals = finding.evidence_values

    lower_title = title.lower()
    lower_desc = desc.lower()

    # 1. Boot Persistence -> G-REM-001
    is_boot_pers = (
        category in ("persistence", "boot_persistence")
        or "boot" in lower_title
        or "boot_completed" in lower_desc
        or fid in ("SEC-MAL-PERSISTENCE-BOOT", "privacy.persistence.boot_receiver")
        or any("BOOT_COMPLETED" in loc for loc in ev_locs)
    )
    if is_boot_pers:
        params: dict[str, str] = {}
        if component:
            params["receiver"] = component
        candidates.append(
            RemediationCandidate(
                remediation=BOOT_RECEIVER_REMEDIATION,
                parameters=params,
                rationale=(
                    "Target finding indicates persistence via boot receiver; "
                    "G-REM-001 disables the boot receiver and removes RECEIVE_BOOT_COMPLETED."
                ),
                target_summary=component or "Discovered Boot Receiver",
                is_supported=True,
            )
        )

    # 2. Permissions -> G-REM-002
    target_perms = list(perms)
    # Also check if finding is directly about a permission
    if not target_perms and (
        category == "permission"
        or fid.startswith("privacy.permission")
        or fid.startswith("unreferenced_permission")
    ):
        for val in ev_vals:
            if "permission" in val:
                target_perms.append(val)
        if not target_perms:
            # Check title
            for part in title.split():
                if part.startswith("android.permission."):
                    target_perms.append(part)

    for perm in set(target_perms):
        candidates.append(
            RemediationCandidate(
                remediation=REMOVE_PERMISSION_REMEDIATION,
                parameters={"permission": perm},
                rationale=(
                    f"Finding references privacy-sensitive permission '{perm}'. "
                    "G-REM-002 removes the manifest declaration."
                ),
                target_summary=f"Permission: {perm}",
                is_supported=True,
            )
        )

    # 3. Explicit Component -> G-REM-003
    if component:
        candidates.append(
            RemediationCandidate(
                remediation=DISABLE_COMPONENT_REMEDIATION,
                parameters={"component": component},
                rationale=(
                    f"Finding identifies component '{component}'. "
                    "G-REM-003 disables the component via android:enabled='false'."
                ),
                target_summary=f"Component: {component}",
                is_supported=True,
            )
        )

    # 4. Third-Party Tracker / SDK -> G-REM-004 (CONDITIONAL / UNSUPPORTED)
    if sdk or category in ("advertising", "analytics", "tracking") or fid.startswith("privacy.sdk"):
        sdk_id = sdk or fid
        candidates.append(
            RemediationCandidate(
                remediation=REMOVE_TRACKER_SDK_REMEDIATION,
                parameters={"sdk_id": sdk_id},
                rationale=(
                    f"Finding identifies SDK '{sdk_id}'. Broad tracker removal is guarded; "
                    "requires isolated classes without dependencies."
                ),
                target_summary=f"SDK Artifact: {sdk_id}",
                is_supported=False,
                unsupported_reason=(
                    "Automated whole-SDK stripping without call-graph refactoring is not supported "
                    "in Phase G to avoid runtime crashes (NoClassDefFoundError)."
                ),
            )
        )

    return candidates


def find_remediations_for_finding(
    finding_id: str,
    findings: list[PrivacyFinding],
    catalog: RemediationCatalog | None = None,
) -> list[RemediationCandidate]:
    """Find remediation candidates for a finding ID from a list of findings."""
    for f in findings:
        if f.id == finding_id:
            return map_finding_to_remediations(f, catalog)
    return []
