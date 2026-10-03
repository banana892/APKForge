"""Phase G: Remediation Catalog.

Defines the conservative, auditable initial catalog of supported remediations:
- G-REM-001: Disable Boot Receiver
- G-REM-002: Remove Specific Permission
- G-REM-003: Disable Specific Manifest Component
- G-REM-004: Remove Specific Tracker/SDK Artifact (conditional / guarded)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.modification.models import ModificationRisk
from apkforge.remediation.models import RemediationDefinition, SupportedStatus

if TYPE_CHECKING:
    import builtins

BOOT_RECEIVER_REMEDIATION = RemediationDefinition(
    id="G-REM-001",
    name="Disable Boot Receiver",
    description=(
        "Disables a specified boot receiver by setting android:enabled='false' in the "
        "manifest and removing the RECEIVE_BOOT_COMPLETED uses-permission declaration."
    ),
    target_categories=["persistence", "boot_persistence"],
    target_finding_ids=["SEC-MAL-PERSISTENCE-BOOT", "privacy.persistence.boot_receiver"],
    prerequisites=[
        "Target boot receiver exists and is identified in AndroidManifest.xml",
        "Target receiver android:enabled is true or absent",
        "android.permission.RECEIVE_BOOT_COMPLETED is declared",
    ],
    required_evidence=["receiver_name", "RECEIVE_BOOT_COMPLETED"],
    affected_structures=["AndroidManifest.xml"],
    planned_modifications=[
        "Set android:enabled='false' on the target <receiver>",
        "Remove <uses-permission android:name='android.permission.RECEIVE_BOOT_COMPLETED'>",
    ],
    risk=ModificationRisk.MEDIUM,
    reversible=True,
    verification_requirements=[
        "Rebuilt manifest no longer contains RECEIVE_BOOT_COMPLETED",
        "Rebuilt receiver reports enabled=false in verification diff",
    ],
    compatibility_notes=[
        "Application will not start automatically on device boot; background initialization "
        "dependent on BOOT_COMPLETED will not execute."
    ],
    limitations=[
        "Manifest declaration is disabled, but underlying DEX class bytecode remains in the APK."
    ],
    can_apply_after_approval=True,
    manual_review_required=False,
    status=SupportedStatus.SUPPORTED,
)

REMOVE_PERMISSION_REMEDIATION = RemediationDefinition(
    id="G-REM-002",
    name="Remove Specific Permission",
    description=(
        "Removes an exact <uses-permission> declaration from AndroidManifest.xml. "
        "If static DEX code still references the associated API, post-remediation analysis "
        "truthfully reports the result as PARTIALLY_REMEDIATED."
    ),
    target_categories=[
        "permission",
        "location",
        "contacts",
        "camera",
        "microphone",
        "storage",
        "identifiers",
        "network",
    ],
    target_finding_ids=[
        "privacy.permission.*",
        "privacy.location.permission",
        "privacy.contacts.permission",
        "privacy.camera.permission",
        "privacy.microphone.permission",
    ],
    prerequisites=[
        "Target permission is declared as <uses-permission> in AndroidManifest.xml",
        "Permission identifier is explicitly provided",
    ],
    required_evidence=["permission_name"],
    affected_structures=["AndroidManifest.xml"],
    planned_modifications=[
        "Remove <uses-permission android:name='...'> element from manifest",
    ],
    risk=ModificationRisk.MEDIUM,
    reversible=True,
    verification_requirements=[
        "Rebuilt manifest diff confirms target permission removed",
        "Post-remediation Phase F analysis checks for remaining DEX API references",
    ],
    compatibility_notes=[
        "App may throw java.lang.SecurityException at runtime if it attempts to invoke APIs "
        "guarded by the removed permission without handling permission denial."
    ],
    limitations=[
        "Manifest permission is removed, but DEX bytecode calling the API is not stripped. "
        "If DEX code still references the API, the capability is PARTIALLY_REMEDIATED."
    ],
    can_apply_after_approval=True,
    manual_review_required=False,
    status=SupportedStatus.SUPPORTED,
)

DISABLE_COMPONENT_REMEDIATION = RemediationDefinition(
    id="G-REM-003",
    name="Disable Specific Manifest Component",
    description=(
        "Disables a specific activity, service, receiver, or provider in AndroidManifest.xml "
        "by setting android:enabled='false'."
    ),
    target_categories=["component", "activity", "service", "receiver", "provider"],
    target_finding_ids=["privacy.component.*"],
    prerequisites=[
        "Target component is declared in AndroidManifest.xml",
        "Target component android:enabled is true or absent (not already false)",
    ],
    required_evidence=["component_name", "component_type"],
    affected_structures=["AndroidManifest.xml"],
    planned_modifications=[
        "Set android:enabled='false' on the target component tag",
    ],
    risk=ModificationRisk.MEDIUM,
    reversible=True,
    verification_requirements=[
        "Rebuilt manifest diff confirms component has enabled=false",
    ],
    compatibility_notes=[
        "The component cannot be started, bound, or invoked by intents or other applications.",
    ],
    limitations=[
        "Manifest declaration is disabled, but underlying Java/Kotlin class bytecode remains.",
    ],
    can_apply_after_approval=True,
    manual_review_required=False,
    status=SupportedStatus.SUPPORTED,
)

REMOVE_TRACKER_SDK_REMEDIATION = RemediationDefinition(
    id="G-REM-004",
    name="Remove Specific Tracker/SDK Artifact",
    description=(
        "Conditionally removes an identified third-party tracker/advertising SDK artifact. "
        "Phase G permits this only when class references and assets are completely isolated "
        "without cross-module code dependencies; otherwise reports UNSUPPORTED_REMEDIATION."
    ),
    target_categories=["advertising", "analytics", "tracking", "sdk"],
    target_finding_ids=["privacy.sdk.*"],
    prerequisites=[
        "Target SDK classes and assets are strictly isolated",
        "No application code invokes target SDK classes directly",
    ],
    required_evidence=["sdk_id", "package_signature"],
    affected_structures=["classes.dex", "assets"],
    planned_modifications=[
        "Remove isolated SDK bytecode classes and associated assets",
    ],
    risk=ModificationRisk.HIGH,
    reversible=True,
    verification_requirements=[
        "Rebuilt APK builds and verifies cleanly",
        "Target SDK signatures absent from rebuilt DEX",
    ],
    compatibility_notes=[
        "High risk of NoClassDefFoundError or VerifyError if application code still references "
        "the removed SDK classes.",
    ],
    limitations=[
        "Broad or dependency-crossing tracker removal is not supported in Phase G. "
        "Unchecked removal will be REFUSED or marked UNSUPPORTED_REMEDIATION.",
    ],
    can_apply_after_approval=True,
    manual_review_required=True,
    status=SupportedStatus.CONDITIONAL,
)

BUILTIN_REMEDIATIONS: dict[str, RemediationDefinition] = {
    BOOT_RECEIVER_REMEDIATION.id: BOOT_RECEIVER_REMEDIATION,
    REMOVE_PERMISSION_REMEDIATION.id: REMOVE_PERMISSION_REMEDIATION,
    DISABLE_COMPONENT_REMEDIATION.id: DISABLE_COMPONENT_REMEDIATION,
    REMOVE_TRACKER_SDK_REMEDIATION.id: REMOVE_TRACKER_SDK_REMEDIATION,
}


class RemediationCatalog:
    """Registry and lookup for supported Phase G remediation definitions."""

    def __init__(self, remediations: dict[str, RemediationDefinition] | None = None) -> None:
        self._remediations = dict(remediations or BUILTIN_REMEDIATIONS)

    def get(self, remediation_id: str) -> RemediationDefinition | None:
        return self._remediations.get(remediation_id)

    def list(self) -> builtins.list[RemediationDefinition]:
        return sorted(self._remediations.values(), key=lambda r: r.id)

    def by_category(self, category: str) -> builtins.list[RemediationDefinition]:
        return [
            r for r in self.list() if category.lower() in [c.lower() for c in r.target_categories]
        ]


def default_remediation_catalog() -> RemediationCatalog:
    return RemediationCatalog()
