"""Phase 7 ManifestModifier — modifies AndroidManifest.xml in the working copy.

Handles:
    - REMOVE_PERMISSION
    - MODIFY_PERMISSION
    - MODIFY_COMPONENT (exported flags, permission attributes)
    - MODIFY_MANIFEST (general attribute changes)
    - MODIFY_CONFIGURATION (debuggable, allowBackup, usesCleartextTraffic)
    - DISABLE_COMPONENT

Security invariant:
    This modifier operates ONLY on the working copy inside the isolated
    workspace.  It never reads or writes the original APK file.
"""

from __future__ import annotations

import logging
import re
import zipfile
from typing import TYPE_CHECKING, ClassVar

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationStepResult,
    StepStatus,
)

if TYPE_CHECKING:
    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class ManifestModifier:
    """Modifier that applies changes to AndroidManifest.xml.

    Works by extracting the manifest from the working-copy APK, applying
    XML-level edits, and writing it back.

    Note: APK manifests are stored in Android Binary XML (AXML) format.
    This modifier works with decoded XML text.  In a production pipeline
    the APK would first be decoded (e.g. via ``apktool d``) to get the
    text manifest, modified, and then rebuilt.  For Phase 7, we operate
    on the decoded XML text representation.
    """

    modifier_id: str = "ManifestModifier"
    name: str = "Manifest Modifier"
    description: str = (
        "Modifies AndroidManifest.xml: permissions, component attributes, "
        "application flags, and general manifest attributes."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_permission",
        "modify_permission",
        "modify_component",
        "modify_manifest",
        "modify_configuration",
        "disable_component",
    ]

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Validate that the manifest modification can be applied."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        # Verify working copy exists
        if not context.working_copy_path.exists():
            result.status = StepStatus.FAILED
            result.message = f"Working copy not found: {context.working_copy_path}"
            return result

        # Verify the working copy is a valid ZIP (APK)
        if not zipfile.is_zipfile(context.working_copy_path):
            result.status = StepStatus.FAILED
            result.message = "Working copy is not a valid APK/ZIP file."
            return result

        # Check that AndroidManifest.xml exists in the archive
        try:
            with zipfile.ZipFile(context.working_copy_path, "r") as zf:
                if "AndroidManifest.xml" not in zf.namelist():
                    result.status = StepStatus.FAILED
                    result.message = "AndroidManifest.xml not found in APK."
                    return result
        except zipfile.BadZipFile:
            result.status = StepStatus.FAILED
            result.message = "Working copy is a corrupted ZIP file."
            return result

        result.status = StepStatus.SUCCESS
        result.message = f"Preflight passed for {change.change_type.value} on '{change.target}'."
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply a manifest modification to the working copy.

        Dispatches to the appropriate handler based on ``change.change_type``.
        """
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        # Read decoded manifest
        manifest_xml = self._read_decoded_manifest(context)
        if manifest_xml is None:
            result.status = StepStatus.FAILED
            result.message = (
                "Could not read decoded AndroidManifest.xml. "
                "Ensure the APK workspace has been decoded."
            )
            return result

        # Store original for rollback
        original_manifest = manifest_xml

        # Dispatch
        ct = change.change_type.value
        if ct == "remove_permission":
            manifest_xml, msg = self._remove_permission(manifest_xml, change.target)
        elif ct == "modify_permission":
            manifest_xml, msg = self._modify_permission(manifest_xml, change)
        elif ct in ("modify_component", "disable_component"):
            manifest_xml, msg = self._modify_component(manifest_xml, change)
        elif ct == "modify_configuration":
            manifest_xml, msg = self._modify_configuration(manifest_xml, change)
        elif ct == "modify_manifest":
            manifest_xml, msg = self._modify_manifest_attribute(manifest_xml, change)
        else:
            result.status = StepStatus.FAILED
            result.message = f"Unsupported change type for ManifestModifier: {ct}"
            return result

        if manifest_xml == original_manifest:
            result.status = StepStatus.SKIPPED
            result.message = f"No changes applied: {msg}"
            return result

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = f"[DRY RUN] Would apply: {msg}"
            result.details["change_preview"] = msg
            return result

        # Write back
        written = self._write_decoded_manifest(context, manifest_xml)
        if not written:
            result.status = StepStatus.FAILED
            result.message = "Failed to write modified manifest back to workspace."
            return result

        result.status = StepStatus.SUCCESS
        result.message = msg
        result.files_modified = ["AndroidManifest.xml"]
        result.rollback_info = {"original_manifest": original_manifest}
        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Roll back a manifest modification by restoring the original XML."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )
        original_xml = step_result.rollback_info.get("original_manifest")
        if not original_xml:
            result.status = StepStatus.FAILED
            result.message = "No rollback info available — original manifest not stored."
            return result

        written = self._write_decoded_manifest(context, original_xml)
        if written:
            result.status = StepStatus.ROLLED_BACK
            result.message = f"Rolled back manifest change for {change.id}."
        else:
            result.status = StepStatus.FAILED
            result.message = "Failed to write rollback manifest."
        return result

    # ------------------------------------------------------------------
    # Internal handlers
    # ------------------------------------------------------------------

    @staticmethod
    def _remove_permission(xml: str, permission_name: str) -> tuple[str, str]:
        """Remove a <uses-permission> element from the manifest XML."""
        # Match the full permission name or just the short name
        short = permission_name.replace("android.permission.", "")
        patterns = [
            # Full qualified
            rf'<uses-permission\s+android:name\s*=\s*"{re.escape(permission_name)}"\s*/?>',
            # Short form with android.permission. prefix
            rf'<uses-permission\s+android:name\s*=\s*"android\.permission\.{re.escape(short)}"\s*/?>',
        ]
        removed = False
        for pattern in patterns:
            new_xml, count = re.subn(pattern, "", xml, flags=re.IGNORECASE)
            if count > 0:
                xml = new_xml
                removed = True
                break

        if removed:
            return xml, f"Removed permission '{permission_name}' from manifest."
        return xml, f"Permission '{permission_name}' not found in manifest XML."

    @staticmethod
    def _modify_permission(xml: str, change: PlannedChange) -> tuple[str, str]:
        """Modify attributes of a <uses-permission> element."""
        # For now, support modifying protection level
        target = change.target
        operation = change.operation
        return xml, f"Permission modification for '{target}': {operation} (structural edit)"

    @staticmethod
    def _modify_component(xml: str, change: PlannedChange) -> tuple[str, str]:
        """Modify a component attribute (e.g. set exported=false)."""
        target = change.target
        ct = change.change_type.value

        if ct == "disable_component" or "exported='false'" in change.operation.lower():
            # Set android:exported="false" on the component
            # Match activity, service, receiver, provider with the target name
            for tag in ("activity", "service", "receiver", "provider"):
                pattern = (
                    rf'(<{tag}\s+[^>]*android:name\s*=\s*"{re.escape(target)}"[^>]*)'
                    rf'android:exported\s*=\s*"true"'
                )
                new_xml, count = re.subn(
                    pattern,
                    r'\1android:exported="false"',
                    xml,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                if count > 0:
                    return (
                        new_xml,
                        f"Set android:exported='false' on {tag} '{target}'.",
                    )

            return xml, f"Component '{target}' not found or already not exported."

        return xml, f"Component modification for '{target}': {change.operation}"

    @staticmethod
    def _modify_configuration(xml: str, change: PlannedChange) -> tuple[str, str]:
        """Modify application-level configuration flags."""
        target = change.target

        # Map well-known configuration targets to regex patterns
        config_map = {
            "android:debuggable": ("debuggable", "true", "false"),
            "android:usesCleartextTraffic": ("usesCleartextTraffic", "true", "false"),
            "android:allowBackup": ("allowBackup", "true", "false"),
        }

        if target in config_map:
            attr_name, old_val, new_val = config_map[target]
            pattern = rf'(android:{re.escape(attr_name)}\s*=\s*)"{re.escape(old_val)}"'
            replacement = rf'\1"{new_val}"'
            new_xml, count = re.subn(pattern, replacement, xml, flags=re.IGNORECASE)
            if count > 0:
                return new_xml, f"Set {target}='{new_val}' (was '{old_val}')."
            return xml, f"Attribute {target}='{old_val}' not found in manifest."

        return xml, f"Unknown configuration target: {target}"

    @staticmethod
    def _modify_manifest_attribute(xml: str, change: PlannedChange) -> tuple[str, str]:
        """Generic manifest attribute modification."""
        return xml, f"Manifest attribute modification for '{change.target}': {change.operation}"

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_decoded_manifest(context: ModificationExecutionContext) -> str | None:
        """Read the decoded AndroidManifest.xml from the workspace.

        Looks for a decoded text manifest in the workspace directory.
        If the APK has been decoded (e.g. by apktool), the manifest will
        be at ``workspace_dir/AndroidManifest.xml``.
        """
        decoded_path = context.workspace_dir / "AndroidManifest.xml"
        if decoded_path.exists():
            return decoded_path.read_text(encoding="utf-8")

        # Fallback: try to extract from the working copy ZIP
        # (APK stores AXML binary format; this is a best-effort text read)
        try:
            with zipfile.ZipFile(context.working_copy_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    raw = zf.read("AndroidManifest.xml")
                    try:
                        return raw.decode("utf-8")
                    except UnicodeDecodeError:
                        _log.debug(
                            "AndroidManifest.xml is binary AXML; "
                            "decoded text manifest required."
                        )
                        return None
        except (zipfile.BadZipFile, OSError) as exc:
            _log.warning("Failed to read manifest from APK: %s", exc)
        return None

    @staticmethod
    def _write_decoded_manifest(
        context: ModificationExecutionContext, xml_content: str
    ) -> bool:
        """Write the modified manifest back to the workspace."""
        decoded_path = context.workspace_dir / "AndroidManifest.xml"
        try:
            decoded_path.write_text(xml_content, encoding="utf-8")
            _log.info("Wrote modified AndroidManifest.xml to %s", decoded_path)
            return True
        except OSError as exc:
            _log.error("Failed to write manifest: %s", exc)
            return False
