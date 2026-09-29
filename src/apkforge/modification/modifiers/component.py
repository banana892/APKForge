"""Phase 7 ComponentModifier — disables or removes APK components.

Handles:
    - REMOVE_COMPONENT
    - DISABLE_COMPONENT

Disabling a component means setting ``android:enabled="false"`` and/or
``android:exported="false"`` in the manifest.  Removing a component
removes it from the manifest and optionally removes its smali class.

Security invariant: operates only on the working copy.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, ClassVar

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationStepResult,
    StepStatus,
)
from apkforge.modification.modifiers.manifest import ManifestModifier

if TYPE_CHECKING:
    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class ComponentModifier:
    """Modifier that disables or removes Android components."""

    modifier_id: str = "ComponentModifier"
    name: str = "Component Modifier"
    description: str = (
        "Disables or removes Activities, Services, BroadcastReceivers, "
        "and ContentProviders from AndroidManifest.xml."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_component",
        "disable_component",
    ]

    def __init__(self) -> None:
        self._manifest_modifier = ManifestModifier()

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Verify the component exists in the manifest."""
        base_result = self._manifest_modifier.preflight(change, context)
        if base_result.status != StepStatus.SUCCESS:
            base_result.modifier_id = self.modifier_id
            return base_result

        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
            status=StepStatus.SUCCESS,
            message=f"Component preflight passed for '{change.target}'.",
        )
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply component modification."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        manifest_xml = self._manifest_modifier._read_decoded_manifest(context)
        if manifest_xml is None:
            result.status = StepStatus.FAILED
            result.message = "Could not read decoded AndroidManifest.xml."
            return result

        original_xml = manifest_xml
        ct = change.change_type.value

        if ct == "disable_component":
            manifest_xml, msg = self._disable_component(manifest_xml, change.target)
        elif ct == "remove_component":
            manifest_xml, msg = self._remove_component(manifest_xml, change.target)
        else:
            result.status = StepStatus.FAILED
            result.message = f"Unsupported change type: {ct}"
            return result

        if manifest_xml == original_xml:
            result.status = StepStatus.SKIPPED
            result.message = f"No changes applied: {msg}"
            return result

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = f"[DRY RUN] Would apply: {msg}"
            return result

        written = self._manifest_modifier._write_decoded_manifest(context, manifest_xml)
        if not written:
            result.status = StepStatus.FAILED
            result.message = "Failed to write modified manifest."
            return result

        result.status = StepStatus.SUCCESS
        result.message = msg
        result.files_modified = ["AndroidManifest.xml"]
        result.rollback_info = {"original_manifest": original_xml}
        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Roll back component modification."""
        result = self._manifest_modifier.rollback(change, context, step_result)
        result.modifier_id = self.modifier_id
        return result

    # ------------------------------------------------------------------
    # Internal handlers
    # ------------------------------------------------------------------

    @staticmethod
    def _disable_component(xml: str, component_name: str) -> tuple[str, str]:
        """Set android:enabled="false" on a component."""
        for tag in ("activity", "service", "receiver", "provider"):
            # Find the component and add/set enabled="false"
            pattern = (
                rf'(<{tag}\s+[^>]*android:name\s*=\s*"{re.escape(component_name)}"[^>]*)'
                rf'android:enabled\s*=\s*"true"'
            )
            new_xml, count = re.subn(
                pattern,
                r'\1android:enabled="false"',
                xml,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if count > 0:
                return new_xml, f"Disabled component '{component_name}' (enabled=false)."

            # If no android:enabled attribute exists, add it
            pattern2 = (
                rf'(<{tag}\s+)(android:name\s*=\s*"{re.escape(component_name)}")'
            )
            new_xml, count = re.subn(
                pattern2,
                r'\1android:enabled="false" \2',
                xml,
                flags=re.IGNORECASE,
            )
            if count > 0:
                return new_xml, f"Disabled component '{component_name}' (added enabled=false)."

        return xml, f"Component '{component_name}' not found in manifest."

    @staticmethod
    def _remove_component(xml: str, component_name: str) -> tuple[str, str]:
        """Remove a component element entirely from the manifest."""
        for tag in ("activity", "service", "receiver", "provider"):
            # Match self-closing or paired tags
            pattern = (
                rf'<{tag}\s+[^>]*android:name\s*=\s*"{re.escape(component_name)}"'
                rf'[^>]*/>'
            )
            new_xml, count = re.subn(pattern, "", xml, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                return new_xml, f"Removed {tag} '{component_name}' from manifest."

            # Try paired tags (with inner intent-filters etc.)
            pattern2 = (
                rf'<{tag}\s+[^>]*android:name\s*=\s*"{re.escape(component_name)}"'
                rf'[^>]*>.*?</{tag}>'
            )
            new_xml, count = re.subn(pattern2, "", xml, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                return new_xml, f"Removed {tag} '{component_name}' from manifest."

        return xml, f"Component '{component_name}' not found in manifest."
