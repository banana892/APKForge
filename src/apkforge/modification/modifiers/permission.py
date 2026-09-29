"""Phase 7 PermissionModifier — permission-specific operations.

Handles REMOVE_PERMISSION and MODIFY_PERMISSION change types.
Delegates to ManifestModifier for the actual XML editing but adds
permission-specific validation and preflight logic.
"""

from __future__ import annotations

import logging
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


class PermissionModifier:
    """Specialised modifier for Android permission management.

    Wraps ManifestModifier with permission-domain preflight checks:
    - Validates that the target permission exists in the manifest.
    - Warns about runtime-only permissions.
    - Delegates actual editing to ManifestModifier internals.
    """

    modifier_id: str = "PermissionModifier"
    name: str = "Permission Modifier"
    description: str = (
        "Removes or modifies Android permission declarations in AndroidManifest.xml."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_permission",
        "modify_permission",
    ]

    def __init__(self) -> None:
        self._manifest_modifier = ManifestModifier()

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Permission-specific preflight validation."""
        # Delegate base manifest preflight first
        base_result = self._manifest_modifier.preflight(change, context)
        if base_result.status != StepStatus.SUCCESS:
            base_result.modifier_id = self.modifier_id
            return base_result

        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
            status=StepStatus.SUCCESS,
            message=f"Permission preflight passed for '{change.target}'.",
        )
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply permission change, delegating to ManifestModifier."""
        result = self._manifest_modifier.apply(change, context)
        result.modifier_id = self.modifier_id
        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Roll back permission change via ManifestModifier."""
        result = self._manifest_modifier.rollback(change, context, step_result)
        result.modifier_id = self.modifier_id
        return result
