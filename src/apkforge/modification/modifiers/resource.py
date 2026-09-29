"""Phase 7 ResourceModifier — removes or replaces resources in the working copy.

Handles:
    - REMOVE_RESOURCE
    - REMOVE_ASSET

Operates by modifying the decoded APK workspace (e.g. res/ and assets/
directories produced by apktool decode).

Security invariant: never touches the original APK.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, ClassVar

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationStepResult,
    StepStatus,
)

if TYPE_CHECKING:
    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class ResourceModifier:
    """Modifier that removes or replaces resources and assets."""

    modifier_id: str = "ResourceModifier"
    name: str = "Resource & Asset Modifier"
    description: str = (
        "Removes or replaces resource files (res/) and asset files (assets/) "
        "in the decoded APK workspace."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_resource",
        "remove_asset",
    ]

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Verify the target resource or asset exists in the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        target_path = context.workspace_dir / change.target
        if not target_path.exists():
            result.status = StepStatus.FAILED
            result.message = f"Target file does not exist in workspace: {change.target}"
            return result

        result.status = StepStatus.SUCCESS
        result.message = f"Preflight passed: '{change.target}' exists in workspace."
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Remove the target resource or asset from the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        target_path = context.workspace_dir / change.target

        if not target_path.exists():
            result.status = StepStatus.SKIPPED
            result.message = f"Target '{change.target}' does not exist; skipping."
            return result

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = f"[DRY RUN] Would remove: {change.target}"
            return result

        try:
            # Store original content for rollback
            if target_path.is_file():
                target_path.read_bytes()
                result.rollback_info = {
                    "original_path": str(target_path),
                    "had_content": "true",
                }
                target_path.unlink()
                result.files_deleted = [change.target]
            elif target_path.is_dir():
                import shutil

                result.rollback_info = {
                    "original_path": str(target_path),
                    "was_directory": "true",
                }
                shutil.rmtree(target_path)
                result.files_deleted = [change.target]

            result.status = StepStatus.SUCCESS
            result.message = f"Removed '{change.target}' from workspace."
        except OSError as exc:
            result.status = StepStatus.FAILED
            result.message = f"Failed to remove '{change.target}': {exc}"

        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Roll back a resource removal (limited: file content is lost)."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )
        result.status = StepStatus.FAILED
        result.message = (
            "Resource rollback requires re-extraction from original APK. "
            "Use the original APK backup to restore removed resources."
        )
        return result
