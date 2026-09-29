"""Phase 7 PayloadModifier — removes embedded executable payloads.

Handles:
    - REMOVE_EMBEDDED_PAYLOAD

Removes files identified by the security engine as suspicious embedded
executables (standalone ELF binaries, nested APKs, etc.).

Security invariant: operates only on the working copy.
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


class PayloadModifier:
    """Modifier that removes embedded executable payloads from the workspace."""

    modifier_id: str = "PayloadModifier"
    name: str = "Embedded Payload Remover"
    description: str = (
        "Removes suspicious embedded executable files (ELF binaries, nested APKs) "
        "identified by security analysis."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_embedded_payload",
    ]

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Verify the target payload file exists in the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        target_path = context.workspace_dir / change.target
        if not target_path.exists():
            result.status = StepStatus.FAILED
            result.message = (
                f"Payload file not found in workspace: {change.target}"
            )
            return result

        result.status = StepStatus.SUCCESS
        result.message = f"Preflight passed: payload '{change.target}' exists in workspace."
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Remove the embedded payload file from the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        target_path = context.workspace_dir / change.target

        if not target_path.exists():
            result.status = StepStatus.SKIPPED
            result.message = f"Payload '{change.target}' does not exist; skipping."
            return result

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = f"[DRY RUN] Would remove payload: {change.target}"
            return result

        try:
            file_size = target_path.stat().st_size
            target_path.unlink()
            result.status = StepStatus.SUCCESS
            result.message = (
                f"Removed embedded payload '{change.target}' ({file_size} bytes)."
            )
            result.files_deleted = [change.target]
            result.rollback_info = {
                "original_path": str(target_path),
                "original_size": str(file_size),
            }
        except OSError as exc:
            result.status = StepStatus.FAILED
            result.message = f"Failed to remove payload '{change.target}': {exc}"

        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Payload removal rollback requires re-extraction from original APK."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )
        result.status = StepStatus.FAILED
        result.message = (
            "Payload removal rollback requires re-extraction from the "
            "original APK backup."
        )
        return result
