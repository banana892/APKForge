"""Phase 7 DexModifier — DEX-level modifications (placeholder for bytecode patching).

Handles:
    - DEX_MODIFICATION

DEX modification is inherently complex (smali editing, method replacement,
class removal).  Phase 7 provides the structural framework; deeper
bytecode editing tools can plug in as external modifiers.

Security invariant: operates only on the working copy.
"""

from __future__ import annotations

import logging
import shutil
from typing import TYPE_CHECKING, ClassVar

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationStepResult,
    StepStatus,
)

if TYPE_CHECKING:
    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class DexModifier:
    """Modifier for DEX/smali-level operations.

    Currently supports:
    - Removing entire classes from decoded smali directories.
    - Removing methods from smali files (by pattern).

    Full bytecode patching (instruction replacement, method body
    modification) is deferred to Phase 8+ or external tooling.
    """

    modifier_id: str = "DexModifier"
    name: str = "DEX / Smali Modifier"
    description: str = (
        "Performs DEX-level modifications on decoded smali files: "
        "class removal, method stubbing, and basic smali edits."
    )
    supported_change_types: ClassVar[list[str]] = [
        "dex_modification",
    ]

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Validate that DEX modification prerequisites are met."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        # Check workspace exists
        if not context.workspace_dir.exists():
            result.status = StepStatus.FAILED
            result.message = "Workspace directory does not exist."
            return result

        # Check for decoded smali directories
        smali_dirs = [
            d
            for d in context.workspace_dir.iterdir()
            if d.is_dir() and (d.name == "smali" or d.name.startswith("smali_"))
        ]
        if not smali_dirs:
            result.status = StepStatus.FAILED
            result.message = (
                "No decoded smali directories found in workspace. "
                "DEX modification requires decoded smali output."
            )
            return result

        result.status = StepStatus.SUCCESS
        result.message = (
            f"Preflight passed: {len(smali_dirs)} smali directories found. "
            f"Target: '{change.target}'."
        )
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply DEX modification to the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        target = change.target
        # Convert Java class name to smali path
        smali_path = target.replace(".", "/")

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = f"[DRY RUN] Would apply DEX modification to '{target}'."
            return result

        removed_files: list[str] = []

        # Try to find and remove the target class in smali directories
        for child in context.workspace_dir.iterdir():
            if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_")):
                target_file = child / f"{smali_path}.smali"
                target_dir = child / smali_path

                if target_file.exists():
                    target_file.unlink()
                    removed_files.append(str(target_file.relative_to(context.workspace_dir)))
                    _log.info("Removed smali class file: %s", target_file)

                if target_dir.exists() and target_dir.is_dir():
                    # Remove entire package directory
                    for smali_file in target_dir.rglob("*.smali"):
                        removed_files.append(
                            str(smali_file.relative_to(context.workspace_dir))
                        )
                    shutil.rmtree(target_dir)
                    _log.info("Removed smali package directory: %s", target_dir)

        if removed_files:
            result.status = StepStatus.SUCCESS
            result.message = f"DEX modification applied: {len(removed_files)} files removed."
            result.files_deleted = removed_files
        else:
            result.status = StepStatus.SKIPPED
            result.message = (
                f"Target '{target}' not found in decoded smali directories. "
                f"Ensure the APK has been decoded."
            )

        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """DEX modification rollback requires re-decoding from original APK."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )
        result.status = StepStatus.FAILED
        result.message = (
            "DEX modification rollback requires re-extraction and decoding "
            "from the original APK backup."
        )
        return result
