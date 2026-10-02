"""Phase 7 Modification Framework — the orchestrator.

This is the central engine that:
1. Accepts an approved ModificationPlan.
2. Validates that the plan is approved and not stale.
3. Creates an isolated workspace with a working copy.
4. Runs preflight checks for all approved changes.
5. Applies changes in dependency order via the ModifierRegistry.
6. Reports results.

Core invariants:
- The original APK is never modified.
- Only explicitly approved changes are applied.
- All operations happen inside an isolated workspace.
- Dry-run mode simulates everything without writing.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationResult,
    ModificationStepResult,
    StepStatus,
)
from apkforge.modification.modifiers.component import ComponentModifier
from apkforge.modification.modifiers.dex import DexModifier
from apkforge.modification.modifiers.manifest import ManifestModifier
from apkforge.modification.modifiers.payload import PayloadModifier
from apkforge.modification.modifiers.permission import PermissionModifier
from apkforge.modification.modifiers.registry import ModifierRegistry
from apkforge.modification.modifiers.resource import ResourceModifier
from apkforge.modification.modifiers.tracker import TrackerModifier

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.modification.models import ModificationPlan, PlannedChange

_log = logging.getLogger(__name__)


class ModificationFramework:
    """Orchestrates approved modification plan execution.

    Usage::

        framework = ModificationFramework()
        result = framework.execute(
            plan=approved_plan,
            apk_path=Path("target.apk"),
        )
    """

    def __init__(
        self,
        registry: ModifierRegistry | None = None,
        workspace_base: Path | None = None,
    ) -> None:
        self._registry = registry or self._create_default_registry()
        self._workspace_base = workspace_base

    @staticmethod
    def _create_default_registry() -> ModifierRegistry:
        """Create registry pre-populated with all built-in modifiers."""
        registry = ModifierRegistry()
        registry.register(ManifestModifier())
        registry.register(PermissionModifier())
        registry.register(ResourceModifier())
        registry.register(TrackerModifier())
        registry.register(DexModifier())
        registry.register(ComponentModifier())
        registry.register(PayloadModifier())
        return registry

    @property
    def registry(self) -> ModifierRegistry:
        """Access the modifier registry."""
        return self._registry

    def execute(
        self,
        plan: ModificationPlan,
        apk_path: Path,
        *,
        inspection: InspectionResult | None = None,
        dry_run: bool = False,
        workspace_dir: Path | None = None,
        keep_workspace: bool = False,
    ) -> ModificationResult:
        """Execute an approved modification plan.

        Args:
            plan: The modification plan (must be APPROVED).
            apk_path: Path to the original APK file.
            inspection: Optional inspection result for structural lookups.
            dry_run: If True, simulate all modifications without writing.
            workspace_dir: Optional custom workspace directory.  A caller-supplied
                directory is never deleted.
            keep_workspace: Keep a framework-created workspace even when the run
                fails (debugging).  A successful run always keeps it: the working
                copy is the run's output.

        Returns:
            ModificationResult with the outcome of each step.

        Raises:
            ValueError: If the plan is not APPROVED.
        """
        result = ModificationResult(
            plan_id=plan.plan_id,
            dry_run=dry_run,
            original_apk_path=str(apk_path),
        )

        # 1. Enforce approval
        from apkforge.modification.models import ChangeStatus, PlanStatus

        if plan.status != PlanStatus.APPROVED:
            result.status = StepStatus.FAILED
            result.errors.append(
                f"Plan status is '{plan.status.value}', not APPROVED. "
                f"Only approved plans may be executed."
            )
            return result

        # 2. Verify APK exists
        apk_path = Path(apk_path).resolve()
        if not apk_path.is_file():
            result.status = StepStatus.FAILED
            result.errors.append(f"APK file not found: {apk_path}")
            return result

        # 3. Staleness check
        current_sha = self._compute_sha256(apk_path)
        if plan.source_sha256.lower() != current_sha.lower():
            result.status = StepStatus.FAILED
            result.errors.append(
                f"Plan is STALE: expected SHA-256 {plan.source_sha256[:16]}... "
                f"but APK has {current_sha[:16]}..."
            )
            return result

        # 4. Filter to accepted/approved changes only
        accepted_changes = [
            c for c in plan.changes if c.status == ChangeStatus.ACCEPTED
        ]
        if not accepted_changes:
            result.status = StepStatus.SUCCESS
            result.warnings.append("No accepted changes in the plan; nothing to apply.")
            return result

        # 5. Create isolated workspace
        created_ws = workspace_dir is None
        ws_dir = workspace_dir or self._create_workspace_dir(apk_path)
        try:
            self._execute_in_workspace(
                plan, apk_path, accepted_changes, ws_dir, inspection, dry_run, result
            )
        finally:
            if created_ws and not keep_workspace and result.status != StepStatus.SUCCESS:
                # A failed (or interrupted) run's working copy is not an output.
                shutil.rmtree(ws_dir, ignore_errors=True)
                result.working_copy_path = None
        return result

    def _execute_in_workspace(
        self,
        plan: ModificationPlan,
        apk_path: Path,
        accepted_changes: list[PlannedChange],
        ws_dir: Path,
        inspection: InspectionResult | None,
        dry_run: bool,
        result: ModificationResult,
    ) -> None:
        """Steps 5-9 of :meth:`execute`: preflight and apply inside *ws_dir*."""
        context = ModificationExecutionContext.create(
            apk_path=apk_path,
            plan=plan,
            workspace_dir=ws_dir,
            inspection=inspection,
            dry_run=dry_run,
        )
        result.working_copy_path = str(context.working_copy_path)

        _log.info(
            "Executing plan %s (%d accepted changes, dry_run=%s)",
            plan.plan_id,
            len(accepted_changes),
            dry_run,
        )

        # 6. Preflight all changes
        preflight_failures: list[ModificationStepResult] = []
        for change in accepted_changes:
            modifier = self._registry.get_modifier(change.change_type.value)
            if modifier is None:
                fail = ModificationStepResult(
                    change_id=change.id,
                    modifier_id="unknown",
                    status=StepStatus.FAILED,
                    message=(
                        f"No modifier registered for change type "
                        f"'{change.change_type.value}'."
                    ),
                )
                preflight_failures.append(fail)
                continue

            try:
                pf_result = modifier.preflight(change, context)
                if pf_result.status == StepStatus.FAILED:
                    preflight_failures.append(pf_result)
            except Exception as exc:
                fail = ModificationStepResult(
                    change_id=change.id,
                    modifier_id=getattr(modifier, "modifier_id", "unknown"),
                    status=StepStatus.FAILED,
                    message=f"Preflight exception: {exc}",
                )
                preflight_failures.append(fail)

        if preflight_failures:
            result.steps.extend(preflight_failures)
            result.status = StepStatus.FAILED
            result.errors.append(
                f"{len(preflight_failures)} preflight check(s) failed. "
                f"No modifications were applied."
            )
            return

        # 7. Apply changes in order
        applied_steps: list[tuple[PlannedChange, ModificationStepResult]] = []
        for change in accepted_changes:
            modifier = self._registry.get_modifier(change.change_type.value)
            if modifier is None:
                step = ModificationStepResult(
                    change_id=change.id,
                    modifier_id="unknown",
                    status=StepStatus.SKIPPED,
                    message="No modifier available.",
                )
                result.steps.append(step)
                continue

            try:
                step = modifier.apply(change, context)
            except Exception as exc:
                step = ModificationStepResult(
                    change_id=change.id,
                    modifier_id=getattr(modifier, "modifier_id", "unknown"),
                    status=StepStatus.FAILED,
                    message=f"Apply exception: {exc}",
                )

            result.steps.append(step)
            applied_steps.append((change, step))

            if step.status == StepStatus.FAILED:
                result.errors.append(
                    f"Change {change.id} failed: {step.message}. "
                    f"Stopping execution."
                )
                # Attempt to roll back previously applied changes
                self._rollback_applied(applied_steps[:-1], context, result)
                result.status = StepStatus.FAILED
                break

        # 8. Final safety check
        if context.verify_original_untouched():
            _log.info("Safety check passed: original APK is untouched.")
        else:
            result.errors.append("CRITICAL: Original APK may have been modified!")
            result.status = StepStatus.FAILED

        # 9. Set overall status
        if result.status != StepStatus.FAILED:
            if result.all_succeeded:
                result.status = StepStatus.DRY_RUN if dry_run else StepStatus.SUCCESS
            else:
                result.status = StepStatus.FAILED

        _log.info(
            "Plan %s execution complete: %d/%d steps succeeded.",
            plan.plan_id,
            result.successful_steps,
            result.total_steps,
        )

    def _rollback_applied(
        self,
        applied_steps: list[tuple[PlannedChange, ModificationStepResult]],
        context: ModificationExecutionContext,
        result: ModificationResult,
    ) -> None:
        """Attempt to roll back previously applied changes in reverse order."""
        for change, step in reversed(applied_steps):
            if step.status not in (StepStatus.SUCCESS, StepStatus.DRY_RUN):
                continue

            modifier = self._registry.get_modifier(change.change_type.value)
            if modifier is None:
                result.warnings.append(
                    f"Cannot rollback {change.id}: no modifier found."
                )
                continue

            try:
                rb_result = modifier.rollback(change, context, step)
                if rb_result.status == StepStatus.ROLLED_BACK:
                    _log.info("Rolled back change %s.", change.id)
                else:
                    result.warnings.append(
                        f"Rollback of {change.id} failed: {rb_result.message}"
                    )
            except Exception as exc:
                result.warnings.append(
                    f"Rollback exception for {change.id}: {exc}"
                )

    def _create_workspace_dir(self, apk_path: Path) -> Path:
        """Create a temporary workspace directory."""
        # Unique per run, so cleaning one run never touches another's workspace.
        base = self._workspace_base
        if base is not None:
            base.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f"apkforge_mod_{apk_path.stem}_", dir=base))

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().lower()
