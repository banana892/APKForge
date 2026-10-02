"""Phase 7 Modification Framework — the orchestrator.

This is the central engine that:
1. Accepts an approved ModificationPlan.
2. Validates that the plan is approved and not stale.
3. Creates an isolated workspace with a working copy.
4. Runs preflight checks for all approved changes.
5. Applies changes in dependency order via the ModifierRegistry, and runs a
   modifier's optional ``verify()`` after each applied change.
6. Reports results.  The overall status is derived from the step results by
   ``ModificationResult.aggregate_status()``: a skipped change is never a success.

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
    from apkforge.modification.modifiers.base import Modifier

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
                does not produce an output (debugging).  A SUCCESS or PARTIAL run
                always keeps it: the working copy, with the executed changes, is the
                run's output.  FAILED, SKIPPED and DRY_RUN runs produce none.

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
            # Nothing executed: complete, but not a successful modification.
            result.status = StepStatus.SKIPPED
            result.warnings.append("No accepted changes in the plan; nothing to apply.")
            return result
        result.planned_steps = len(accepted_changes)

        # 5. Create isolated workspace
        created_ws = workspace_dir is None
        ws_dir = workspace_dir or self._create_workspace_dir(apk_path)
        try:
            self._execute_in_workspace(
                plan, apk_path, accepted_changes, ws_dir, inspection, dry_run, result
            )
            # Original-APK integrity: full SHA-256, not just existence.
            if self._compute_sha256(apk_path) != current_sha:
                result.errors.append("CRITICAL: Original APK was modified during execution!")
                result.status = StepStatus.FAILED
        finally:
            if (
                created_ws
                and not keep_workspace
                and result.status not in (StepStatus.SUCCESS, StepStatus.PARTIAL)
            ):
                # Without executed changes (failed, skipped, dry run or interrupted
                # run) the working copy is not an output.
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

        # 7. Apply (and verify) changes in order
        applied_steps: list[tuple[PlannedChange, ModificationStepResult]] = []
        for index, change in enumerate(accepted_changes):
            modifier = self._registry.get_modifier(change.change_type.value)
            if modifier is None:
                # Unreachable after preflight; a missing modifier is a failure, not a skip.
                step = ModificationStepResult(
                    change_id=change.id,
                    modifier_id="unknown",
                    status=StepStatus.FAILED,
                    message="No modifier available.",
                )
            else:
                step = self._apply_and_verify(modifier, change, context)

            result.steps.append(step)
            applied_steps.append((change, step))

            if step.status in (StepStatus.FAILED, StepStatus.VERIFICATION_FAILED):
                result.errors.append(
                    f"Change {change.id} {step.status.value}: {step.message}. "
                    f"Stopping execution."
                )
                # Roll back executed changes, including one that failed verification.
                to_undo = applied_steps if step.executed else applied_steps[:-1]
                self._rollback_applied(to_undo, context, result)
                for skipped_change in accepted_changes[index + 1 :]:
                    result.steps.append(
                        ModificationStepResult(
                            change_id=skipped_change.id,
                            modifier_id=self._modifier_id_for(skipped_change),
                            status=StepStatus.PENDING,
                            message=f"Not attempted: execution stopped at {change.id}.",
                        )
                    )
                break

        # 8. Final safety check
        if context.verify_original_untouched():
            _log.info("Safety check passed: original APK is untouched.")
        else:
            result.errors.append("CRITICAL: Original APK may have been modified!")
            result.status = StepStatus.FAILED

        # Overall status, derived from the steps (a skipped step is not a success).
        if result.status != StepStatus.FAILED:
            result.status = result.aggregate_status()
        if result.status == StepStatus.SKIPPED:
            result.warnings.append("No change was executed: every step was skipped.")
        elif result.status == StepStatus.PARTIAL:
            result.warnings.append(
                f"{result.skipped_steps} of {result.total_steps} change(s) were skipped "
                f"(not executed)."
            )

        _log.info(
            "Plan %s execution complete: status=%s, %d/%d executed, %d skipped, "
            "%d failed, %d verified.",
            plan.plan_id,
            result.status.value,
            result.executed_steps,
            result.planned_steps,
            result.skipped_steps,
            result.failed_steps,
            result.verified_steps,
        )

    def _modifier_id_for(self, change: PlannedChange) -> str:
        modifier = self._registry.get_modifier(change.change_type.value)
        return getattr(modifier, "modifier_id", "unknown") if modifier else "unknown"

    @staticmethod
    def _apply_and_verify(
        modifier: Modifier,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply one change; if it was executed, run the modifier's optional verify()."""
        modifier_id = getattr(modifier, "modifier_id", "unknown")
        try:
            step = modifier.apply(change, context)
        except Exception as exc:
            return ModificationStepResult(
                change_id=change.id,
                modifier_id=modifier_id,
                status=StepStatus.FAILED,
                message=f"Apply exception: {type(exc).__name__}: {exc}",
                details={"exception_type": type(exc).__name__, "exception": str(exc)},
            )

        verify = getattr(modifier, "verify", None)
        if step.status != StepStatus.SUCCESS or context.dry_run or not callable(verify):
            return step

        try:
            check = verify(change, context, step)
            passed = check.status == StepStatus.SUCCESS
            detail = check.message
        except Exception as exc:
            passed = False
            detail = f"Verify exception: {type(exc).__name__}: {exc}"
            step.details["exception_type"] = type(exc).__name__
        step.verified = passed
        if not passed:
            step.status = StepStatus.VERIFICATION_FAILED
            step.message = f"{step.message} | verification failed: {detail}"
        return step

    def _rollback_applied(
        self,
        applied_steps: list[tuple[PlannedChange, ModificationStepResult]],
        context: ModificationExecutionContext,
        result: ModificationResult,
    ) -> None:
        """Attempt to roll back previously applied changes in reverse order."""
        for change, step in reversed(applied_steps):
            if not step.executed:
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
                    step.rolled_back = True
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
