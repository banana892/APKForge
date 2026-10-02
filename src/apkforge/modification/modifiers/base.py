"""Phase 7 Modification Framework — Base types and Modifier protocol.

Core principle: The original APK file must remain byte-for-byte unchanged.
All modification operations happen inside an isolated workspace on a working
copy.  Only explicitly approved changes may reach ``apply()``.

Design:
    - ``Modifier`` is the interface (Protocol) that every built-in or
      third-party modifier must satisfy.
    - ``ModificationExecutionContext`` carries all runtime state that a
      modifier needs: workspace paths, the approved plan, inspection data,
      and a logger.
    - ``ModificationResult`` / ``ModificationStepResult`` capture the
      outcome of every atomic change.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.inspection.models import InspectionResult
    from apkforge.modification.models import ModificationPlan, PlannedChange

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StepStatus(StrEnum):
    """Outcome status of a modifier step, or of a whole plan execution.

    Step statuses:

    - ``PENDING``: planned, not attempted (e.g. execution stopped at an earlier failure).
    - ``SUCCESS``: executed; the working copy was changed.  Whether the change was
      also *verified* is recorded separately in ``ModificationStepResult.verified``.
    - ``SKIPPED``: not executed; the modifier found nothing to change.  Never a success.
    - ``FAILED``: execution failed (including an exception raised by the modifier).
    - ``VERIFICATION_FAILED``: executed, but the modifier's post-apply verification
      rejected the result.
    - ``DRY_RUN``: simulated; would have been executed.
    - ``ROLLED_BACK``: returned by ``Modifier.rollback`` only.

    Aggregate (``ModificationResult.status``) additionally uses ``PARTIAL``: some
    changes were executed and others were skipped.  See
    :meth:`ModificationResult.aggregate_status`.
    """

    PENDING = "pending"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"
    PARTIAL = "partial"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"


# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------


@dataclass
class ModificationExecutionContext:
    """Runtime context passed to every modifier during execution.

    The context is responsible for workspace isolation.  It copies the
    original APK into a temporary workspace directory and provides the
    modifier with a working copy to operate on.

    Attributes:
        original_apk_path: Absolute path to the original (immutable) APK.
        workspace_dir: The root of the isolated workspace directory.
        working_copy_path: Path to the working copy of the APK inside the
            workspace.  This is the file modifiers operate on.
        plan: The approved ``ModificationPlan`` being executed.
        inspection: Optional inspection result for structural look-ups.
        dry_run: If True, modifiers must simulate but not write changes.
        logger: Logger instance for modifier-level logging.
    """

    original_apk_path: Path
    workspace_dir: Path
    working_copy_path: Path
    plan: ModificationPlan
    inspection: InspectionResult | None = None
    dry_run: bool = False
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("apkforge.modifier"))

    @classmethod
    def create(
        cls,
        apk_path: Path,
        plan: ModificationPlan,
        workspace_dir: Path,
        *,
        inspection: InspectionResult | None = None,
        dry_run: bool = False,
    ) -> ModificationExecutionContext:
        """Factory that sets up workspace isolation.

        1. Creates ``workspace_dir`` if it doesn't exist.
        2. Copies the original APK into the workspace.
        3. Returns a fully initialised context.
        """
        workspace_dir.mkdir(parents=True, exist_ok=True)
        working_copy = workspace_dir / apk_path.name
        if not working_copy.exists():
            shutil.copy2(apk_path, working_copy)
            _log.info("Created working copy: %s", working_copy)
        return cls(
            original_apk_path=apk_path.resolve(),
            workspace_dir=workspace_dir,
            working_copy_path=working_copy,
            plan=plan,
            inspection=inspection,
            dry_run=dry_run,
        )

    def verify_original_untouched(self) -> bool:
        """Verify that the original APK file has not been modified.

        Returns True if the original file still exists and its size is
        unchanged.  A full SHA-256 check can be done externally.
        """
        if not self.original_apk_path.exists():
            _log.error("Original APK no longer exists: %s", self.original_apk_path)
            return False
        return True


# ---------------------------------------------------------------------------
# Result Models
# ---------------------------------------------------------------------------


class ModificationStepResult(BaseModel):
    """Outcome of applying a single PlannedChange via a Modifier."""

    change_id: str = Field(description="ID of the PlannedChange that was applied.")
    modifier_id: str = Field(description="ID of the modifier that executed this step.")
    status: StepStatus = StepStatus.PENDING
    message: str = ""
    details: dict[str, str] = Field(default_factory=dict)
    files_modified: list[str] = Field(default_factory=list)
    files_created: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    rollback_info: dict[str, str] = Field(
        default_factory=dict,
        description="Information needed to roll back this step.",
    )
    verified: bool | None = Field(
        default=None,
        description=(
            "Post-apply verification outcome: True passed, False failed, None not "
            "verified (not executed, dry run, or the modifier has no verify())."
        ),
    )
    rolled_back: bool = Field(
        default=False,
        description="True if this executed step was undone after a later failure.",
    )

    @property
    def executed(self) -> bool:
        """True if the modifier actually changed the working copy for this step."""
        return self.status in (StepStatus.SUCCESS, StepStatus.VERIFICATION_FAILED)


class ModificationResult(BaseModel):
    """Aggregate result of executing an entire ModificationPlan."""

    plan_id: str = Field(description="ID of the plan that was executed.")
    status: StepStatus = StepStatus.PENDING
    dry_run: bool = False
    planned_steps: int = Field(
        default=0, description="Number of accepted changes the run set out to apply."
    )
    steps: list[ModificationStepResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    working_copy_path: str | None = None
    original_apk_path: str | None = None

    def _count(self, *statuses: StepStatus) -> int:
        return sum(1 for s in self.steps if s.status in statuses)

    @property
    def total_steps(self) -> int:
        """Total number of steps in this result."""
        return len(self.steps)

    @property
    def successful_steps(self) -> int:
        """Number of steps executed successfully (status SUCCESS)."""
        return self._count(StepStatus.SUCCESS)

    @property
    def executed_steps(self) -> int:
        """Number of steps that changed the working copy (SUCCESS or VERIFICATION_FAILED)."""
        return sum(1 for s in self.steps if s.executed)

    @property
    def verified_steps(self) -> int:
        """Number of steps whose post-apply verification passed."""
        return sum(1 for s in self.steps if s.verified is True)

    @property
    def failed_steps(self) -> int:
        """Number of steps that failed, in execution or in verification."""
        return self._count(StepStatus.FAILED, StepStatus.VERIFICATION_FAILED)

    @property
    def verification_failed_steps(self) -> int:
        """Number of steps executed but rejected by post-apply verification."""
        return self._count(StepStatus.VERIFICATION_FAILED)

    @property
    def skipped_steps(self) -> int:
        """Number of steps that were skipped (not executed)."""
        return self._count(StepStatus.SKIPPED)

    @property
    def not_attempted_steps(self) -> int:
        """Number of planned steps never attempted (execution stopped earlier)."""
        return self._count(StepStatus.PENDING)

    @property
    def rolled_back_steps(self) -> int:
        """Number of executed steps undone after a later failure."""
        return sum(1 for s in self.steps if s.rolled_back)

    @property
    def all_succeeded(self) -> bool:
        """True if there is at least one step and every step was executed (or, in a
        dry run, simulated) successfully.  A skipped step is not a success."""
        return bool(self.steps) and all(
            s.status in (StepStatus.SUCCESS, StepStatus.DRY_RUN) and s.verified is not False
            for s in self.steps
        )

    def aggregate_status(self) -> StepStatus:
        """Derive the overall status from the step results.

        - ``FAILED``: any step failed, failed verification or was rolled back, or
          any planned step was never attempted.
        - ``SKIPPED``: nothing was executed (no steps, or every step skipped).
        - ``PARTIAL``: some steps executed (or simulated), others skipped.
        - ``SUCCESS`` / ``DRY_RUN``: every step executed (or simulated) successfully.
        """
        if any(
            s.status in (StepStatus.FAILED, StepStatus.VERIFICATION_FAILED, StepStatus.PENDING)
            or s.rolled_back
            or s.verified is False
            for s in self.steps
        ):
            return StepStatus.FAILED
        done = self._count(StepStatus.SUCCESS, StepStatus.DRY_RUN)
        if done == 0:
            return StepStatus.SKIPPED
        if done < len(self.steps):
            return StepStatus.PARTIAL
        return StepStatus.DRY_RUN if self.dry_run else StepStatus.SUCCESS


# ---------------------------------------------------------------------------
# Modifier Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Modifier(Protocol):
    """Protocol that every modifier must implement.

    A Modifier knows how to take a single ``PlannedChange`` and apply it
    to the working copy inside the execution context.

    Attributes:
        modifier_id: Stable, unique identifier (e.g. ``ManifestModifier``).
        name: Human-readable name.
        description: Brief description of what this modifier does.
        supported_change_types: The set of ``ChangeType`` values this
            modifier can handle.
    """

    modifier_id: str
    name: str
    description: str
    supported_change_types: list[str]

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Validate that a change *can* be applied without actually doing it.

        Returns a ``ModificationStepResult`` with status ``SUCCESS`` if the
        change can be applied, or ``FAILED`` with details if not.
        """
        ...

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Apply a single ``PlannedChange`` to the working copy.

        If ``context.dry_run`` is True, simulate the change and return
        status ``DRY_RUN`` instead of ``SUCCESS``.

        Must never touch ``context.original_apk_path``.
        """
        ...

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Attempt to roll back a previously applied change.

        Returns a result with status ``ROLLED_BACK`` on success or
        ``FAILED`` if rollback was not possible.
        """
        ...

    # Optional: a modifier may also define
    #
    #     def verify(self, change, context, step_result) -> ModificationStepResult
    #
    # which the framework calls after a successful (non-dry-run) apply.  It returns
    # status ``SUCCESS`` if the working copy now reflects the change, ``FAILED``
    # otherwise.  It is not part of the Protocol so that existing modifiers still
    # satisfy ``isinstance(m, Modifier)``; without it a step stays ``verified=None``.
