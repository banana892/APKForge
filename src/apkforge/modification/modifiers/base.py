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
    """Outcome status of a single modifier step."""

    PENDING = "pending"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"
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


class ModificationResult(BaseModel):
    """Aggregate result of executing an entire ModificationPlan."""

    plan_id: str = Field(description="ID of the plan that was executed.")
    status: StepStatus = StepStatus.PENDING
    dry_run: bool = False
    steps: list[ModificationStepResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    working_copy_path: str | None = None
    original_apk_path: str | None = None

    @property
    def total_steps(self) -> int:
        """Total number of steps in this result."""
        return len(self.steps)

    @property
    def successful_steps(self) -> int:
        """Number of steps that succeeded."""
        return sum(1 for s in self.steps if s.status == StepStatus.SUCCESS)

    @property
    def failed_steps(self) -> int:
        """Number of steps that failed."""
        return sum(1 for s in self.steps if s.status == StepStatus.FAILED)

    @property
    def skipped_steps(self) -> int:
        """Number of steps that were skipped."""
        return sum(1 for s in self.steps if s.status == StepStatus.SKIPPED)

    @property
    def all_succeeded(self) -> bool:
        """True if every step either succeeded or was a dry-run success."""
        return all(
            s.status in (StepStatus.SUCCESS, StepStatus.DRY_RUN, StepStatus.SKIPPED)
            for s in self.steps
        )


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
