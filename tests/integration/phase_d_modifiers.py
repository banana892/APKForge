"""Test-only Phase D modifiers used by the integration tests and the Phase D runner.

They exist to exercise failure paths on a real decoded APK; neither is registered in
the default catalog.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.modification.contract import (
    APKModifier,
    ApplyOutcome,
    FileAction,
    ModifierPlan,
    PlannedFileChange,
)

if TYPE_CHECKING:
    from apkforge.modification.contract import ProjectContext

__all__ = ["FailingModifier", "UndeclaredChangeModifier"]


class FailingModifier(APKModifier):
    """Test-only: plans a file addition, then fails to apply it."""

    id: ClassVar[str] = "test.failing"
    name: ClassVar[str] = "Failing (test)"
    description: ClassVar[str] = "Always fails in apply."

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        plan.file_changes = [PlannedFileChange(path="assets/failing.txt", action=FileAction.ADD)]
        plan.changes = ["add assets/failing.txt"]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        raise RuntimeError("simulated modifier failure")


class UndeclaredChangeModifier(APKModifier):
    """Test-only: adds an asset but declares no expected change and has no verify()."""

    id: ClassVar[str] = "test.undeclared"
    name: ClassVar[str] = "Undeclared change (test)"
    description: ClassVar[str] = "Adds a file the plan does not announce as an expected change."
    path = "assets/apkforge-test/undeclared.txt"

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        plan.file_changes = [PlannedFileChange(path=self.path, action=FileAction.ADD)]
        plan.changes = [f"add {self.path}"]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        target = project.path(self.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"undeclared\n")
        return ApplyOutcome(applied=True)
