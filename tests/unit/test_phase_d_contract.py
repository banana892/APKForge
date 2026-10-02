"""Phase D modifier contract: paths, preconditions, plan validation, conflict rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from apkforge.core.exceptions import ModificationError
from apkforge.modification import boot_receiver, edits
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.contract import (
    FileAction,
    ModifierPlan,
    PlannedFileChange,
    PlanReadiness,
    PlanTarget,
    Precondition,
    ProjectContext,
    TargetAccess,
    VerificationOutcome,
    validate_relative_path,
)
from apkforge.modification.edits import SourceEdit
from apkforge.modification.modifiers.base import StepStatus
from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineStatus,
    detect_conflicts,
)
from tests.fixtures import create_synthetic_apk
from tests.unit.phase_d_support import Scripted, ZipService
from tests.unit.test_c5_boot_receiver import PKG


def _plan(mid: str, **kw: Any) -> ModifierPlan:
    return ModifierPlan(modifier_id=mid, target_apk="a.apk", target_sha256="0" * 64, **kw)


class TestPaths:
    @pytest.mark.parametrize(
        "bad", ["", "/etc/passwd", "../x", "a/../../x", "a//b", "./a", "a\\b", "a\x00b"]
    )
    def test_unsafe_paths_rejected(self, bad: str) -> None:
        with pytest.raises(ModificationError):
            validate_relative_path(bad)

    def test_plain_path_accepted(self) -> None:
        assert validate_relative_path("assets/x/y.txt") == "assets/x/y.txt"

    def test_project_path_rejects_symlink_escape(self, tmp_path: Path) -> None:
        decoded = tmp_path / "decoded"
        decoded.mkdir()
        (decoded / "link").symlink_to(tmp_path)
        project = ProjectContext(decoded, original_apk=tmp_path / "a.apk", original_sha256="0")
        assert project.path("assets/x") == decoded.resolve() / "assets" / "x"
        with pytest.raises(ModificationError, match="escapes"):
            project.path("link/outside.txt")


class TestPlanModel:
    def test_require_records_and_blocks(self) -> None:
        plan = _plan("m")
        assert plan.require("ok", True, expected="x", actual="x")
        assert plan.ready
        assert not plan.require("missing", False, expected="present", actual="absent")
        assert plan.readiness == PlanReadiness.PRECONDITION_FAILED and not plan.ready
        assert plan.problems == ["missing: expected present, found absent"]
        assert [p.satisfied for p in plan.preconditions] == [True, False]

    def test_comparable_ignores_details(self) -> None:
        a = _plan("m", details={"sha": "1"}, changes=["x"])
        b = _plan("m", details={"sha": "2"}, changes=["y"])
        assert a.comparable() == b.comparable()
        b.file_changes = [PlannedFileChange(path="x", action=FileAction.ADD)]
        assert a.comparable() != b.comparable()

    def test_verification_outcome_needs_checks(self) -> None:
        assert not VerificationOutcome.from_checks([]).passed
        ok = Precondition(name="c", satisfied=True, expected="e", actual="e")
        bad = Precondition(name="d", satisfied=False, expected="e", actual="f")
        assert VerificationOutcome.from_checks([ok]).passed
        out = VerificationOutcome.from_checks([ok, bad])
        assert not out.passed and out.message == "d: expected e, found f"

    def test_source_edit_shared_with_c5(self) -> None:
        assert boot_receiver.SourceEdit is edits.SourceEdit
        assert boot_receiver.manifest_edits is edits.manifest_edits


class TestConflictRules:
    def _t(self, kind: str, ident: str, access: TargetAccess) -> PlanTarget:
        return PlanTarget(kind=kind, identifier=ident, access=access)

    def test_shared_manifest_modify_is_not_a_conflict(self) -> None:
        manifest = [PlannedFileChange(path="AndroidManifest.xml", action=FileAction.MODIFY)]
        a = _plan(
            "a", file_changes=manifest, targets=[self._t("permission", "P", TargetAccess.REMOVE)]
        )
        b = _plan(
            "b", file_changes=manifest, targets=[self._t("component", "C", TargetAccess.MODIFY)]
        )
        assert detect_conflicts([a, b]) == []

    def test_add_vs_modify_same_file_conflicts(self) -> None:
        a = _plan("a", file_changes=[PlannedFileChange(path="f", action=FileAction.ADD)])
        b = _plan("b", file_changes=[PlannedFileChange(path="f", action=FileAction.MODIFY)])
        (c,) = detect_conflicts([a, b])
        assert (c.kind, c.subject, c.modifiers) == ("file", "f", ["a", "b"])

    def test_conflicts_reported_in_plan_order(self) -> None:
        t = [self._t("component", "C", TargetAccess.MODIFY)]
        plans = [_plan("x", targets=t), _plan("y", targets=t), _plan("z", targets=t)]
        assert [c.modifiers for c in detect_conflicts(plans)] == [
            ["x", "y"],
            ["x", "z"],
            ["y", "z"],
        ]


class _BadPlan(Scripted):
    def __init__(self, mid: str, mode: str) -> None:
        super().__init__(mid)
        self.mode = mode

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = super().plan(project, findings, parameters)
        if self.mode == "traversal":
            plan.file_changes = [PlannedFileChange(path="../escape.txt", action=FileAction.ADD)]
        elif self.mode == "undeclared_manifest":
            plan.manifest_edits = [SourceEdit(kind="remove_element", element="manifest/x")]
        elif self.mode == "no_files":
            plan.file_changes = []
        elif self.mode == "wrong_id":
            plan.modifier_id = "someone-else"
        elif self.mode == "wrong_sha":
            plan.target_sha256 = "f" * 64
        return plan


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("traversal", "Unsafe project path"),
        ("undeclared_manifest", "AndroidManifest.xml is not declared"),
        ("no_files", "must declare the files"),
        ("wrong_id", "plan names modifier"),
        ("wrong_sha", "target SHA-256"),
    ],
)
def test_invalid_plans_fail_before_apply(tmp_path: Path, mode: str, message: str) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk", package_name=PKG)
    mod = _BadPlan("bad", mode)
    svc = ZipService()
    res = ModificationPipeline(svc, ModifierCatalog([mod])).run(  # type: ignore[arg-type]
        apk, [ModifierRequest(modifier_id="bad")], work_dir=tmp_path / "work"
    )
    assert res.status == PipelineStatus.FAILED
    step = res.modifiers[0].step
    assert step.status == StepStatus.FAILED and message in step.message
    assert "apply" not in mod.calls and "build" not in svc.calls
