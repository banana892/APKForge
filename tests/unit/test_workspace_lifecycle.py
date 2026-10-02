"""Regression tests: temporary workspaces are removed unless explicitly kept.

Before the fix, ``InspectionEngine.inspect(keep_workspace=False)`` on a standalone APK
left its intake workspace (``<base>/apkforge_<id>_*/input/<apk>``) behind on every call,
because cleanup searched the *original* APK's parents for an ``apkforge_*`` directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkforge.core.config import APKForgeConfig, WorkspaceSettings
from apkforge.inspection.engine import InspectionEngine
from apkforge.intake import APKIntakeService
from apkforge.modification.framework import ModificationFramework
from apkforge.modification.models import (
    ChangeStatus,
    ChangeType,
    ModificationPlan,
    PlannedChange,
    PlanStatus,
)
from apkforge.modification.modifiers.base import StepStatus
from tests.fixtures import create_synthetic_apk


def _config(base: Path) -> APKForgeConfig:
    return APKForgeConfig(workspace=WorkspaceSettings(base_directory=base))


def _entries(base: Path) -> list[Path]:
    return sorted(base.iterdir()) if base.exists() else []


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "in" / "app.apk"
    path.parent.mkdir()
    create_synthetic_apk(path, package_name="com.test.lifecycle")
    return path


class TestInspectionWorkspace:
    def test_removed_on_success(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        for _ in range(3):
            result = InspectionEngine(_config(base)).inspect(apk, keep_workspace=False)
            assert result.manifest is not None
        assert _entries(base) == []

    def test_default_removes(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        InspectionEngine(_config(base)).inspect(apk)
        assert _entries(base) == []

    def test_removed_when_inspector_raises(
        self, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "ws"
        engine = InspectionEngine(_config(base))

        def boom(*_a: object, **_k: object) -> None:
            raise KeyboardInterrupt  # not caught by the per-inspector handlers

        monkeypatch.setattr(engine, "_compile_inventory", boom)
        with pytest.raises(KeyboardInterrupt):
            engine.inspect(apk, keep_workspace=False)
        assert _entries(base) == []

    def test_removed_when_intake_fails(self, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        bad = tmp_path / "bad.apk"
        bad.write_bytes(b"PK\x03\x04 not really a zip")
        InspectionEngine(_config(base)).inspect(bad, keep_workspace=False)
        assert _entries(base) == []

    def test_kept_when_requested(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        result = InspectionEngine(_config(base)).inspect(apk, keep_workspace=True)
        kept = _entries(base)
        assert len(kept) == 1
        assert result.package is not None and result.package.workspace_root == kept[0]

    def test_never_touches_input_directory(self, tmp_path: Path) -> None:
        # The old heuristic deleted any parent named apkforge_* of the *input* APK.
        src_dir = tmp_path / "apkforge_user_samples"
        src_dir.mkdir()
        apk = src_dir / "app.apk"
        create_synthetic_apk(apk, package_name="com.test.lifecycle")
        InspectionEngine(_config(tmp_path / "ws")).inspect(apk, keep_workspace=False)
        assert apk.is_file()

    def test_does_not_remove_other_runs(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        kept = InspectionEngine(_config(base)).inspect(apk, keep_workspace=True)
        InspectionEngine(_config(base)).inspect(apk, keep_workspace=False)
        assert kept.package is not None
        assert _entries(base) == [kept.package.workspace_root]


class TestIntakeWorkspace:
    def test_retained_root_is_reported(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        pkg = APKIntakeService(_config(base)).process(apk, keep_workspace=True)
        assert pkg.workspace_root is not None and pkg.workspace_root.parent == base.resolve()
        assert "workspace_root" not in pkg.model_dump()

    def test_removed_when_not_kept(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "ws"
        pkg = APKIntakeService(_config(base)).process(apk, keep_workspace=False)
        assert pkg.workspace_root is None
        assert _entries(base) == []


def _approved_plan(apk: Path) -> ModificationPlan:
    """An approved plan whose only change has no registered modifier, so preflight fails."""
    plan = ModificationPlan(
        plan_id="lifecycle",
        source_apk=str(apk),
        source_sha256=ModificationFramework._compute_sha256(apk),
        created_at="2026-10-02T00:00:00Z",
        status=PlanStatus.APPROVED,
    )
    plan.changes.append(
        PlannedChange(
            id="c1",
            change_type=ChangeType.EXTERNAL_TOOL_PATCH,
            target="unsupported",
            status=ChangeStatus.ACCEPTED,
        )
    )
    return plan


class TestModificationFrameworkWorkspace:
    def test_failed_run_removes_own_workspace(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "mods"
        result = ModificationFramework(workspace_base=base).execute(
            _approved_plan(apk), apk
        )
        assert result.status == StepStatus.FAILED
        assert result.working_copy_path is None
        assert _entries(base) == []

    def test_failed_run_kept_when_requested(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "mods"
        result = ModificationFramework(workspace_base=base).execute(
            _approved_plan(apk), apk, keep_workspace=True
        )
        assert result.status == StepStatus.FAILED
        assert len(_entries(base)) == 1

    def test_caller_workspace_never_removed(self, apk: Path, tmp_path: Path) -> None:
        own = tmp_path / "mine"
        own.mkdir()
        result = ModificationFramework().execute(
            _approved_plan(apk), apk, workspace_dir=own
        )
        assert result.status == StepStatus.FAILED
        assert own.is_dir()

    def test_runs_get_distinct_workspaces(self, apk: Path, tmp_path: Path) -> None:
        fw = ModificationFramework(workspace_base=tmp_path / "mods")
        assert fw._create_workspace_dir(apk) != fw._create_workspace_dir(apk)
