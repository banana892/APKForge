"""Phase D CLI: ``apkforge modifiers`` and ``apkforge modify --modifier`` (simulated toolchain)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkforge.cli import main as cli
from apkforge.diff.models import ChangeType, FileEntryDiff
from apkforge.modification import pipeline as pipeline_mod
from apkforge.modification.builtin.marker_asset import MARKER_CONTENT
from tests.fixtures import create_synthetic_apk
from tests.unit.phase_d_support import FakeDiff, ZipService, baseline_for, diff_adding, sha
from tests.unit.test_c5_boot_receiver import PKG, manifest

runner = CliRunner()
MARKER = "assets/apkforge-test/marker.txt"


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk", package_name=PKG)


@pytest.fixture()
def baseline_file(apk: Path, tmp_path: Path) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(baseline_for(apk).model_dump_json())
    return p


@pytest.fixture()
def setup(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch the CLI's BuildService and the pipeline's DiffEngine."""
    state: dict[str, Any] = {"service": ZipService(), "diff": diff_adding(extra=[_marker()])}
    monkeypatch.setattr(cli, "_build_service", lambda work_dir: state["service"])
    monkeypatch.setattr(pipeline_mod, "DiffEngine", lambda: FakeDiff(state["diff"]))
    return state


def _marker() -> FileEntryDiff:
    return FileEntryDiff(
        path=MARKER, change_type=ChangeType.ADDED, category="asset", size_after=len(MARKER_CONTENT)
    )


def _modify(apk: Path, tmp_path: Path, *args: str) -> Any:
    return runner.invoke(
        cli.app, ["modify", str(apk), "--workspace", str(tmp_path / "work"), *args]
    )


class TestList:
    def test_list_text(self) -> None:
        res = runner.invoke(cli.app, ["modifiers"])
        assert res.exit_code == 0
        assert "c5.disable_boot_receiver" in res.output and "test.marker_asset" in res.output

    def test_list_json(self) -> None:
        res = runner.invoke(cli.app, ["modifiers", "--json"])
        assert res.exit_code == 0
        data = json.loads(res.stdout)
        assert [d["id"] for d in data] == ["c5.disable_boot_receiver", "test.marker_asset"]
        for d in data:
            assert {"id", "name", "description", "verification_available"} <= d.keys()


class TestModify:
    def test_dry_run_shows_plan_and_changes_nothing(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any]
    ) -> None:
        before = sha(apk)
        res = _modify(
            apk, tmp_path, "-m", "test.marker_asset", "-m", "c5.disable_boot_receiver", "--dry-run"
        )
        assert res.exit_code == 0, res.output
        assert "DRY_RUN" in res.output and "Plan: test.marker_asset" in res.output
        assert "marker_absent" in res.output  # precondition with expected/actual
        assert setup["service"].calls == ["prepare", "decode"]
        assert sha(apk) == before

    def test_dry_run_json(self, apk: Path, tmp_path: Path, setup: dict[str, Any]) -> None:
        res = _modify(apk, tmp_path, "-m", "test.marker_asset", "--dry-run", "--json")
        assert res.exit_code == 0, res.output
        data = json.loads(res.stdout)
        assert data["status"] == "dry_run" and data["dry_run"] is True
        (run,) = data["modifiers"]
        assert run["plan"]["readiness"] == "ready"
        assert run["plan"]["expected_changes"][0]["identifier"] == MARKER
        assert data["counts"]["executed"] == 0 and data["counts"]["dry_run"] == 1

    def test_execute_verified(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any], baseline_file: Path
    ) -> None:
        out = tmp_path / "out.apk"
        report = tmp_path / "reports" / "run.json"
        res = _modify(
            apk,
            tmp_path,
            "-m",
            "test.marker_asset",
            "--noop-baseline",
            str(baseline_file),
            "--output",
            str(out),
            "--report",
            str(report),
        )
        assert res.exit_code == 0, res.output
        assert "VERIFIED" in res.output and out.is_file()
        data = json.loads(report.read_text())
        assert data["status"] == "verified" and data["original_preserved"] is True
        assert data["modifiers"][0]["step"]["verified"] is True

    def test_execute_with_param(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any], baseline_file: Path
    ) -> None:
        setup["diff"] = diff_adding(
            extra=[
                FileEntryDiff(
                    path="assets/apkforge-test/m2.txt",
                    change_type=ChangeType.ADDED,
                    category="asset",
                    size_after=len(MARKER_CONTENT),
                )
            ]
        )
        res = _modify(
            apk,
            tmp_path,
            "-m",
            "test.marker_asset",
            "--param",
            "test.marker_asset:name=m2.txt",
            "--noop-baseline",
            str(baseline_file),
            "--json",
        )
        assert res.exit_code == 0, res.output
        assert json.loads(res.stdout)["modifiers"][0]["parameters"] == {"name": "m2.txt"}

    def test_skipped_exit_3(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any], baseline_file: Path
    ) -> None:
        setup["service"] = ZipService(manifest(permission=False))
        res = _modify(
            apk,
            tmp_path,
            "-m",
            "c5.disable_boot_receiver",
            "--noop-baseline",
            str(baseline_file),
            "--json",
        )
        assert res.exit_code == 3
        data = json.loads(res.stdout)
        assert data["status"] == "skipped" and data["counts"]["skipped"] == 1

    def test_build_failure_exit_1(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any], baseline_file: Path
    ) -> None:
        setup["service"] = ZipService(fail="build")
        res = _modify(
            apk, tmp_path, "-m", "test.marker_asset", "--noop-baseline", str(baseline_file)
        )
        assert res.exit_code == 1
        assert "FAILED" in res.output

    def test_no_noise_floor_exit_1(self, apk: Path, tmp_path: Path, setup: dict[str, Any]) -> None:
        res = _modify(apk, tmp_path, "-m", "test.marker_asset", "--json")
        assert res.exit_code == 1
        assert "noise floor is not established" in json.loads(res.stdout)["failures"][0]

    @pytest.mark.parametrize(
        "args",
        [
            ["-m", "does.not.exist"],
            ["-m", "test.marker_asset", "--param", "test.marker_asset:bogus=1"],
            ["-m", "test.marker_asset", "--param", "nocolon"],
            ["-m", "test.marker_asset", "-m", "test.marker_asset"],
            ["-m", "test.marker_asset", "--approve-all"],
            ["--allow-partial"],
        ],
    )
    def test_usage_errors_exit_2(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any], args: list[str]
    ) -> None:
        res = _modify(apk, tmp_path, *args)
        assert res.exit_code == 2, res.output
        assert setup["service"].calls == []

    def test_toolchain_unavailable_exit_2(
        self, apk: Path, tmp_path: Path, setup: dict[str, Any]
    ) -> None:
        setup["service"].toolchain_valid = False
        res = _modify(apk, tmp_path, "-m", "test.marker_asset", "--dry-run")
        assert res.exit_code == 2 and setup["service"].calls == []
