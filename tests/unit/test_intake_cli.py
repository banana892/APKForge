"""Tests for CLI inspect command."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from tests.fixtures import (
    create_split_apk_dir,
    create_synthetic_apk,
    create_synthetic_apks,
    create_synthetic_xapk,
)

runner = CliRunner()


def test_cli_inspect_text(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.test.cli",
        version_name="1.0.0",
        version_code=100,
    )

    result = runner.invoke(app, ["inspect", str(apk_path)])
    assert result.exit_code == 0
    assert "APKForge Package Inspection" in result.stdout
    assert "com.test.cli" in result.stdout
    assert "1.0.0" in result.stdout


def test_cli_inspect_json(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.test.jsoncli",
        version_name="2.0.0",
        version_code=200,
    )

    result = runner.invoke(app, ["inspect", str(apk_path), "--json"])
    assert result.exit_code == 0

    # Parse and validate JSON
    data = json.loads(result.stdout)
    assert data["package_type"] == "apk"
    assert data["metadata"]["package_name"] == "com.test.jsoncli"
    assert data["metadata"]["version_name"] == "2.0.0"
    assert data["hashes"]["sha256"] is not None


def test_cli_inspect_apks(tmp_path: Path) -> None:
    apks_path = tmp_path / "app.apks"
    create_synthetic_apks(apks_path)

    result = runner.invoke(app, ["inspect", str(apks_path)])
    assert result.exit_code == 0
    assert "APKS" in result.stdout


def test_cli_inspect_xapk(tmp_path: Path) -> None:
    xapk_path = tmp_path / "app.xapk"
    create_synthetic_xapk(xapk_path)

    result = runner.invoke(app, ["inspect", str(xapk_path)])
    assert result.exit_code == 0
    assert "XAPK" in result.stdout


def test_cli_inspect_split_dir(tmp_path: Path) -> None:
    split_dir = tmp_path / "splits"
    create_split_apk_dir(split_dir)

    result = runner.invoke(app, ["inspect", str(split_dir)])
    assert result.exit_code == 0
    assert "SPLIT" in result.stdout


def test_cli_inspect_invalid_file(tmp_path: Path) -> None:
    broken = tmp_path / "broken.apk"
    broken.write_text("not a real apk")

    result = runner.invoke(app, ["inspect", str(broken)])
    assert result.exit_code != 0
