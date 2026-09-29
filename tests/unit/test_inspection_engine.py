"""Unit tests for InspectionEngine and Phase 2 CLI options."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus
from apkforge.inspection.engine import InspectionEngine
from tests.fixtures import create_synthetic_apk

runner = CliRunner()


def test_inspection_engine_complete_pipeline(tmp_path: Path) -> None:
    apk_path = tmp_path / "complete_engine_test.apk"
    extra_files = {
        "res/layout/custom_layout.xml": b"<LinearLayout/>",
        "res/drawable/icon.png": b"PNG_DATA",
        "assets/app_config.json": b'{"endpoint": "https://api.test.com"}',
        "assets/helper.sh": b"#!/bin/bash\necho hello",
    }
    create_synthetic_apk(
        apk_path,
        package_name="com.test.engine",
        version_name="1.2.3",
        version_code=123,
        dex_count=2,
        native_abis=["arm64-v8a"],
        extra_files=extra_files,
    )

    engine = InspectionEngine()
    result = engine.inspect(apk_path)

    # 1. Status
    assert result.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert result.metadata.package_name == "com.test.engine"

    # 2. Package Inventory
    inv = result.inventory
    assert inv.manifest_count == 1
    assert inv.dex_count >= 1
    assert inv.native_library_count >= 1
    assert inv.resource_count >= 2
    assert inv.asset_count >= 2
    assert inv.executable_file_count >= 1

    # 3. Sub-inspectors results present
    assert result.manifest is not None
    assert result.dex is not None
    assert result.native is not None
    assert result.resources is not None
    assert result.assets is not None
    assert result.network is not None
    assert result.embedded is not None
    assert result.obfuscation is not None

    # 4. Inspector statuses recorded
    assert "manifest" in result.inspector_statuses
    assert "dex" in result.inspector_statuses
    assert "native" in result.inspector_statuses


def test_inspection_engine_error_isolation(tmp_path: Path) -> None:
    apk_path = tmp_path / "isolation_test.apk"
    create_synthetic_apk(apk_path)

    # Mock native inspector to raise an unhandled exception
    mock_native = MagicMock()
    mock_native.inspect.side_effect = RuntimeError("Simulated crash in ELF parser")

    engine = InspectionEngine(native_inspector=mock_native)
    result = engine.inspect(apk_path)

    # Status degrades to PARTIAL, does NOT crash the entire inspection
    assert result.status == AnalysisStatus.PARTIAL
    assert result.inspector_statuses["native"] == "failed"
    assert any("Simulated crash in ELF parser" in lim for lim in result.limitations)

    # Other inspectors succeeded
    assert result.manifest is not None
    assert result.inspector_statuses["manifest"] in ("complete", "partial")
    assert result.dex is not None


def test_cli_inspect_all_phase2_flags(tmp_path: Path) -> None:
    apk_path = tmp_path / "cli_flags_test.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.test.flags",
        dex_count=1,
        native_abis=["x86_64"],
    )

    # Test individual CLI flags
    flags = [
        "--manifest",
        "--dex",
        "--native",
        "--network",
        "--resources",
        "--assets",
        "--embedded",
        "--obfuscation",
    ]
    for flag in flags:
        res = runner.invoke(app, ["inspect", str(apk_path), flag])
        assert res.exit_code == 0, f"CLI inspect failed with flag: {flag}"
        assert "APKForge Package Inspection" in res.stdout


def test_cli_inspect_json_contains_all_phase2_fields(tmp_path: Path) -> None:
    apk_path = tmp_path / "cli_json_test.apk"
    create_synthetic_apk(apk_path, package_name="com.test.phase2json")

    res = runner.invoke(app, ["inspect", str(apk_path), "--json"])
    assert res.exit_code == 0

    data = json.loads(res.stdout)
    assert data["package_type"] == "apk"
    assert data["metadata"]["package_name"] == "com.test.phase2json"

    # Verify Phase 2 sections are in the JSON
    assert "inventory" in data
    assert "manifest" in data
    assert "dex" in data
    assert "native" in data
    assert "resources" in data
    assert "assets" in data
    assert "network" in data
    assert "embedded" in data
    assert "obfuscation" in data
    assert "inspector_statuses" in data
