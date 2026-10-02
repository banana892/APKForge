"""Security invariant tests for intake subsystem."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkforge.core.config import APKForgeConfig, ExtractionLimits, WorkspaceSettings
from apkforge.core.models import AnalysisStatus
from apkforge.intake.hashing import compute_file_hashes
from apkforge.intake.service import APKIntakeService
from tests.fixtures import create_synthetic_apk, create_synthetic_apks


def _ws(tmp_path: Path) -> WorkspaceSettings:
    # Failed intakes keep their workspace by default (keep_on_failure); keep it in tmp_path.
    return WorkspaceSettings(base_directory=tmp_path / "ws")


def test_original_input_immutability(tmp_path: Path) -> None:
    """Security invariant: the original APK file is NEVER modified."""
    apk_path = tmp_path / "target.apk"
    create_synthetic_apk(apk_path, package_name="com.test.immutable")

    hash_before = compute_file_hashes(apk_path).sha256

    service = APKIntakeService(APKForgeConfig(workspace=_ws(tmp_path)))
    pkg = service.process(apk_path)

    hash_after = compute_file_hashes(apk_path).sha256

    assert hash_before == hash_after
    assert pkg.hashes is not None
    assert pkg.hashes.sha256 == hash_before


def test_apks_container_immutability(tmp_path: Path) -> None:
    """Security invariant: container formats remain untouched during extraction."""
    apks_path = tmp_path / "target.apks"
    create_synthetic_apks(apks_path)

    hash_before = compute_file_hashes(apks_path).sha256

    service = APKIntakeService(APKForgeConfig(workspace=_ws(tmp_path)))
    service.process(apks_path)

    hash_after = compute_file_hashes(apks_path).sha256
    assert hash_before == hash_after


def test_zip_slip_prevention(tmp_path: Path) -> None:
    """Security invariant: archives attempting directory traversal are rejected."""
    malicious_apk = tmp_path / "zip_slip.apk"
    with zipfile.ZipFile(malicious_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest />")
        zf.writestr("../../../../../evil.sh", b"#!/bin/sh\nrm -rf /")

    service = APKIntakeService(APKForgeConfig(workspace=_ws(tmp_path)))
    pkg = service.process(malicious_apk)

    assert pkg.status == AnalysisStatus.FAILED
    assert any("traversal" in err.lower() for err in pkg.errors)


def test_archive_limits_enforced_by_service(tmp_path: Path) -> None:
    """Security invariant: decompression limits (file count, size) reject bombs."""
    bomb_apk = tmp_path / "bomb.apk"
    with zipfile.ZipFile(bomb_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest />")
        for i in range(20):
            zf.writestr(f"filler_{i}.bin", b"A" * 100)

    # Configure very strict limit: max 5 files
    cfg = APKForgeConfig(
        extraction=ExtractionLimits(max_file_count=5),
        workspace=_ws(tmp_path),
    )
    service = APKIntakeService(config=cfg)
    pkg = service.process(bomb_apk)

    assert pkg.status == AnalysisStatus.FAILED
    assert any("limit" in err.lower() for err in pkg.errors)
