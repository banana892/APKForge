"""Tests for APKIntakeService orchestrator."""

from __future__ import annotations

from pathlib import Path

from apkforge.core.models import AnalysisStatus
from apkforge.intake import (
    APKIntakeService,
    InputFormat,
    PackageIdentity,
    PackageType,
)
from tests.fixtures import (
    create_split_apk_dir,
    create_synthetic_apk,
    create_synthetic_apks,
    create_synthetic_xapk,
)


def test_service_process_single_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.test.service",
        version_name="1.0.0",
        version_code=100,
    )

    service = APKIntakeService()
    pkg = service.process(apk_path)

    assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert pkg.package_type == PackageType.APK
    assert pkg.input_format == InputFormat.SINGLE_APK
    assert pkg.metadata.package_name == "com.test.service"
    assert pkg.identity is not None
    assert pkg.identity.package_name == "com.test.service"


def test_service_process_apks(tmp_path: Path) -> None:
    apks_path = tmp_path / "bundle.apks"
    create_synthetic_apks(apks_path)

    service = APKIntakeService()
    pkg = service.process(apks_path)

    assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert pkg.package_type == PackageType.APKS
    assert len(pkg.splits) == 3


def test_service_process_xapk(tmp_path: Path) -> None:
    xapk_path = tmp_path / "bundle.xapk"
    create_synthetic_xapk(xapk_path)

    service = APKIntakeService()
    pkg = service.process(xapk_path)

    assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert pkg.package_type == PackageType.XAPK
    assert len(pkg.splits) == 2


def test_service_process_split_dir(tmp_path: Path) -> None:
    split_dir = tmp_path / "splits"
    create_split_apk_dir(split_dir)

    service = APKIntakeService()
    pkg = service.process(split_dir)

    assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert pkg.package_type == PackageType.SPLIT
    assert len(pkg.splits) == 4


def test_service_process_invalid_input(tmp_path: Path) -> None:
    corrupt = tmp_path / "broken.apk"
    corrupt.write_text("not a zip")

    service = APKIntakeService()
    pkg = service.process(corrupt)

    assert pkg.status == AnalysisStatus.FAILED
    assert len(pkg.errors) > 0


def test_service_workspace_retention_override(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    create_synthetic_apk(apk_path)

    service = APKIntakeService()
    # Process without error
    pkg = service.process(apk_path, keep_workspace=False)
    assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)


def test_package_identity_comparison() -> None:
    id1 = PackageIdentity(package_name="com.example.app", version_name="1.0.0", version_code=1)
    id2 = PackageIdentity(package_name="com.example.app", version_name="2.0.0", version_code=2)
    id3 = PackageIdentity(package_name="com.different.app", version_name="1.0.0", version_code=1)

    assert id1.same_application(id2)
    assert not id1.same_application(id3)
