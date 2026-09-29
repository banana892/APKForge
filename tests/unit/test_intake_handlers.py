"""Tests for package intake handlers (APK, APKS, XAPK, Split)."""

from __future__ import annotations

from pathlib import Path

from apkforge.core.config import ExtractionLimits
from apkforge.core.models import AnalysisStatus, APKInput
from apkforge.core.workspace import Workspace
from apkforge.intake import (
    InputFormat,
    PackageType,
    SplitType,
)
from apkforge.intake.detector import PackageDetector
from apkforge.intake.handlers.apk import SingleAPKHandler
from apkforge.intake.handlers.apks import APKSHandler
from apkforge.intake.handlers.split import SplitAPKHandler
from apkforge.intake.handlers.xapk import XAPKHandler
from apkforge.intake.hashing import compute_file_hashes
from tests.fixtures import (
    create_split_apk_dir,
    create_synthetic_apk,
    create_synthetic_apks,
    create_synthetic_xapk,
)


def test_single_apk_handler(tmp_path: Path) -> None:
    apk_file = tmp_path / "app.apk"
    create_synthetic_apk(
        apk_file,
        package_name="com.test.single",
        version_name="1.5.0",
        version_code=150,
        dex_count=2,
        native_abis=["arm64-v8a"],
    )

    initial_hash = compute_file_hashes(apk_file).sha256

    handler = SingleAPKHandler()
    ws = Workspace.create(APKInput(path=apk_file), base_dir=tmp_path / "workspaces")
    limits = ExtractionLimits()

    try:
        detection = PackageDetector.detect(apk_file)
        assert handler.can_handle(detection)

        pkg = handler.process(apk_file, ws, limits)
        assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
        assert pkg.package_type == PackageType.APK
        assert pkg.input_format == InputFormat.SINGLE_APK
        assert pkg.metadata.package_name == "com.test.single"
        assert pkg.metadata.version_name == "1.5.0"
        assert pkg.metadata.version_code == 150
        assert pkg.identity is not None
        assert pkg.identity.package_name == "com.test.single"
        assert len(pkg.dex_files) == 2
        assert len(pkg.native_libraries) == 1
        assert len(pkg.certificates) >= 1
        assert pkg.hashes is not None
        assert pkg.hashes.sha256 == initial_hash

        # Security check: original file must not be modified
        assert compute_file_hashes(apk_file).sha256 == initial_hash
    finally:
        ws.cleanup()


def test_apks_handler(tmp_path: Path) -> None:
    apks_file = tmp_path / "bundle.apks"
    create_synthetic_apks(
        apks_file,
        package_name="com.test.apks",
        version_code=200,
    )

    initial_hash = compute_file_hashes(apks_file).sha256

    handler = APKSHandler()
    ws = Workspace.create(APKInput(path=apks_file), base_dir=tmp_path / "workspaces")
    limits = ExtractionLimits()

    try:
        detection = PackageDetector.detect(apks_file)
        assert handler.can_handle(detection)

        pkg = handler.process(apks_file, ws, limits)
        assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
        assert pkg.package_type == PackageType.APKS
        assert pkg.input_format == InputFormat.APKS_BUNDLE
        assert pkg.metadata.package_name == "com.test.apks"
        assert len(pkg.splits) == 3

        # Check split classification
        split_types = {s.split_type for s in pkg.splits}
        assert SplitType.BASE in split_types
        assert SplitType.CONFIGURATION in split_types

        # Original container untouched
        assert compute_file_hashes(apks_file).sha256 == initial_hash
    finally:
        ws.cleanup()


def test_xapk_handler(tmp_path: Path) -> None:
    xapk_file = tmp_path / "app.xapk"
    create_synthetic_xapk(
        xapk_file,
        package_name="com.test.xapk",
        version_name="3.0.0",
        version_code=300,
    )

    initial_hash = compute_file_hashes(xapk_file).sha256

    handler = XAPKHandler()
    ws = Workspace.create(APKInput(path=xapk_file), base_dir=tmp_path / "workspaces")
    limits = ExtractionLimits()

    try:
        detection = PackageDetector.detect(xapk_file)
        assert handler.can_handle(detection)

        pkg = handler.process(xapk_file, ws, limits)
        assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
        assert pkg.package_type == PackageType.XAPK
        assert pkg.input_format == InputFormat.XAPK_BUNDLE
        assert pkg.metadata.package_name == "com.test.xapk"
        assert len(pkg.splits) >= 2
        assert "xapk_manifest" in pkg.extra

        # Original container untouched
        assert compute_file_hashes(xapk_file).sha256 == initial_hash
    finally:
        ws.cleanup()


def test_split_apk_handler(tmp_path: Path) -> None:
    split_dir = tmp_path / "split_dir"
    create_split_apk_dir(
        split_dir,
        package_name="com.test.splitdir",
        version_code=400,
    )

    handler = SplitAPKHandler()
    ws = Workspace.create(APKInput(path=split_dir), base_dir=tmp_path / "workspaces")
    limits = ExtractionLimits()

    try:
        detection = PackageDetector.detect(split_dir)
        assert handler.can_handle(detection)

        pkg = handler.process(split_dir, ws, limits)
        assert pkg.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
        assert pkg.package_type == PackageType.SPLIT
        assert pkg.input_format == InputFormat.SPLIT_DIRECTORY
        assert pkg.metadata.package_name == "com.test.splitdir"
        assert len(pkg.splits) == 4

        split_types = {s.split_type for s in pkg.splits}
        assert SplitType.BASE in split_types
        assert SplitType.CONFIGURATION in split_types
        assert SplitType.FEATURE in split_types
    finally:
        ws.cleanup()
