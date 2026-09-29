"""Tests for package format detection."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkforge.intake import InputFormat, PackageType
from apkforge.intake.detector import detect_package_format
from tests.fixtures import (
    create_split_apk_dir,
    create_synthetic_apk,
    create_synthetic_apks,
    create_synthetic_xapk,
)


def test_detect_single_apk(tmp_path: Path) -> None:
    apk_file = tmp_path / "app.apk"
    create_synthetic_apk(apk_file)

    res = detect_package_format(apk_file)
    assert res.is_valid
    assert res.format == InputFormat.SINGLE_APK
    assert res.package_type == PackageType.APK


def test_detect_apks_bundle(tmp_path: Path) -> None:
    apks_file = tmp_path / "app.apks"
    create_synthetic_apks(apks_file)

    res = detect_package_format(apks_file)
    assert res.is_valid
    assert res.format == InputFormat.APKS_BUNDLE
    assert res.package_type == PackageType.APKS


def test_detect_xapk_bundle(tmp_path: Path) -> None:
    xapk_file = tmp_path / "app.xapk"
    create_synthetic_xapk(xapk_file)

    res = detect_package_format(xapk_file)
    assert res.is_valid
    assert res.format == InputFormat.XAPK_BUNDLE
    assert res.package_type == PackageType.XAPK


def test_detect_split_directory(tmp_path: Path) -> None:
    split_dir = tmp_path / "splits"
    create_split_apk_dir(split_dir)

    res = detect_package_format(split_dir)
    assert res.is_valid
    assert res.format == InputFormat.SPLIT_DIRECTORY
    assert res.package_type == PackageType.SPLIT


def test_detect_nonexistent_path(tmp_path: Path) -> None:
    res = detect_package_format(tmp_path / "nonexistent.apk")
    assert not res.is_valid
    assert res.format == InputFormat.INVALID


def test_detect_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.apk"
    empty.touch()

    res = detect_package_format(empty)
    assert not res.is_valid
    assert res.format == InputFormat.INVALID


def test_detect_text_file_renamed_to_apk(tmp_path: Path) -> None:
    fake_apk = tmp_path / "fake.apk"
    fake_apk.write_text("This is just a text file, not a ZIP or APK.")

    res = detect_package_format(fake_apk)
    assert not res.is_valid
    assert res.format == InputFormat.INVALID


def test_detect_corrupt_zip(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.apk"
    corrupt.write_bytes(b"PK\x03\x04corrupted_header_data_without_central_dir")

    res = detect_package_format(corrupt)
    assert not res.is_valid
    assert res.format == InputFormat.INVALID


def test_detect_zip_without_android_manifest(tmp_path: Path) -> None:
    regular_zip = tmp_path / "not_an_apk.apk"
    with zipfile.ZipFile(regular_zip, "w") as zf:
        zf.writestr("readme.txt", "hello")

    res = detect_package_format(regular_zip)
    assert not res.is_valid
    assert res.format == InputFormat.INVALID


def test_detect_empty_directory(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()

    res = detect_package_format(empty_dir)
    assert not res.is_valid
    assert res.format == InputFormat.UNKNOWN
