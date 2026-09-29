"""Tests for manifest parsing."""

from __future__ import annotations

from pathlib import Path

from apkforge.intake.manifest import parse_apk_manifest, parse_manifest_from_bytes
from tests.fixtures import create_synthetic_apk


def test_parse_manifest_from_bytes_plain_xml() -> None:
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.plainxml"
    android:versionCode="42"
    android:versionName="2.0.1">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33" />
    <application android:label="Plain App" android:debuggable="true" />
</manifest>"""

    meta, warnings = parse_manifest_from_bytes(xml)
    assert meta.package_name == "com.example.plainxml"
    assert meta.version_code == 42
    assert meta.version_name == "2.0.1"
    assert meta.min_sdk == 23
    assert meta.target_sdk == 33
    assert meta.application_label == "Plain App"
    assert meta.application_debuggable is True
    assert warnings == []


def test_parse_manifest_from_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.apkforge.manifesttest",
        version_name="3.2.1",
        version_code=321,
        min_sdk=21,
        target_sdk=34,
    )

    meta, _ = parse_apk_manifest(apk_path)
    assert meta.package_name == "com.apkforge.manifesttest"
    assert meta.version_name == "3.2.1"
    assert meta.version_code == 321
    assert meta.min_sdk == 21
    assert meta.target_sdk == 34
    assert meta.application_label == "Synthetic Test App"
    assert meta.application_debuggable is False


def test_parse_manifest_malformed_xml() -> None:
    malformed = b"<manifest package='com.broken'"
    meta, warnings = parse_manifest_from_bytes(malformed)
    assert meta.package_name is None
    assert any("XML parse error" in w for w in warnings)
