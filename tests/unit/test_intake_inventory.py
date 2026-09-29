"""Tests for APK structural inventory builder."""

from __future__ import annotations

from pathlib import Path

from apkforge.intake import FileCategory
from apkforge.intake.inventory import build_inventory, classify_entry
from tests.fixtures import create_synthetic_apk


def test_classify_entry() -> None:
    assert classify_entry("AndroidManifest.xml") == FileCategory.MANIFEST
    assert classify_entry("classes.dex") == FileCategory.DEX
    assert classify_entry("classes2.dex") == FileCategory.DEX
    assert classify_entry("resources.arsc") == FileCategory.RESOURCE_TABLE
    assert classify_entry("res/drawable/icon.png") == FileCategory.RESOURCE
    assert classify_entry("assets/data.json") == FileCategory.ASSET
    assert classify_entry("lib/arm64-v8a/libfoo.so") == FileCategory.NATIVE_LIB
    assert classify_entry("META-INF/CERT.RSA") == FileCategory.CERTIFICATE
    assert classify_entry("META-INF/MANIFEST.MF") == FileCategory.SIGNATURE
    assert classify_entry("other/misc.txt") == FileCategory.OTHER


def test_build_inventory(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    create_synthetic_apk(
        apk_path,
        dex_count=2,
        native_abis=["arm64-v8a", "x86_64"],
        include_cert=True,
    )

    files, dex_files, native_libs, warnings = build_inventory(apk_path)
    assert len(files) >= 5
    assert warnings == []

    # Check DEX files
    assert len(dex_files) == 2
    dex_names = {d.path for d in dex_files}
    assert "classes.dex" in dex_names
    assert "classes2.dex" in dex_names
    for d in dex_files:
        assert len(d.sha256) == 64
        assert d.size > 0

    # Check Native libraries
    assert len(native_libs) == 2
    abi_map = {n.abi: n for n in native_libs}
    assert "arm64-v8a" in abi_map
    assert "x86_64" in abi_map
    for n in native_libs:
        assert len(n.sha256) == 64
        assert n.path.endswith(".so")
