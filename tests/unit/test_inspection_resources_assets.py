"""Unit tests for ResourceInspector and AssetInspector."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkforge.inspection.assets import AssetInspector
from apkforge.inspection.resources import ResourceInspector


def test_resource_inspector_structure(tmp_path: Path) -> None:
    apk_path = tmp_path / "resources_test.apk"

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("resources.arsc", b"ARSC_BINARY_HEADER")
        zf.writestr("res/drawable-hdpi/icon.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        zf.writestr("res/drawable-xxhdpi/icon.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        zf.writestr("res/layout/activity_main.xml", b"<LinearLayout/>")
        zf.writestr("res/layout/fragment_test.xml", b"<FrameLayout/>")
        zf.writestr("res/values/strings.xml", b"<resources/>")
        zf.writestr("res/raw/sample_audio.mp3", b"ID3" + b"\x00" * 20)

    inspector = ResourceInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert result.has_resources_arsc is True
    assert result.resource_file_count == 6

    # Verify resource types breakdown
    type_map = {rc.resource_type: rc.count for rc in result.resource_types}
    assert type_map["drawable"] == 2
    assert type_map["layout"] == 2
    assert type_map["values"] == 1
    assert type_map["raw"] == 1


def test_asset_inspector_inventory_and_entropy(tmp_path: Path) -> None:
    apk_path = tmp_path / "assets_test.apk"

    # High entropy (random bytes) vs low entropy (repeating bytes)
    low_entropy_data = b"AAAAAAAAAAAAAAAA" * 32
    high_entropy_data = bytes(range(256))

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("assets/config.json", b'{"key": "value"}')
        zf.writestr("assets/low_entropy.txt", low_entropy_data)
        zf.writestr("assets/high_entropy.bin", high_entropy_data)

    inspector = AssetInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert result.total_assets == 3

    asset_map = {a.path: a for a in result.assets}
    assert "assets/config.json" in asset_map
    assert asset_map["assets/config.json"].mime_type == "application/json"

    # Entropy checks
    low_asset = asset_map["assets/low_entropy.txt"]
    high_asset = asset_map["assets/high_entropy.bin"]
    assert low_asset.entropy is not None
    assert high_asset.entropy is not None
    assert high_asset.entropy > low_asset.entropy
    assert low_asset.entropy < 1.0  # Repeating 'A' should have near 0 entropy
