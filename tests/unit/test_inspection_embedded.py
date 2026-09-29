"""Unit tests for EmbeddedFileInspector."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from apkforge.inspection.embedded import EmbeddedFileInspector


def test_embedded_files_detection(tmp_path: Path) -> None:
    apk_path = tmp_path / "embedded_test.apk"

    # Construct inner APK with AndroidManifest.xml
    inner_apk_bytes = io.BytesIO()
    with zipfile.ZipFile(inner_apk_bytes, "w") as inner_zf:
        inner_zf.writestr("AndroidManifest.xml", b"<manifest/>")
        inner_zf.writestr("classes.dex", b"dex\n035\x00")
    inner_apk_data = inner_apk_bytes.getvalue()

    # Construct extra DEX
    extra_dex_data = b"dex\n035\x00" + b"\x00" * 32

    # Construct ELF binary
    elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32

    # Construct shell script
    script_data = b"#!/bin/sh\necho 'hello'\n"

    with zipfile.ZipFile(apk_path, "w") as zf:
        # Standard DEX should NOT be reported as embedded DEX
        zf.writestr("classes.dex", b"dex\n035\x00")
        zf.writestr("classes2.dex", b"dex\n035\x00")

        # Embedded files in assets
        zf.writestr("assets/dropped.apk", inner_apk_data)
        zf.writestr("assets/payload.dex", extra_dex_data)
        zf.writestr("assets/bin/su_binary", elf_data)
        zf.writestr("assets/scripts/run.sh", script_data)

    inspector = EmbeddedFileInspector()
    result, _warnings = inspector.inspect(apk_path)

    # 1. Embedded APK
    assert len(result.embedded_apks) == 1
    assert result.embedded_apks[0].path == "assets/dropped.apk"

    # 2. Embedded DEX (outside classes*.dex)
    assert len(result.embedded_dex) == 1
    assert result.embedded_dex[0].path == "assets/payload.dex"

    # 3. Executable-looking files
    exec_paths = {ex.path: ex.detected_type for ex in result.executable_files}
    assert "assets/bin/su_binary" in exec_paths
    assert exec_paths["assets/bin/su_binary"] == "ELF"
    assert "assets/scripts/run.sh" in exec_paths
    assert exec_paths["assets/scripts/run.sh"] == "script"
