"""Unit tests for DEXInspector."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from apkforge.inspection.dex import DEXInspector


def _build_minimal_dex(strings: list[str]) -> bytes:
    """Construct a synthetic minimal DEX header with printable string pool."""
    magic = b"dex\n035\x00"
    checksum = b"\x00\x00\x00\x00"
    signature = b"\x00" * 20

    header_size = 0x70  # 112 bytes
    endian_tag = struct.pack("<I", 0x12345678)
    link_size = struct.pack("<I", 0)
    link_off = struct.pack("<I", 0)
    map_off = struct.pack("<I", 0)

    # String items
    string_data_payload = b""
    for s in strings:
        encoded = s.encode("utf-8")
        # uleb128 length + bytes + null terminator
        string_data_payload += bytes([len(encoded)]) + encoded + b"\x00"

    file_size_val = header_size + len(string_data_payload) + 128
    file_size = struct.pack("<I", file_size_val)
    header_size_bytes = struct.pack("<I", header_size)

    string_ids_size = struct.pack("<I", len(strings))
    string_ids_off = struct.pack("<I", header_size)
    type_ids_size = struct.pack("<I", 0)
    type_ids_off = struct.pack("<I", 0)
    proto_ids_size = struct.pack("<I", 0)
    proto_ids_off = struct.pack("<I", 0)
    field_ids_size = struct.pack("<I", 0)
    field_ids_off = struct.pack("<I", 0)
    method_ids_size = struct.pack("<I", 0)
    method_ids_off = struct.pack("<I", 0)
    class_defs_size = struct.pack("<I", 0)
    class_defs_off = struct.pack("<I", 0)
    data_size = struct.pack("<I", len(string_data_payload))
    data_off = struct.pack("<I", header_size + 32)

    header = (
        magic
        + checksum
        + signature
        + file_size
        + header_size_bytes
        + endian_tag
        + link_size
        + link_off
        + map_off
        + string_ids_size
        + string_ids_off
        + type_ids_size
        + type_ids_off
        + proto_ids_size
        + proto_ids_off
        + field_ids_size
        + field_ids_off
        + method_ids_size
        + method_ids_off
        + class_defs_size
        + class_defs_off
        + data_size
        + data_off
    )
    assert len(header) == header_size
    return header + string_data_payload + b"\x00" * 64


def test_single_dex_inspection(tmp_path: Path) -> None:
    apk_path = tmp_path / "single_dex.apk"
    dex_data = _build_minimal_dex(["https://api.example.com", "MainActivity", "onCreate"])

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("classes.dex", dex_data)

    inspector = DEXInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert len(result.dex_files) == 1
    dex_file = result.dex_files[0]
    assert dex_file.path == "classes.dex"
    assert dex_file.size == len(dex_data)
    assert dex_file.dex_version == "035"

    # Verify strings extracted
    str_values = [s.value for s in result.strings]
    assert any("https://api.example.com" in s for s in str_values)


def test_multidex_inspection(tmp_path: Path) -> None:
    apk_path = tmp_path / "multidex.apk"
    dex1 = _build_minimal_dex(["string_one", "https://auth.example.com"])
    dex2 = _build_minimal_dex(["string_two", "198.51.100.1"])

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("classes.dex", dex1)
        zf.writestr("classes2.dex", dex2)

    inspector = DEXInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert len(result.dex_files) == 2
    names = [df.path for df in result.dex_files]
    assert "classes.dex" in names
    assert "classes2.dex" in names

    str_values = [s.value for s in result.strings]
    assert any("string_one" in s for s in str_values)
    assert any("string_two" in s for s in str_values)


def test_corrupt_dex_error_isolation(tmp_path: Path) -> None:
    apk_path = tmp_path / "corrupt_dex.apk"

    with zipfile.ZipFile(apk_path, "w") as zf:
        # Corrupted DEX: only 4 bytes of magic, no header
        zf.writestr("classes.dex", b"dex\n")

    inspector = DEXInspector()
    result, _warnings = inspector.inspect(apk_path)

    # Should not raise an exception; gracefully captures the failure
    assert len(result.dex_files) == 1
    assert result.dex_files[0].path == "classes.dex"


def test_parse_params_ignores_androguard_separators() -> None:
    """androguard's get_descriptor() separates parameter types with spaces; whitespace must
    never become a parameter (it produced Phase E keys like ``f(int, ,long)V``)."""
    from apkforge.inspection.dex import _parse_params
    from apkforge.transformation.dexstate import method_key

    compact = "IJLjava/lang/String;[[D[Lcom/x/A;Z"
    spaced = "I J Ljava/lang/String; [[D [Lcom/x/A; Z"
    want = ["int", "long", "Ljava/lang/String;", "[[D", "[Lcom/x/A;", "boolean"]
    assert _parse_params(compact) == _parse_params(spaced) == want
    assert _parse_params("") == _parse_params(" ") == []
    # the H.5 key from the smali proto equals the key Phase E derives from androguard
    assert (
        method_key("f", "(ILjava/lang/String;J)Ljava/lang/String;")
        == method_key("f", "(I Ljava/lang/String; J)Ljava/lang/String;")
        == "f(int,java.lang.String,long)java.lang.String"
    )
