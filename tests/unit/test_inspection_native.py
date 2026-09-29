"""Unit tests for NativeInspector."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from apkforge.inspection.native import NativeInspector


def _build_synthetic_elf(
    is_64bit: bool = True,
    is_little_endian: bool = True,
    machine: int = 183,  # 183 = AArch64, 40 = ARM
    strings: list[str] | None = None,
) -> bytes:
    """Build a valid minimal ELF header and string section."""
    ei_class = 2 if is_64bit else 1
    ei_data = 1 if is_little_endian else 2
    endian_prefix = "<" if is_little_endian else ">"

    e_ident = (
        b"\x7fELF"
        + bytes([ei_class, ei_data, 1, 0])  # version 1, OS/ABI none
        + b"\x00" * 8  # padding
    )
    assert len(e_ident) == 16

    e_type = 3  # ET_DYN (shared object)

    if is_64bit:
        # ELF64 header: 64 bytes total
        # H: type, H: machine, I: version, Q: entry, Q: phoff, Q: shoff, I: flags,
        # H: ehsize, H: phentsize, H: phnum, H: shentsize, H: shnum, H: shstrndx
        header_body = struct.pack(
            f"{endian_prefix}HHIQQQIHHHHHH",
            e_type,
            machine,
            1,  # version
            0,  # entry
            0,  # phoff
            0,  # shoff
            0,  # flags
            64,  # ehsize
            56,  # phentsize
            0,  # phnum
            64,  # shentsize
            0,  # shnum
            0,  # shstrndx
        )
    else:
        # ELF32 header: 52 bytes total
        header_body = struct.pack(
            f"{endian_prefix}HHIIIIIHHHHHH",
            e_type,
            machine,
            1,  # version
            0,  # entry
            0,  # phoff
            0,  # shoff
            0,  # flags
            52,  # ehsize
            32,  # phentsize
            0,  # phnum
            40,  # shentsize
            0,  # shnum
            0,  # shstrndx
        )

    elf_header = e_ident + header_body

    # Append string payload
    payload = b""
    if strings:
        for s in strings:
            payload += s.encode("utf-8") + b"\x00"

    return elf_header + payload + b"\x00" * 128


def test_native_library_inspection_64bit_arm(tmp_path: Path) -> None:
    apk_path = tmp_path / "native_arm64.apk"
    elf_data = _build_synthetic_elf(
        is_64bit=True,
        is_little_endian=True,
        machine=183,  # AArch64
        strings=["NativeSecretKey123", "https://c2.example.org/ping"],
    )

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("lib/arm64-v8a/libcrypt.so", elf_data)

    inspector = NativeInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert result.total_libraries == 1
    assert "arm64-v8a" in result.abis_found

    lib = result.libraries[0]
    assert lib.path == "lib/arm64-v8a/libcrypt.so"
    assert lib.abi == "arm64-v8a"
    assert lib.elf_class == "ELF64"
    assert lib.endianness == "little-endian"
    assert lib.machine_type == "AArch64"

    # Check extracted native strings
    str_vals = [s.value for s in lib.strings]
    assert any("NativeSecretKey123" in s for s in str_vals)


def test_native_library_inspection_32bit_arm(tmp_path: Path) -> None:
    apk_path = tmp_path / "native_armeabi.apk"
    elf_data = _build_synthetic_elf(
        is_64bit=False,
        is_little_endian=True,
        machine=40,  # ARM
    )

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("lib/armeabi-v7a/liblegacy.so", elf_data)

    inspector = NativeInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert result.total_libraries == 1
    assert "armeabi-v7a" in result.abis_found

    lib = result.libraries[0]
    assert lib.elf_class == "ELF32"
    assert lib.machine_type == "ARM"


def test_native_inspector_non_elf_so_error_isolation(tmp_path: Path) -> None:
    apk_path = tmp_path / "fake_so.apk"

    with zipfile.ZipFile(apk_path, "w") as zf:
        # Not a valid ELF file
        zf.writestr("lib/x86/libinvalid.so", b"THIS_IS_NOT_AN_ELF_FILE")

    inspector = NativeInspector()
    result, warnings = inspector.inspect(apk_path)

    assert result.total_libraries == 1
    lib = result.libraries[0]
    assert lib.elf_class is None  # Gracefully failed to parse header
    assert len(warnings) > 0
