"""Native library inspector — ELF inspection of .so files.

Inspects native shared libraries inside the APK, extracting ELF metadata,
architecture, sections, symbols, and printable strings.

Security invariant: Native libraries are never executed or loaded as
executable code.  All inspection is static, reading raw bytes only.
"""

from __future__ import annotations

import struct
import zipfile
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    NativeInspection,
    NativeLibraryInspection,
    NativeStringReference,
)
from apkforge.intake.hashing import compute_sha256

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["NativeInspector"]

_log = get_logger(__name__)

# ELF magic bytes
_ELF_MAGIC = b"\x7fELF"

# ELF class
_ELF_CLASS = {1: "ELF32", 2: "ELF64"}

# ELF endianness
_ELF_DATA = {1: "little-endian", 2: "big-endian"}

# ELF machine types (common ones)
_ELF_MACHINE = {
    0: "NONE",
    3: "x86",
    8: "MIPS",
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
}

# ELF type
_ELF_TYPE = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

# Known ABI paths
_KNOWN_ABIS = frozenset(
    {
        "arm64-v8a",
        "armeabi-v7a",
        "armeabi",
        "x86",
        "x86_64",
        "mips",
        "mips64",
    }
)

# Limits
_MAX_STRINGS_PER_LIB = 5_000
_MAX_SYMBOLS = 10_000
_MIN_STRING_LENGTH = 4


def _infer_abi(path: str) -> str | None:
    """Infer ABI from a native library path like 'lib/arm64-v8a/libfoo.so'."""
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "lib" and parts[1] in _KNOWN_ABIS:
        return parts[1]
    return None


class NativeInspector:
    """Inspects native shared libraries (.so files) inside an APK.

    Parses ELF headers for architecture, class, endianness, and machine type.
    Extracts section names, dynamic dependencies, and symbol tables where
    available.  Extracts printable strings from the binary.
    """

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[NativeInspection, list[str]]:
        """Inspect all native libraries in the APK.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage (for reusing native lib info).

        Returns:
            Tuple of (NativeInspection, warnings).
        """
        warnings: list[str] = []
        result = NativeInspection()
        abis: set[str] = set()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                so_entries = [
                    info.filename
                    for info in zf.infolist()
                    if not info.is_dir() and info.filename.endswith(".so")
                ]

                for so_name in sorted(so_entries):
                    try:
                        data = zf.read(so_name)
                        info = zf.getinfo(so_name)
                        lib_result = self._inspect_single_lib(
                            so_name, data, info.file_size, warnings
                        )
                        result.libraries.append(lib_result)
                        if lib_result.abi:
                            abis.add(lib_result.abi)
                    except Exception as exc:
                        warnings.append(f"Could not inspect native library '{so_name}': {exc}")

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Could not open APK for native inspection: {exc}")

        result.total_libraries = len(result.libraries)
        result.abis_found = sorted(abis)

        return result, warnings

    def _inspect_single_lib(
        self,
        path: str,
        data: bytes,
        file_size: int,
        warnings: list[str],
    ) -> NativeLibraryInspection:
        """Inspect a single native library."""
        sha256 = compute_sha256(data)
        abi = _infer_abi(path)

        lib = NativeLibraryInspection(
            path=path,
            size=file_size,
            sha256=sha256,
            abi=abi,
        )

        if len(data) < 16 or data[:4] != _ELF_MAGIC:
            # Not a valid ELF
            warnings.append(f"Library '{path}' is not a valid ELF binary.")
            return lib

        # Parse ELF header
        self._parse_elf_header(data, lib, warnings)

        # Extract strings
        lib.strings = self._extract_strings(data, path)

        return lib

    def _parse_elf_header(
        self,
        data: bytes,
        lib: NativeLibraryInspection,
        warnings: list[str],
    ) -> None:
        """Parse the ELF header to extract metadata."""
        if len(data) < 64:
            return

        # ELF identification
        ei_class = data[4]
        ei_data = data[5]

        lib.elf_class = _ELF_CLASS.get(ei_class, f"unknown({ei_class})")
        lib.endianness = _ELF_DATA.get(ei_data, f"unknown({ei_data})")

        # Determine byte order for struct parsing
        endian = "<" if ei_data == 1 else ">"
        is_64 = ei_class == 2

        try:
            # ELF type (offset 16-17)
            e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
            lib.elf_type = _ELF_TYPE.get(e_type, f"unknown({e_type})")

            # Machine type (offset 18-19)
            e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
            lib.machine_type = _ELF_MACHINE.get(e_machine, f"unknown({e_machine})")

            # Section headers
            if is_64:
                if len(data) >= 64:
                    e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
                    e_shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
                    e_shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
                    e_shstrndx = struct.unpack_from(f"{endian}H", data, 62)[0]
                    self._parse_sections_64(
                        data, e_shoff, e_shentsize, e_shnum, e_shstrndx, endian, lib, warnings
                    )
            else:
                if len(data) >= 52:
                    e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
                    e_shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
                    e_shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
                    e_shstrndx = struct.unpack_from(f"{endian}H", data, 50)[0]
                    self._parse_sections_32(
                        data, e_shoff, e_shentsize, e_shnum, e_shstrndx, endian, lib, warnings
                    )

        except Exception as exc:
            warnings.append(f"ELF header parsing incomplete for {lib.path}: {exc}")

    def _parse_sections_64(
        self,
        data: bytes,
        shoff: int,
        shentsize: int,
        shnum: int,
        shstrndx: int,
        endian: str,
        lib: NativeLibraryInspection,
        warnings: list[str],
    ) -> None:
        """Parse 64-bit ELF section headers."""
        if shoff == 0 or shnum == 0 or shentsize == 0:
            return
        if shoff + shnum * shentsize > len(data):
            return

        # Get section header string table
        strtab_offset = 0
        if shstrndx < shnum:
            str_sh_offset = shoff + shstrndx * shentsize
            if str_sh_offset + 64 <= len(data):
                strtab_offset = struct.unpack_from(f"{endian}Q", data, str_sh_offset + 24)[0]

        for i in range(min(shnum, 256)):  # Limit section count
            offset = shoff + i * shentsize
            if offset + 64 > len(data):
                break

            sh_name_idx = struct.unpack_from(f"{endian}I", data, offset)[0]
            sh_type = struct.unpack_from(f"{endian}I", data, offset + 4)[0]

            # Get section name
            name = self._read_string_at(data, strtab_offset + sh_name_idx)
            if name:
                lib.sections.append(name)

            # Parse dynamic section for dependencies
            if sh_type == 6:  # SHT_DYNAMIC
                sh_offset = struct.unpack_from(f"{endian}Q", data, offset + 24)[0]
                sh_size = struct.unpack_from(f"{endian}Q", data, offset + 32)[0]
                self._parse_dynamic_64(data, sh_offset, sh_size, endian, lib, warnings)

            # Parse symbol tables
            if sh_type in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
                sh_offset = struct.unpack_from(f"{endian}Q", data, offset + 24)[0]
                sh_size = struct.unpack_from(f"{endian}Q", data, offset + 32)[0]
                sh_link = struct.unpack_from(f"{endian}I", data, offset + 40)[0]

                # Get the linked string table
                if sh_link < shnum:
                    link_offset = shoff + sh_link * shentsize
                    if link_offset + 64 <= len(data):
                        sym_strtab = struct.unpack_from(f"{endian}Q", data, link_offset + 24)[0]
                        self._parse_symbols_64(
                            data, sh_offset, sh_size, sym_strtab, endian, lib, sh_type == 11
                        )

    def _parse_sections_32(
        self,
        data: bytes,
        shoff: int,
        shentsize: int,
        shnum: int,
        shstrndx: int,
        endian: str,
        lib: NativeLibraryInspection,
        warnings: list[str],
    ) -> None:
        """Parse 32-bit ELF section headers."""
        if shoff == 0 or shnum == 0 or shentsize == 0:
            return
        if shoff + shnum * shentsize > len(data):
            return

        strtab_offset = 0
        if shstrndx < shnum:
            str_sh_offset = shoff + shstrndx * shentsize
            if str_sh_offset + 40 <= len(data):
                strtab_offset = struct.unpack_from(f"{endian}I", data, str_sh_offset + 16)[0]

        for i in range(min(shnum, 256)):
            offset = shoff + i * shentsize
            if offset + 40 > len(data):
                break

            sh_name_idx = struct.unpack_from(f"{endian}I", data, offset)[0]
            sh_type = struct.unpack_from(f"{endian}I", data, offset + 4)[0]

            name = self._read_string_at(data, strtab_offset + sh_name_idx)
            if name:
                lib.sections.append(name)

            if sh_type == 6:  # SHT_DYNAMIC
                sh_offset = struct.unpack_from(f"{endian}I", data, offset + 16)[0]
                sh_size = struct.unpack_from(f"{endian}I", data, offset + 20)[0]
                self._parse_dynamic_32(data, sh_offset, sh_size, endian, lib, warnings)

    def _parse_dynamic_64(
        self,
        data: bytes,
        offset: int,
        size: int,
        endian: str,
        lib: NativeLibraryInspection,
        warnings: list[str],
    ) -> None:
        """Parse 64-bit dynamic section for DT_NEEDED entries."""
        entry_size = 16
        strtab_offset = 0

        # First pass: find DT_STRTAB
        pos = offset
        while pos + entry_size <= min(offset + size, len(data)):
            d_tag = struct.unpack_from(f"{endian}q", data, pos)[0]
            d_val = struct.unpack_from(f"{endian}Q", data, pos + 8)[0]
            if d_tag == 5:  # DT_STRTAB
                strtab_offset = d_val
                break
            if d_tag == 0:  # DT_NULL
                break
            pos += entry_size

        if strtab_offset == 0:
            return

        # For .so files in APKs, strtab_offset is typically a virtual address.
        # We do a best-effort search — this may not work for all ELF layouts.
        # Check if the offset seems like a file offset vs VA.
        if strtab_offset > len(data):
            # Try to find .dynstr in sections
            return

        # Second pass: extract DT_NEEDED names
        pos = offset
        while pos + entry_size <= min(offset + size, len(data)):
            d_tag = struct.unpack_from(f"{endian}q", data, pos)[0]
            d_val = struct.unpack_from(f"{endian}Q", data, pos + 8)[0]
            if d_tag == 1:  # DT_NEEDED
                name = self._read_string_at(data, strtab_offset + d_val)
                if name:
                    lib.dynamic_dependencies.append(name)
            if d_tag == 0:
                break
            pos += entry_size

    def _parse_dynamic_32(
        self,
        data: bytes,
        offset: int,
        size: int,
        endian: str,
        lib: NativeLibraryInspection,
        warnings: list[str],
    ) -> None:
        """Parse 32-bit dynamic section for DT_NEEDED entries."""
        entry_size = 8
        strtab_offset = 0

        pos = offset
        while pos + entry_size <= min(offset + size, len(data)):
            d_tag = struct.unpack_from(f"{endian}i", data, pos)[0]
            d_val = struct.unpack_from(f"{endian}I", data, pos + 4)[0]
            if d_tag == 5:
                strtab_offset = d_val
                break
            if d_tag == 0:
                break
            pos += entry_size

        if strtab_offset == 0 or strtab_offset > len(data):
            return

        pos = offset
        while pos + entry_size <= min(offset + size, len(data)):
            d_tag = struct.unpack_from(f"{endian}i", data, pos)[0]
            d_val = struct.unpack_from(f"{endian}I", data, pos + 4)[0]
            if d_tag == 1:
                name = self._read_string_at(data, strtab_offset + d_val)
                if name:
                    lib.dynamic_dependencies.append(name)
            if d_tag == 0:
                break
            pos += entry_size

    def _parse_symbols_64(
        self,
        data: bytes,
        offset: int,
        size: int,
        strtab_offset: int,
        endian: str,
        lib: NativeLibraryInspection,
        is_dynsym: bool,
    ) -> None:
        """Parse 64-bit symbol table."""
        entry_size = 24
        count = 0
        pos = offset
        while pos + entry_size <= min(offset + size, len(data)) and count < _MAX_SYMBOLS:
            st_name = struct.unpack_from(f"{endian}I", data, pos)[0]
            st_info = data[pos + 4] if pos + 4 < len(data) else 0
            st_shndx = (
                struct.unpack_from(f"{endian}H", data, pos + 6)[0] if pos + 6 < len(data) else 0
            )

            name = (
                self._read_string_at(data, strtab_offset + st_name)
                if strtab_offset + st_name < len(data)
                else None
            )
            if name and len(name) > 0:
                st_bind = st_info >> 4
                if st_shndx != 0:  # Defined symbol
                    lib.exported_symbols.append(name)
                elif st_bind == 1:  # STB_GLOBAL and undefined
                    lib.imported_symbols.append(name)
                count += 1

            pos += entry_size

    def _read_string_at(self, data: bytes, offset: int) -> str | None:
        """Read a null-terminated string from data at the given offset."""
        if offset < 0 or offset >= len(data):
            return None
        end = data.find(b"\x00", offset)
        if end < 0:
            end = min(offset + 256, len(data))
        try:
            s = data[offset:end].decode("utf-8", errors="replace")
            return s if s else None
        except Exception:
            return None

    def _extract_strings(
        self,
        data: bytes,
        lib_path: str,
    ) -> list[NativeStringReference]:
        """Extract printable strings from native library bytes."""
        strings: list[NativeStringReference] = []
        current: list[int] = []
        start_offset = 0
        count = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current:
                    start_offset = i
                current.append(byte)
            else:
                if len(current) >= _MIN_STRING_LENGTH and count < _MAX_STRINGS_PER_LIB:
                    s = bytes(current).decode("ascii")
                    strings.append(
                        NativeStringReference(
                            library=lib_path,
                            offset=start_offset,
                            value=s,
                        )
                    )
                    count += 1
                current = []

        if len(current) >= _MIN_STRING_LENGTH and count < _MAX_STRINGS_PER_LIB:
            s = bytes(current).decode("ascii")
            strings.append(
                NativeStringReference(
                    library=lib_path,
                    offset=start_offset,
                    value=s,
                )
            )

        return strings
