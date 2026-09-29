"""APK structural inventory — file, DEX, and native library discovery.

Classifies every entry inside an APK into categories (manifest, DEX,
resource, native lib, etc.) and produces :class:`PackageFile`,
:class:`DEXFile`, and :class:`NativeLibrary` models.

Does NOT perform deep analysis.  The purpose is to establish the inventory
that later phases can analyse.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path, PurePosixPath

from apkforge.core.logging import get_logger
from apkforge.intake import (
    DEXFile,
    FileCategory,
    NativeLibrary,
    PackageFile,
)
from apkforge.intake.hashing import compute_sha256

__all__ = ["build_inventory"]

_log = get_logger(__name__)

# Regex to match DEX filenames
_DEX_PATTERN = re.compile(r"^classes\d*\.dex$")

# Known ABI directories under lib/
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


def classify_entry(entry_path: str) -> FileCategory:
    """Classify a ZIP entry path into a :class:`FileCategory`.

    Args:
        entry_path: The ZIP entry path (e.g. ``classes.dex``).

    Returns:
        FileCategory: The classification.
    """
    p = PurePosixPath(entry_path)
    name = p.name.lower()
    parts = p.parts

    if entry_path == "AndroidManifest.xml":
        return FileCategory.MANIFEST

    if _DEX_PATTERN.match(p.name):
        return FileCategory.DEX

    if entry_path == "resources.arsc":
        return FileCategory.RESOURCE_TABLE

    if len(parts) >= 1 and parts[0] == "res":
        return FileCategory.RESOURCE

    if len(parts) >= 1 and parts[0] == "assets":
        return FileCategory.ASSET

    if name.endswith(".so") and len(parts) >= 2 and parts[0] == "lib":
        return FileCategory.NATIVE_LIB

    if len(parts) >= 1 and parts[0] == "META-INF":
        lower = entry_path.lower()
        if lower.endswith((".rsa", ".dsa", ".ec")):
            return FileCategory.CERTIFICATE
        if lower.endswith((".sf", ".mf")):
            return FileCategory.SIGNATURE
        return FileCategory.SIGNATURE  # All META-INF entries are signature-related

    if name.endswith((".kotlin_module", ".kotlin_builtins")):
        return FileCategory.KOTLIN_MODULE

    return FileCategory.OTHER


def _infer_abi(entry_path: str) -> str | None:
    """Infer the ABI from a native library path like ``lib/arm64-v8a/libfoo.so``."""
    parts = PurePosixPath(entry_path).parts
    if len(parts) >= 3 and parts[0] == "lib" and parts[1] in _KNOWN_ABIS:
        return parts[1]
    return None


def build_inventory(
    apk_path: Path,
) -> tuple[list[PackageFile], list[DEXFile], list[NativeLibrary], list[str]]:
    """Build the structural inventory of an APK file.

    Iterates all ZIP entries, classifies them, and produces separate
    inventories for DEX files and native libraries.

    Does NOT extract files to disk.  All reads are done in-memory from
    the ZIP stream.

    Args:
        apk_path: Path to the APK file.

    Returns:
        A tuple of (files, dex_files, native_libraries, warnings).
    """
    warnings: list[str] = []
    files: list[PackageFile] = []
    dex_files: list[DEXFile] = []
    native_libs: list[NativeLibrary] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                category = classify_entry(info.filename)

                files.append(
                    PackageFile(
                        path=info.filename,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                        category=category,
                    )
                )

                # DEX files — compute hash
                if category == FileCategory.DEX:
                    try:
                        data = zf.read(info.filename)
                        sha256 = compute_sha256(data)
                        dex_files.append(
                            DEXFile(
                                path=info.filename,
                                size=info.file_size,
                                sha256=sha256,
                            )
                        )
                    except Exception as exc:
                        warnings.append(f"Could not read DEX file {info.filename}: {exc}")

                # Native libraries — compute hash and infer ABI
                elif category == FileCategory.NATIVE_LIB:
                    try:
                        data = zf.read(info.filename)
                        sha256 = compute_sha256(data)
                        native_libs.append(
                            NativeLibrary(
                                path=info.filename,
                                size=info.file_size,
                                sha256=sha256,
                                abi=_infer_abi(info.filename),
                            )
                        )
                    except Exception as exc:
                        warnings.append(f"Could not read native library {info.filename}: {exc}")

    except (zipfile.BadZipFile, OSError) as exc:
        warnings.append(f"Could not build inventory: {exc}")

    _log.debug(
        "Inventory: %d files, %d DEX, %d native libs",
        len(files),
        len(dex_files),
        len(native_libs),
    )
    return files, dex_files, native_libs, warnings
