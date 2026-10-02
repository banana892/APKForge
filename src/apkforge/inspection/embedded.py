"""Embedded file inspector — detection of embedded APKs, DEX, and executables.

Detects APK files, DEX files outside conventional locations, and other
executable-looking files inside the APK.

Detection is based on file structure/signatures, not filenames alone.

Security invariant: Embedded files are never executed or recursively
unpacked beyond detection.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING

from apkforge.core.config import ExtractionLimits
from apkforge.core.exceptions import ExtractionError
from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    EmbeddedAPKInfo,
    EmbeddedDEXInfo,
    EmbeddedFileInspection,
    ExecutableFileInfo,
)
from apkforge.intake.archive import validate_archive_entries
from apkforge.intake.hashing import compute_sha256

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["EmbeddedFileInspector"]

_log = get_logger(__name__)

# Conventional DEX locations
_CONVENTIONAL_DEX = re.compile(r"^classes\d*\.dex$")

# File signatures for detection
_SIGNATURES = {
    b"\x7fELF": "ELF",
    b"dex\n": "DEX",
    b"PK\x03\x04": "ZIP/APK/JAR",
    b"\x1f\x8b": "gzip",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\xfd7zXZ": "xz",
    b"BZ": "bzip2",
}

# Max file size to read for detection
_MAX_DETECT_SIZE = 64 * 1024 * 1024  # 64 MiB


# Depth of an archive nested directly inside the inspected APK.  Nested
# inspection only ever lists the entries of that one level and never opens an
# archive found inside it, so this is the maximum depth reached.
_NESTED_DEPTH = 1


def _nested_entry_names(data: bytes, limits: ExtractionLimits) -> list[str]:
    """List the entries of an in-memory nested archive under *limits*.

    Only the central directory is parsed; no entry is decompressed.

    Raises:
        ExtractionError: If the archive violates the configured limits
            (recursion depth, entry count, unsafe entry path, declared sizes).
        zipfile.BadZipFile: If the data is not a readable archive.
    """
    if limits.max_recursion_depth < _NESTED_DEPTH:
        raise ExtractionError(
            f"Nested archive depth {_NESTED_DEPTH} exceeds limit {limits.max_recursion_depth}",
            context="archive-limits",
        )
    with zipfile.ZipFile(io.BytesIO(data), "r") as inner_zf:
        entries = inner_zf.infolist()
    validate_archive_entries(entries, limits)
    return [e.filename for e in entries]


def _detect_file_type(data: bytes, filename: str, limits: ExtractionLimits) -> str | None:
    """Detect the file type from magic bytes and extension.

    Raises:
        ExtractionError: If a ZIP needing content sniffing violates *limits*.
    """
    # Magic byte detection (first 8 bytes)
    header = data[:8]
    for magic, file_type in _SIGNATURES.items():
        if header.startswith(magic):
            # Distinguish APK/JAR from plain ZIP
            if file_type == "ZIP/APK/JAR":
                if filename.endswith(".apk"):
                    return "APK"
                if filename.endswith(".jar"):
                    return "JAR"
                try:
                    names = _nested_entry_names(data, limits)
                except ExtractionError:
                    raise
                except Exception:
                    return "ZIP"
                if "AndroidManifest.xml" in names:
                    return "APK"
                if any(n.endswith(".class") for n in names):
                    return "JAR"
                return "ZIP"
            return file_type

    # Extension-based fallback
    lower = filename.lower()
    if (lower.endswith(".sh") or lower.endswith(".bash")) and data[:2] == b"#!":
        return "script"
    if lower.endswith(".py") and data[:2] == b"#!":
        return "script"
    if lower.endswith((".bat", ".cmd")):
        return "script"

    return None


class EmbeddedFileInspector:
    """Detects embedded APKs, DEX files, and executables inside an APK.

    Nested archives are opened in memory under the same
    :class:`~apkforge.core.config.ExtractionLimits` that govern top-level
    intake.  A nested APK that violates them is still reported, is treated as
    possibly containing code (it cannot be proven code-free), and produces a
    warning.

    Args:
        limits: Extraction limits; defaults to ``ExtractionLimits()``.
    """

    def __init__(self, limits: ExtractionLimits | None = None) -> None:
        self._limits = limits or ExtractionLimits()

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[EmbeddedFileInspection, list[str]]:
        """Detect embedded files in the APK.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage.

        Returns:
            Tuple of (EmbeddedFileInspection, warnings).
        """
        warnings: list[str] = []
        result = EmbeddedFileInspection()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    filename = info.filename

                    # Skip conventional locations
                    if filename == "AndroidManifest.xml":
                        continue
                    if filename == "resources.arsc":
                        continue
                    if filename.startswith("META-INF/"):
                        continue

                    try:
                        if info.file_size > _MAX_DETECT_SIZE:
                            warnings.append(
                                f"File '{filename}' too large for embedded detection "
                                f"({info.file_size} bytes)."
                            )
                            continue

                        data = zf.read(filename)
                        file_type = _detect_file_type(data, filename, self._limits)

                        if file_type is None:
                            continue

                        sha256 = compute_sha256(data)

                        # Embedded APK
                        has_code = True
                        if file_type == "APK" and not _CONVENTIONAL_DEX.match(filename):
                            has_code = False
                            try:
                                names = _nested_entry_names(data, self._limits)
                            except ExtractionError as exc:
                                has_code = True
                                warnings.append(
                                    f"Nested archive '{filename}' rejected by extraction "
                                    f"limits; treated as possibly containing code: {exc}"
                                )
                            except Exception:
                                _log.debug("Nested archive '%s' unreadable", filename)
                            else:
                                has_code = any(
                                    n.endswith(".dex")
                                    or (n.startswith("lib/") and n.endswith(".so"))
                                    for n in names
                                )
                            result.embedded_apks.append(
                                EmbeddedAPKInfo(
                                    path=filename,
                                    size=info.file_size,
                                    sha256=sha256,
                                    has_code=has_code,
                                )
                            )

                        # Embedded DEX outside conventional locations
                        if file_type == "DEX" and not _CONVENTIONAL_DEX.match(filename):
                            result.embedded_dex.append(
                                EmbeddedDEXInfo(
                                    path=filename,
                                    size=info.file_size,
                                    sha256=sha256,
                                )
                            )

                        # All executable-looking files (excluding conventional DEX)
                        if file_type in ("ELF", "DEX", "APK", "JAR", "script"):
                            # Skip conventional .so in lib/
                            if (
                                file_type == "ELF"
                                and filename.startswith("lib/")
                                and filename.endswith(".so")
                            ):
                                continue
                            # Skip conventional DEX
                            if file_type == "DEX" and _CONVENTIONAL_DEX.match(filename):
                                continue
                            # Skip code-free APKs
                            if file_type == "APK" and not has_code:
                                continue

                            result.executable_files.append(
                                ExecutableFileInfo(
                                    path=filename,
                                    size=info.file_size,
                                    sha256=sha256,
                                    detected_type=file_type,
                                )
                            )

                    except Exception as exc:
                        warnings.append(f"Could not inspect '{filename}' for embedded files: {exc}")

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Could not open APK for embedded file detection: {exc}")

        return result, warnings
