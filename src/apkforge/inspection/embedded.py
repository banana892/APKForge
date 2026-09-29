"""Embedded file inspector — detection of embedded APKs, DEX, and executables.

Detects APK files, DEX files outside conventional locations, and other
executable-looking files inside the APK.

Detection is based on file structure/signatures, not filenames alone.

Security invariant: Embedded files are never executed or recursively
unpacked beyond detection.
"""

from __future__ import annotations

import contextlib
import io
import re
import zipfile
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    EmbeddedAPKInfo,
    EmbeddedDEXInfo,
    EmbeddedFileInspection,
    ExecutableFileInfo,
)
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


def _detect_file_type(data: bytes, filename: str) -> str | None:
    """Detect the file type from magic bytes and extension."""
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
                with (
                    contextlib.suppress(Exception),
                    zipfile.ZipFile(io.BytesIO(data), "r") as inner_zf,
                ):
                    if "AndroidManifest.xml" in inner_zf.namelist():
                        return "APK"
                    if any(n.endswith(".class") for n in inner_zf.namelist()):
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
    """Detects embedded APKs, DEX files, and executables inside an APK."""

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
                        file_type = _detect_file_type(data, filename)

                        if file_type is None:
                            continue

                        sha256 = compute_sha256(data)

                        # Embedded APK
                        if file_type == "APK" and not _CONVENTIONAL_DEX.match(filename):
                            result.embedded_apks.append(
                                EmbeddedAPKInfo(
                                    path=filename,
                                    size=info.file_size,
                                    sha256=sha256,
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
