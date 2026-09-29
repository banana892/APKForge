"""Intake detection for Android packages and containers.

Determines whether a given path is an APK, APKS bundle, XAPK bundle,
or a directory of split APKs.

Validation is based on file structure and contents (magic bytes, ZIP entry
inspection, manifest presence) — NOT solely on file extensions.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from pydantic import BaseModel

from apkforge.core.logging import get_logger
from apkforge.intake import InputFormat, PackageType
from apkforge.intake.archive import is_zip_file

__all__ = ["DetectionResult", "PackageDetector", "detect_package_format"]

_log = get_logger(__name__)


class DetectionResult(BaseModel):
    """Result of package format detection.

    Attributes:
        format: Detailed input format classification.
        package_type: Top-level package type.
        is_valid: True if the input appears structurally valid for its format.
        reason: Explanation if invalid or unknown, or details about detection.
    """

    format: InputFormat
    package_type: PackageType
    is_valid: bool = True
    reason: str | None = None


class PackageDetector:
    """Detects and validates input package formats."""

    @classmethod
    def detect(cls, path: Path) -> DetectionResult:
        """Inspect *path* and classify its package format.

        Args:
            path: Path to inspect (file or directory).

        Returns:
            DetectionResult: Detected format, package type, validity, and details.
        """
        path = Path(path)

        if not path.exists():
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Path does not exist: {path}",
            )

        if path.is_dir():
            return cls._detect_directory(path)

        if path.is_file():
            return cls._detect_file(path)

        return DetectionResult(
            format=InputFormat.UNKNOWN,
            package_type=PackageType.UNKNOWN,
            is_valid=False,
            reason=f"Unsupported file system object: {path}",
        )

    @classmethod
    def _detect_directory(cls, dir_path: Path) -> DetectionResult:
        """Inspect a directory to see if it is a split APK collection."""
        try:
            apk_files = [p for p in dir_path.glob("*.apk") if p.is_file()]
        except OSError as exc:
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Cannot read directory {dir_path}: {exc}",
            )

        if not apk_files:
            return DetectionResult(
                format=InputFormat.UNKNOWN,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Directory contains no .apk files: {dir_path}",
            )

        return DetectionResult(
            format=InputFormat.SPLIT_DIRECTORY,
            package_type=PackageType.SPLIT,
            is_valid=True,
            reason=f"Directory contains {len(apk_files)} APK file(s)",
        )

    @classmethod
    def _detect_file(cls, file_path: Path) -> DetectionResult:
        """Inspect a file (ZIP-based container or APK)."""
        try:
            stat = file_path.stat()
            if stat.st_size == 0:
                return DetectionResult(
                    format=InputFormat.INVALID,
                    package_type=PackageType.UNKNOWN,
                    is_valid=False,
                    reason=f"File is empty: {file_path.name}",
                )
        except OSError as exc:
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Cannot access file {file_path}: {exc}",
            )

        if not is_zip_file(file_path):
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"File is not a valid ZIP-compatible archive: {file_path.name}",
            )

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
        except zipfile.BadZipFile as exc:
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Corrupt archive: {exc}",
            )
        except OSError as exc:
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.UNKNOWN,
                is_valid=False,
                reason=f"Cannot open archive: {exc}",
            )

        names_set = set(namelist)
        apk_entries = [n for n in namelist if n.lower().endswith(".apk")]

        # 1. Check for XAPK bundle:
        # XAPK archives usually contain manifest.json at root and .apk files.
        if "manifest.json" in names_set:
            try:
                manifest_data = zf.read("manifest.json")
                manifest_json = json.loads(manifest_data.decode("utf-8", errors="replace"))
                if isinstance(manifest_json, dict) and (
                    "package_name" in manifest_json or "split_apks" in manifest_json or apk_entries
                ):
                    return DetectionResult(
                        format=InputFormat.XAPK_BUNDLE,
                        package_type=PackageType.XAPK,
                        is_valid=True,
                        reason="XAPK bundle identified by manifest.json and APK entries",
                    )
            except Exception as exc:
                _log.debug("Failed parsing manifest.json in %s: %s", file_path.name, exc)

        # 2. Check for APKS bundle:
        has_splits = apk_entries and any(n.startswith("splits/") for n in apk_entries)
        if "toc.pb" in names_set or has_splits:
            return DetectionResult(
                format=InputFormat.APKS_BUNDLE,
                package_type=PackageType.APKS,
                is_valid=True,
                reason="APKS bundle identified by bundletool structure",
            )

        # If it has multiple APKs inside and ends with .apks or .xapk, or has multiple APKs:
        suffix = file_path.suffix.lower()
        if suffix == ".xapk" and apk_entries:
            return DetectionResult(
                format=InputFormat.XAPK_BUNDLE,
                package_type=PackageType.XAPK,
                is_valid=True,
                reason="XAPK container with contained APKs",
            )

        if suffix == ".apks" and apk_entries:
            return DetectionResult(
                format=InputFormat.APKS_BUNDLE,
                package_type=PackageType.APKS,
                is_valid=True,
                reason="APKS container with contained APKs",
            )

        if len(apk_entries) > 1 and "AndroidManifest.xml" not in names_set:
            # Multi-APK archive without root AndroidManifest.xml
            return DetectionResult(
                format=InputFormat.APKS_BUNDLE,
                package_type=PackageType.APKS,
                is_valid=True,
                reason="Multi-APK archive",
            )

        # 3. Check for Single APK:
        # Must contain AndroidManifest.xml at root of archive
        if "AndroidManifest.xml" in names_set:
            return DetectionResult(
                format=InputFormat.SINGLE_APK,
                package_type=PackageType.APK,
                is_valid=True,
                reason="Single APK with root AndroidManifest.xml",
            )

        # ZIP archive but lacks AndroidManifest.xml and contains no APKs
        if suffix == ".apk":
            return DetectionResult(
                format=InputFormat.INVALID,
                package_type=PackageType.APK,
                is_valid=False,
                reason="Archive has .apk extension but lacks AndroidManifest.xml",
            )

        return DetectionResult(
            format=InputFormat.UNKNOWN,
            package_type=PackageType.UNKNOWN,
            is_valid=False,
            reason="Archive does not contain Android package components",
        )


def detect_package_format(path: Path) -> DetectionResult:
    """Convenience helper to detect package format."""
    return PackageDetector.detect(path)
