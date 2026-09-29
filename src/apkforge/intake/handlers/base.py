"""Base class and common utilities for package handlers."""

from __future__ import annotations

import abc
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.intake import (
    AndroidPackage,
    APKMetadata,
    DEXFile,
    NativeLibrary,
    PackageFile,
    SigningCertificate,
    SplitType,
)
from apkforge.intake.certificates import extract_certificates
from apkforge.intake.inventory import build_inventory
from apkforge.intake.manifest import parse_apk_manifest

if TYPE_CHECKING:
    from apkforge.core.config import ExtractionLimits
    from apkforge.core.workspace import Workspace
    from apkforge.intake.detector import DetectionResult

__all__ = ["BasePackageHandler", "classify_split_type", "inspect_single_apk"]

_log = get_logger(__name__)


def classify_split_type(filename: str) -> SplitType:
    """Classify the type of a split APK based on its filename."""
    stem = Path(filename).stem.lower()

    if stem in ("base", "base-master", "standalone", "universal"):
        return SplitType.BASE

    if (
        stem.startswith("config.")
        or "arm64" in stem
        or "armeabi" in stem
        or "x86" in stem
        or "hdpi" in stem
        or "mdpi" in stem
        or "ldpi" in stem
        or "xhdpi" in stem
        or "xxhdpi" in stem
        or "xxxhdpi" in stem
        or any(stem.endswith(f".{lang}") for lang in ("en", "es", "fr", "de", "zh", "ja", "ru"))
    ):
        return SplitType.CONFIGURATION

    if stem.startswith("feature_") or stem.startswith("split_") or "dynamic" in stem:
        return SplitType.FEATURE

    return SplitType.UNKNOWN


def inspect_single_apk(
    apk_path: Path,
) -> tuple[
    APKMetadata,
    list[SigningCertificate],
    list[PackageFile],
    list[DEXFile],
    list[NativeLibrary],
    list[str],
]:
    """Extract metadata, certificates, and inventory for a single APK.

    Args:
        apk_path: Path to the APK on disk.

    Returns:
        Tuple of (metadata, certificates, files, dex_files, native_libraries, warnings).
    """
    all_warnings: list[str] = []

    # 1. Manifest parsing
    metadata, manifest_warnings = parse_apk_manifest(apk_path)
    all_warnings.extend(manifest_warnings)

    # 2. Certificates
    certs, cert_warnings = extract_certificates(apk_path)
    all_warnings.extend(cert_warnings)

    # 3. Structural inventory
    files, dex_files, native_libs, inv_warnings = build_inventory(apk_path)
    all_warnings.extend(inv_warnings)

    return metadata, certs, files, dex_files, native_libs, all_warnings


class BasePackageHandler(abc.ABC):
    """Abstract base class for all intake handlers."""

    @classmethod
    @abc.abstractmethod
    def can_handle(cls, detection: DetectionResult) -> bool:
        """Return True if this handler can process the detected input."""
        raise NotImplementedError

    @abc.abstractmethod
    def process(
        self,
        input_path: Path,
        workspace: Workspace,
        limits: ExtractionLimits,
    ) -> AndroidPackage:
        """Process the input package into a normalized :class:`AndroidPackage`.

        Args:
            input_path: Path to the original input file or directory.
            workspace: The isolated workspace session.
            limits: Security limits for archive operations.

        Returns:
            AndroidPackage: Normalized package representation.
        """
        raise NotImplementedError

    def _stage_file(self, src: Path, dest: Path) -> Path:
        """Copy *src* into workspace *dest* using streaming chunked copy."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        with src.open("rb") as s, dest.open("wb") as d:
            while chunk := s.read(128 * 1024):
                d.write(chunk)
        return dest
