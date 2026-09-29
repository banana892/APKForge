"""Data models for Phase 1: Intake & Identification subsystem.

Re-exports normalized package and intake models defined in apkforge.intake.
"""

from __future__ import annotations

from apkforge.intake import (
    AndroidPackage,
    DetectionResult,
    DEXFile,
    FileCategory,
    FileHashes,
    InputFormat,
    NativeLibrary,
    PackageFile,
    PackageIdentity,
    PackageType,
    SigningCertificate,
    SplitAPKInfo,
    SplitType,
)

__all__ = [
    "AndroidPackage",
    "DEXFile",
    "DetectionResult",
    "FileCategory",
    "FileHashes",
    "InputFormat",
    "NativeLibrary",
    "PackageFile",
    "PackageIdentity",
    "PackageType",
    "SigningCertificate",
    "SplitAPKInfo",
    "SplitType",
]
