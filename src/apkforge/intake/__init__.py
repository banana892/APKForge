"""APKForge intake data models — Phase 1.

These models represent the normalized output of the APK intake pipeline.
All intake handlers (APK, APKS, XAPK, Split) produce the same
:class:`AndroidPackage` model so that downstream consumers never need to
know the original input format.

Enums
-----
:class:`PackageType` — The detected input format.
:class:`InputFormat` — Detailed format classification.
:class:`FileCategory` — Classification of a file inside an APK.
:class:`SplitType` — Classification of a split APK.

Models
------
:class:`FileHashes` — MD5 + SHA-1 + SHA-256 digests.
:class:`PackageFile` — An entry inside an APK archive.
:class:`DEXFile` — A classes*.dex file.
:class:`NativeLibrary` — A .so native library.
:class:`SigningCertificate` — X.509 certificate from APK signing.
:class:`SplitAPKInfo` — Metadata for one split of a split-APK application.
:class:`PackageIdentity` — Stable identity (package name + version).
:class:`AndroidPackage` — The top-level normalized package model.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 - required at runtime by Pydantic
from enum import StrEnum
from pathlib import Path  # noqa: TC003 - required at runtime by Pydantic
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus

__all__ = [
    "APKIntakeService",
    "AndroidPackage",
    "DEXFile",
    "DetectionResult",
    "FileCategory",
    "FileHashes",
    "InputFormat",
    "NativeLibrary",
    "PackageDetector",
    "PackageFile",
    "PackageIdentity",
    "PackageType",
    "SigningCertificate",
    "SplitAPKInfo",
    "SplitType",
    "detect_package_format",
]


# ===========================================================================
# Enums
# ===========================================================================


class PackageType(StrEnum):
    """Detected package type."""

    APK = "apk"
    APKS = "apks"
    XAPK = "xapk"
    SPLIT = "split"
    UNKNOWN = "unknown"


class InputFormat(StrEnum):
    """Detailed input format classification from the detector."""

    SINGLE_APK = "single_apk"
    APKS_BUNDLE = "apks_bundle"
    XAPK_BUNDLE = "xapk_bundle"
    SPLIT_DIRECTORY = "split_directory"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class FileCategory(StrEnum):
    """Classification of a file entry inside an APK."""

    MANIFEST = "manifest"
    DEX = "dex"
    RESOURCE_TABLE = "resource_table"
    RESOURCE = "resource"
    ASSET = "asset"
    NATIVE_LIB = "native_lib"
    SIGNATURE = "signature"
    CERTIFICATE = "certificate"
    KOTLIN_MODULE = "kotlin_module"
    OTHER = "other"


class SplitType(StrEnum):
    """Classification of a split APK within a collection."""

    BASE = "base"
    CONFIGURATION = "configuration"
    FEATURE = "feature"
    UNKNOWN = "unknown"


# ===========================================================================
# Data models
# ===========================================================================


class FileHashes(BaseModel):
    """Cryptographic hashes of a file.

    All hashes are lowercase hex-encoded strings computed from the original
    file bytes (not from a transformed/extracted copy).
    """

    md5: str = Field(description="MD5 hex digest.")
    sha1: str = Field(description="SHA-1 hex digest.")
    sha256: str = Field(description="SHA-256 hex digest.")


class PackageFile(BaseModel):
    """An entry inside an APK archive.

    Attributes:
        path: ZIP entry path (e.g. ``classes.dex``, ``lib/arm64-v8a/libnative.so``).
        size: Uncompressed size in bytes.
        compressed_size: Compressed size in the archive (may equal *size*).
        category: Classification of this file.
        sha256: SHA-256 hex digest of the entry's contents (may be None if
            not computed during intake).
    """

    path: str
    size: int = Field(ge=0)
    compressed_size: int | None = Field(default=None, ge=0)
    category: FileCategory
    sha256: str | None = None


class DEXFile(BaseModel):
    """A Dalvik Executable file inside an APK.

    Phase 1 records identity only.  Deep DEX analysis belongs to Phase 2+.
    """

    path: str = Field(description="ZIP entry path (e.g. ``classes.dex``).")
    size: int = Field(ge=0, description="Uncompressed size in bytes.")
    sha256: str = Field(description="SHA-256 hex digest.")


class NativeLibrary(BaseModel):
    """A native shared library (``.so``) inside an APK.

    Attributes:
        path: ZIP entry path (e.g. ``lib/arm64-v8a/libfoo.so``).
        size: Uncompressed size in bytes.
        sha256: SHA-256 hex digest.
        abi: Android ABI inferred from the path (e.g. ``arm64-v8a``).
    """

    path: str
    size: int = Field(ge=0)
    sha256: str
    abi: str | None = Field(
        default=None,
        description="ABI inferred from path (e.g. 'arm64-v8a').",
    )


class SigningCertificate(BaseModel):
    """X.509 certificate information from APK signing.

    A valid signature establishes signing identity.  It does NOT establish
    that the application is safe.

    Attributes:
        subject: Certificate subject DN.
        issuer: Certificate issuer DN.
        serial_number: Certificate serial number (hex).
        not_before: Certificate validity start.
        not_after: Certificate validity end.
        sha256_fingerprint: SHA-256 fingerprint of the DER-encoded certificate.
        sha1_fingerprint: SHA-1 fingerprint of the DER-encoded certificate.
        signature_version: Signing scheme version if detectable (v1, v2, v3).
        extraction_backend: Which extraction strategy produced this record
            (``"androguard"`` or ``"pkcs7_fallback"``).
        extraction_notes: Informational notes about how the record was obtained,
            e.g. a recoverable primary-backend failure that the PKCS#7 fallback
            recovered from.  Notes never affect intake status.
    """

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha256_fingerprint: str | None = None
    sha1_fingerprint: str | None = None
    signature_version: str | None = None
    extraction_backend: str | None = None
    extraction_notes: list[str] = Field(default_factory=list)


class SplitAPKInfo(BaseModel):
    """Metadata for one split of a split-APK application.

    Attributes:
        name: Split identifier (e.g. ``base``, ``config.arm64_v8a``).
        path: Path to the APK file on disk.
        split_type: BASE, CONFIGURATION, FEATURE, or UNKNOWN.
        hashes: Cryptographic hashes of this split APK file.
        package_name: Package name extracted from this split's manifest.
        metadata: Additional metadata extracted from this split (may be sparse
            for configuration splits).
    """

    name: str
    path: Path
    split_type: SplitType
    hashes: FileHashes
    package_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PackageIdentity(BaseModel):
    """Stable identity for an Android package.

    Two APKs belong to the same application if they share the same
    ``package_name``.  Version information disambiguates releases.
    """

    package_name: str = Field(description="Android package name (e.g. ``com.example.app``).")
    version_name: str | None = Field(default=None, description="Human-readable version string.")
    version_code: int | None = Field(default=None, description="Integer version code.")

    def same_application(self, other: PackageIdentity) -> bool:
        """Return True if both identities represent the same application."""
        return self.package_name == other.package_name


class APKMetadata(BaseModel):
    """Metadata extracted from an APK's AndroidManifest.xml.

    Phase 1 captures identification-level metadata only.  Permissions,
    components, and intent filters belong to Phase 2+.

    Attributes:
        package_name: Android package name.
        version_name: Human-readable version string.
        version_code: Integer version code.
        min_sdk: Minimum SDK version required.
        target_sdk: Target SDK version.
        compile_sdk: Compile SDK version if available.
        application_label: Application label if available.
        application_debuggable: Whether the app is marked debuggable.
    """

    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    application_label: str | None = None
    application_debuggable: bool | None = None


# ===========================================================================
# Top-level normalized model
# ===========================================================================


class AndroidPackage(BaseModel):
    """Normalized representation of an Android application package.

    This is the primary output of the Phase 1 intake pipeline.  Every handler
    (APK, APKS, XAPK, Split) produces an :class:`AndroidPackage` so that
    downstream consumers never need to know the original input format.

    Attributes:
        input_path: Original input path (file or directory).
        package_type: Detected package type (APK, APKS, XAPK, SPLIT).
        input_format: Detailed format classification.
        hashes: Cryptographic hashes of the primary input file.
        metadata: APK metadata from the manifest.
        identity: Stable package identity (for comparison).
        certificates: Signing certificate information.
        files: Structural inventory of the APK.
        dex_files: DEX file inventory.
        native_libraries: Native library inventory.
        splits: Split APK components (populated for APKS/XAPK/SPLIT types).
        status: COMPLETE, PARTIAL, or FAILED.
        warnings: Non-fatal issues encountered during intake.
        errors: Fatal errors encountered during intake.
        extra: Additional format-specific metadata (e.g. XAPK manifest data).
        workspace_root: Intake workspace retained for the caller (``keep_workspace=True``);
            the caller owns it and must remove it.  ``None`` when intake cleaned it up.
    """

    input_path: Path
    package_type: PackageType
    input_format: InputFormat
    hashes: FileHashes | None = None
    metadata: APKMetadata = Field(default_factory=APKMetadata)
    identity: PackageIdentity | None = None
    certificates: list[SigningCertificate] = Field(default_factory=list)
    files: list[PackageFile] = Field(default_factory=list)
    dex_files: list[DEXFile] = Field(default_factory=list)
    native_libraries: list[NativeLibrary] = Field(default_factory=list)
    splits: list[SplitAPKInfo] = Field(default_factory=list)
    status: AnalysisStatus = AnalysisStatus.FAILED
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
    workspace_root: Path | None = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    @property
    def is_split_app(self) -> bool:
        """Return True if this package contains multiple APK splits."""
        return len(self.splits) > 0

    @property
    def all_findings_count(self) -> int:
        """Return total count of warnings + errors."""
        return len(self.warnings) + len(self.errors)


from apkforge.intake.detector import (  # noqa: E402
    DetectionResult,
    PackageDetector,
    detect_package_format,
)
from apkforge.intake.service import APKIntakeService  # noqa: E402
