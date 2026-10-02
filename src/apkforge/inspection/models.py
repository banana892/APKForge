"""APKForge inspection data models — Phase 2.

Structured Pydantic models representing the output of every inspector.
All models are serialisable to JSON and designed so that evidence can be
cross-referenced (e.g. Permission → Component → Class → Method → API reference).

Security invariant
------------------
These models describe APK contents.  They do NOT establish that an
application is malicious or safe.
"""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - required at runtime by Pydantic

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus
from apkforge.intake import (
    AndroidPackage,
    APKMetadata,
    FileHashes,
    PackageType,
)

__all__ = [
    "ActivityInfo",
    "ApplicationInfo",
    "AssetEntry",
    "AssetInspection",
    "BroadcastReceiverInfo",
    "ClassInfo",
    "ContentProviderInfo",
    "DEXClassInventory",
    "DEXFileInspection",
    "DEXInspection",
    "DomainReference",
    "EmbeddedAPKInfo",
    "EmbeddedDEXInfo",
    "EmbeddedFileInspection",
    "EvidenceSource",
    "ExecutableFileInfo",
    "FieldInfo",
    "IPAddressReference",
    "InspectionResult",
    "IntentDataInfo",
    "IntentFilterInfo",
    "ManifestInspection",
    "MethodInfo",
    "NativeInspection",
    "NativeLibraryInspection",
    "NativeStringReference",
    "NetworkInspection",
    "ObfuscationIndicators",
    "ObfuscationInspection",
    "PermissionInfo",
    "ResourceInspection",
    "ResourceTypeCount",
    "ServiceInfo",
    "StringReference",
    "URLReference",
]


# ===========================================================================
# Evidence provenance
# ===========================================================================


class EvidenceSource(BaseModel):
    """Source location for an extracted item.

    Provides provenance so that future security findings are explainable.
    """

    file: str = Field(description="Source file (e.g. 'classes.dex', 'AndroidManifest.xml').")
    offset: int | None = Field(default=None, description="Byte offset if available.")
    class_name: str | None = Field(default=None, description="Class name if available.")
    method_name: str | None = Field(default=None, description="Method name if available.")


# ===========================================================================
# Intent filter models
# ===========================================================================


class IntentDataInfo(BaseModel):
    """Data element within an intent filter."""

    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_prefix: str | None = Field(default=None, alias="pathPrefix")
    path_pattern: str | None = Field(default=None, alias="pathPattern")
    mime_type: str | None = Field(default=None, alias="mimeType")

    model_config = {"populate_by_name": True}


class IntentFilterInfo(BaseModel):
    """Structural representation of an Android intent filter."""

    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    data: list[IntentDataInfo] = Field(default_factory=list)


# ===========================================================================
# Manifest component models
# ===========================================================================


class PermissionInfo(BaseModel):
    """A declared or used permission."""

    name: str
    protection_level: str | None = None


class ActivityInfo(BaseModel):
    """An activity declared in the manifest."""

    name: str
    exported: bool | None = None
    permission: str | None = None
    enabled: bool | None = None
    direct_boot_aware: bool | None = None
    process: str | None = None
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)


class ServiceInfo(BaseModel):
    """A service declared in the manifest."""

    name: str
    exported: bool | None = None
    permission: str | None = None
    enabled: bool | None = None
    foreground_service_type: str | None = None
    process: str | None = None
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)


class BroadcastReceiverInfo(BaseModel):
    """A broadcast receiver declared in the manifest."""

    name: str
    exported: bool | None = None
    permission: str | None = None
    enabled: bool | None = None
    process: str | None = None
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)


class ContentProviderInfo(BaseModel):
    """A content provider declared in the manifest."""

    name: str
    authorities: str | None = None
    exported: bool | None = None
    enabled: bool | None = None
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    grant_uri_permissions: bool | None = None
    process: str | None = None


class ApplicationInfo(BaseModel):
    """Application-level attributes from the manifest.

    Uses a tri-state representation: ``None`` means the attribute is absent
    from the manifest (unknown), ``True``/``False`` means explicitly set.
    """

    label: str | None = None
    icon: str | None = None
    theme: str | None = None
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    extract_native_libs: bool | None = None
    large_heap: bool | None = None
    test_only: bool | None = None


# ===========================================================================
# Manifest inspection result
# ===========================================================================


class ManifestInspection(BaseModel):
    """Complete manifest inspection result."""

    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None

    permissions: list[PermissionInfo] = Field(default_factory=list)
    declared_permissions: list[PermissionInfo] = Field(default_factory=list)
    activities: list[ActivityInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    receivers: list[BroadcastReceiverInfo] = Field(default_factory=list)
    providers: list[ContentProviderInfo] = Field(default_factory=list)
    application: ApplicationInfo = Field(default_factory=ApplicationInfo)
    resource_map: dict[str, str] = Field(default_factory=dict)


# ===========================================================================
# DEX inspection models
# ===========================================================================


class FieldInfo(BaseModel):
    """A field in a DEX class."""

    name: str
    class_name: str
    type: str
    access_flags: str = ""


class MethodInfo(BaseModel):
    """A method in a DEX class."""

    name: str
    class_name: str
    return_type: str = ""
    parameters: list[str] = Field(default_factory=list)
    access_flags: str = ""
    code_hash: str | None = None


class ClassInfo(BaseModel):
    """A class in a DEX file."""

    name: str
    superclass: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    access_flags: str = ""
    method_count: int = 0
    field_count: int = 0


class DEXClassInventory(BaseModel):
    """Detailed class/method/field inventory for a DEX file."""

    classes: list[ClassInfo] = Field(default_factory=list)
    methods: list[MethodInfo] = Field(default_factory=list)
    fields: list[FieldInfo] = Field(default_factory=list)


class DEXFileInspection(BaseModel):
    """Inspection result for a single DEX file."""

    path: str
    size: int
    sha256: str
    dex_version: str | None = None
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    inventory: DEXClassInventory = Field(default_factory=DEXClassInventory)
    api_references: list[str] = Field(default_factory=list)

    @property
    def name(self) -> str:
        """Name of the DEX file (e.g. 'classes.dex')."""
        return self.path

    @property
    def file_size(self) -> int:
        """Alias for size."""
        return self.size


class StringReference(BaseModel):
    """A string extracted from a DEX file with provenance."""

    value: str
    dex_file: str
    class_name: str | None = None
    method_name: str | None = None


class DEXInspection(BaseModel):
    """Combined DEX inspection result."""

    dex_files: list[DEXFileInspection] = Field(default_factory=list)
    total_classes: int = 0
    total_methods: int = 0
    total_fields: int = 0
    strings: list[StringReference] = Field(default_factory=list)


# ===========================================================================
# Network extraction models
# ===========================================================================


class URLReference(BaseModel):
    """A URL extracted from the APK with provenance."""

    url: str
    source: EvidenceSource


class DomainReference(BaseModel):
    """A domain name extracted from the APK."""

    domain: str
    sources: list[EvidenceSource] = Field(default_factory=list)


class IPAddressReference(BaseModel):
    """An IP address extracted from the APK."""

    address: str
    version: int = Field(description="IP version: 4 or 6.")
    sources: list[EvidenceSource] = Field(default_factory=list)


class NetworkInspection(BaseModel):
    """Network-related data extracted from the APK."""

    urls: list[URLReference] = Field(default_factory=list)
    domains: list[DomainReference] = Field(default_factory=list)
    ip_addresses: list[IPAddressReference] = Field(default_factory=list)


# ===========================================================================
# Native library inspection models
# ===========================================================================


class NativeStringReference(BaseModel):
    """A string extracted from a native library."""

    library: str
    offset: int | None = None
    value: str


class NativeLibraryInspection(BaseModel):
    """Inspection result for a single native library."""

    path: str
    size: int
    sha256: str
    abi: str | None = None
    elf_class: str | None = Field(default=None, description="ELF class: ELF32 or ELF64.")
    endianness: str | None = None
    machine_type: str | None = None
    elf_type: str | None = None
    sections: list[str] = Field(default_factory=list)
    dynamic_dependencies: list[str] = Field(default_factory=list)
    exported_symbols: list[str] = Field(default_factory=list)
    imported_symbols: list[str] = Field(default_factory=list)
    strings: list[NativeStringReference] = Field(default_factory=list)

    @property
    def name(self) -> str:
        """Library filename (e.g. 'libnative.so')."""
        return Path(self.path).name

    @property
    def file_size(self) -> int:
        """Alias for size."""
        return self.size



class NativeInspection(BaseModel):
    """Combined native library inspection result."""

    libraries: list[NativeLibraryInspection] = Field(default_factory=list)
    total_libraries: int = 0
    abis_found: list[str] = Field(default_factory=list)


# ===========================================================================
# Resource inspection models
# ===========================================================================


class ResourceTypeCount(BaseModel):
    """Count of resources of a specific type."""

    resource_type: str
    count: int


class ResourceInspection(BaseModel):
    """Resource structure inspection result."""

    has_resources_arsc: bool = False
    resource_file_count: int = 0
    resource_types: list[ResourceTypeCount] = Field(default_factory=list)
    resource_files: list[str] = Field(default_factory=list)


# ===========================================================================
# Asset inspection models
# ===========================================================================


class AssetEntry(BaseModel):
    """An asset file inside the APK."""

    path: str
    size: int
    sha256: str | None = None
    mime_type: str | None = None
    entropy: float | None = Field(
        default=None,
        description="Shannon entropy estimate (0.0-8.0). High values may indicate encryption.",
    )


class AssetInspection(BaseModel):
    """Asset directory inspection result."""

    total_assets: int = 0
    assets: list[AssetEntry] = Field(default_factory=list)


# ===========================================================================
# Embedded file detection models
# ===========================================================================


class EmbeddedAPKInfo(BaseModel):
    """An APK file embedded inside the main APK."""

    path: str
    size: int
    sha256: str
    has_code: bool = True


class EmbeddedDEXInfo(BaseModel):
    """A DEX file found outside conventional classes*.dex locations."""

    path: str
    size: int
    sha256: str


class ExecutableFileInfo(BaseModel):
    """An executable-looking file inside the APK."""

    path: str
    size: int
    sha256: str | None = None
    detected_type: str = Field(
        description="Detected file type (e.g. 'ELF', 'DEX', 'JAR', 'APK', 'script')."
    )


class EmbeddedFileInspection(BaseModel):
    """Embedded and executable file detection results."""

    embedded_apks: list[EmbeddedAPKInfo] = Field(default_factory=list)
    embedded_dex: list[EmbeddedDEXInfo] = Field(default_factory=list)
    executable_files: list[ExecutableFileInfo] = Field(default_factory=list)


# ===========================================================================
# Obfuscation indicator models
# ===========================================================================


class ObfuscationIndicators(BaseModel):
    """Quantitative obfuscation indicators.

    These are structural observations, NOT malware verdicts.
    """

    short_class_name_pct: float = Field(
        default=0.0,
        description="Percentage of sampled class names with <= 2 characters.",
    )
    short_method_name_pct: float = Field(
        default=0.0,
        description="Percentage of sampled method names with <= 2 characters.",
    )
    short_field_name_pct: float = Field(
        default=0.0,
        description="Percentage of sampled field names with <= 2 characters.",
    )
    total_classes_sampled: int = 0
    total_methods_sampled: int = 0
    total_fields_sampled: int = 0
    observations: list[str] = Field(
        default_factory=list,
        description="Human-readable observations about naming patterns.",
    )


class ObfuscationInspection(BaseModel):
    """Obfuscation inspection result.

    IMPORTANT: Obfuscation does NOT equal malicious intent.  ProGuard/R8
    obfuscation is standard practice for production Android apps.  These
    indicators are structural observations that support further analysis.
    """

    indicators: ObfuscationIndicators = Field(default_factory=ObfuscationIndicators)
    is_likely_obfuscated: bool = Field(
        default=False,
        description="Whether structural indicators suggest obfuscation.  "
        "This is NOT a malware verdict.",
    )


# ===========================================================================
# Top-level inspection result
# ===========================================================================


class PackageInventory(BaseModel):
    """High-level content summary of the APK."""

    manifest_count: int = 0
    dex_count: int = 0
    native_library_count: int = 0
    resource_count: int = 0
    asset_count: int = 0
    embedded_apk_count: int = 0
    embedded_dex_count: int = 0
    executable_file_count: int = 0
    certificate_count: int = 0
    total_file_count: int = 0


class InspectionResult(BaseModel):
    """Top-level inspection result aggregating all inspector outputs.

    This model is the contract between the inspection engine and all
    downstream consumers (CLI, JSON, future GUI, future reports, future
    diff engine).

    Security invariant: Phase 2 describes APK contents.  It does NOT
    establish that an application is malicious or safe.
    """

    status: AnalysisStatus = AnalysisStatus.FAILED
    input_path: Path | None = None
    package_type: PackageType = PackageType.APK
    metadata: APKMetadata = Field(default_factory=APKMetadata)
    hashes: FileHashes | None = None
    package: AndroidPackage | None = None

    inventory: PackageInventory = Field(default_factory=PackageInventory)
    manifest: ManifestInspection | None = None
    dex: DEXInspection | None = None
    native: NativeInspection | None = None
    resources: ResourceInspection | None = None
    assets: AssetInspection | None = None
    network: NetworkInspection | None = None
    embedded: EmbeddedFileInspection | None = None
    obfuscation: ObfuscationInspection | None = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    inspector_statuses: dict[str, str] = Field(
        default_factory=dict,
        description="Per-inspector status (e.g. {'manifest': 'complete', 'dex': 'partial'}).",
    )

    model_config = {"arbitrary_types_allowed": True}
