"""APKForge diff data models — Phase 3.

Structured Pydantic models representing the differences between two APK packages.
All models are serialisable to JSON, deterministic, and evidence-oriented.

Security Invariants:
--------------------
- Purely static and descriptive.
- No security or privacy risk scoring (neutral categorization only).
- No malware or safety conclusions.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus

__all__ = [
    "AssetDiff",
    "AssetEntropyChange",
    "CertificateDiff",
    "ChangeType",
    "ClassDiff",
    "ComponentChange",
    "ComponentDiff",
    "DEXDiff",
    "DiffChange",
    "DiffResult",
    "DiffSummary",
    "FieldDiff",
    "FileDiff",
    "FileEntryDiff",
    "IdentityDiff",
    "IntentFilterDiff",
    "ManifestDiff",
    "MethodDiff",
    "NativeDiff",
    "NativeLibraryDiff",
    "NetworkDiff",
    "PackageIdentity",
    "PermissionDiff",
    "ResourceDiff",
    "SignificanceCategory",
    "StringDiff",
    "URLDiffItem",
]


class ChangeType(StrEnum):
    """Categorisation of a change between two entities."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    RENAMED = "renamed"


class SignificanceCategory(StrEnum):
    """Neutral category classifying the layer where a change occurred."""

    FILE = "FILE"
    STRUCTURAL = "STRUCTURAL"
    METADATA = "METADATA"
    CODE = "CODE"
    NETWORK = "NETWORK"
    SIGNATURE = "SIGNATURE"


class DiffChange(BaseModel):
    """Generic atomic change between before and after values."""

    change_type: ChangeType
    category: str
    identifier: str
    before: Any | None = None
    after: Any | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PackageIdentity(BaseModel):
    """Identity descriptors for one APK being compared."""

    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    sha256: str | None = None
    file_name: str | None = None


class IdentityDiff(BaseModel):
    """Differences in application identity between two packages."""

    is_same_package: bool = True
    package_name_change: DiffChange | None = None
    version_name_change: DiffChange | None = None
    version_code_change: DiffChange | None = None
    min_sdk_change: DiffChange | None = None
    target_sdk_change: DiffChange | None = None
    changes: list[DiffChange] = Field(default_factory=list)


class FileEntryDiff(BaseModel):
    """Difference details for a single file entry in the archive."""

    path: str
    change_type: ChangeType
    size_before: int | None = None
    size_after: int | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None
    category: str = "other"
    old_path: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class FileDiff(BaseModel):
    """File-level differences between the two packages."""

    total_added: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_renamed: int = 0
    total_unchanged: int = 0
    entries: list[FileEntryDiff] = Field(default_factory=list)


class ManifestDiff(BaseModel):
    """Application-level and manifest attribute differences."""

    attribute_changes: list[DiffChange] = Field(default_factory=list)
    sdk_changes: list[DiffChange] = Field(default_factory=list)


class PermissionDiff(BaseModel):
    """Differences in requested and custom declared permissions."""

    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    declared_added: list[str] = Field(default_factory=list)
    declared_removed: list[str] = Field(default_factory=list)
    declared_modified: list[DiffChange] = Field(default_factory=list)


class IntentFilterDiff(BaseModel):
    """Differences inside an intent filter."""

    actions_added: list[str] = Field(default_factory=list)
    actions_removed: list[str] = Field(default_factory=list)
    categories_added: list[str] = Field(default_factory=list)
    categories_removed: list[str] = Field(default_factory=list)
    data_added: list[dict[str, Any]] = Field(default_factory=list)
    data_removed: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Return True if any intent filter element changed."""
        return bool(
            self.actions_added
            or self.actions_removed
            or self.categories_added
            or self.categories_removed
            or self.data_added
            or self.data_removed
        )


class ComponentChange(BaseModel):
    """Change record for an Android component."""

    name: str
    component_type: str  # activity, service, receiver, provider
    change_type: ChangeType
    exported_before: bool | None = None
    exported_after: bool | None = None
    permission_before: str | None = None
    permission_after: str | None = None
    enabled_before: bool | None = None
    enabled_after: bool | None = None
    intent_filter_diff: IntentFilterDiff | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ComponentDiff(BaseModel):
    """Differences across all Android application components."""

    activities: list[ComponentChange] = Field(default_factory=list)
    services: list[ComponentChange] = Field(default_factory=list)
    receivers: list[ComponentChange] = Field(default_factory=list)
    providers: list[ComponentChange] = Field(default_factory=list)
    total_added: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_unchanged: int = 0


class MethodDiff(BaseModel):
    """Difference details for a single method."""

    class_name: str
    method_name: str
    change_type: ChangeType
    return_type_before: str | None = None
    return_type_after: str | None = None
    parameters_before: list[str] = Field(default_factory=list)
    parameters_after: list[str] = Field(default_factory=list)
    access_flags_before: str | None = None
    access_flags_after: str | None = None
    code_hash_before: str | None = None
    code_hash_after: str | None = None
    code_changed: bool = False


class FieldDiff(BaseModel):
    """Difference details for a single field."""

    class_name: str
    field_name: str
    change_type: ChangeType
    type_before: str | None = None
    type_after: str | None = None
    access_flags_before: str | None = None
    access_flags_after: str | None = None


class ClassDiff(BaseModel):
    """Differences inside a matched class."""

    class_name: str
    change_type: ChangeType
    superclass_before: str | None = None
    superclass_after: str | None = None
    methods_added: list[str] = Field(default_factory=list)
    methods_removed: list[str] = Field(default_factory=list)
    methods_modified: list[MethodDiff] = Field(default_factory=list)
    fields_added: list[str] = Field(default_factory=list)
    fields_removed: list[str] = Field(default_factory=list)
    fields_modified: list[FieldDiff] = Field(default_factory=list)


class DEXDiff(BaseModel):
    """Differences in Dalvik Executable bytecode, classes, and framework APIs."""

    dex_files_added: list[str] = Field(default_factory=list)
    dex_files_removed: list[str] = Field(default_factory=list)
    dex_files_modified: list[str] = Field(default_factory=list)
    dex_files_unchanged: list[str] = Field(default_factory=list)
    classes_added: list[str] = Field(default_factory=list)
    classes_removed: list[str] = Field(default_factory=list)
    classes_modified: list[ClassDiff] = Field(default_factory=list)
    classes_unchanged_count: int = 0
    api_references_added: list[str] = Field(default_factory=list)
    api_references_removed: list[str] = Field(default_factory=list)


class StringDiff(BaseModel):
    """Differences in extracted strings."""

    total_added: int = 0
    total_removed: int = 0
    total_unchanged: int = 0
    added_sample: list[str] = Field(default_factory=list)
    removed_sample: list[str] = Field(default_factory=list)


class URLDiffItem(BaseModel):
    """An added or removed URL with origin provenance."""

    url: str
    source_file: str | None = None
    source_class: str | None = None
    source_method: str | None = None


class NetworkDiff(BaseModel):
    """Differences in network endpoints (URLs, domains, IPs)."""

    urls_added: list[URLDiffItem] = Field(default_factory=list)
    urls_removed: list[URLDiffItem] = Field(default_factory=list)
    urls_unchanged_count: int = 0
    domains_added: list[str] = Field(default_factory=list)
    domains_removed: list[str] = Field(default_factory=list)
    domains_unchanged_count: int = 0
    ips_added: list[str] = Field(default_factory=list)
    ips_removed: list[str] = Field(default_factory=list)
    ips_unchanged_count: int = 0


class NativeLibraryDiff(BaseModel):
    """Differences for a native shared library (.so)."""

    path: str
    abi: str
    change_type: ChangeType
    size_before: int | None = None
    size_after: int | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None
    elf_class_before: str | None = None
    elf_class_after: str | None = None
    machine_before: str | None = None
    machine_after: str | None = None
    symbols_exported_added: list[str] = Field(default_factory=list)
    symbols_exported_removed: list[str] = Field(default_factory=list)
    symbols_imported_added: list[str] = Field(default_factory=list)
    symbols_imported_removed: list[str] = Field(default_factory=list)


class NativeDiff(BaseModel):
    """Differences in native libraries, ABIs, and symbols."""

    libraries_added: list[NativeLibraryDiff] = Field(default_factory=list)
    libraries_removed: list[NativeLibraryDiff] = Field(default_factory=list)
    libraries_modified: list[NativeLibraryDiff] = Field(default_factory=list)
    libraries_unchanged: list[str] = Field(default_factory=list)
    abis_added: list[str] = Field(default_factory=list)
    abis_removed: list[str] = Field(default_factory=list)


class ResourceDiff(BaseModel):
    """Differences in resources.arsc and res/ directory files."""

    resources_arsc_change: ChangeType = ChangeType.UNCHANGED
    resources_arsc_details: dict[str, Any] = Field(default_factory=dict)
    total_added: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_unchanged: int = 0
    by_type: dict[str, dict[str, int]] = Field(default_factory=dict)
    entries: list[FileEntryDiff] = Field(default_factory=list)


class AssetEntropyChange(BaseModel):
    """Entropy delta for a modified or added asset."""

    path: str
    entropy_before: float | None = None
    entropy_after: float | None = None
    delta: float | None = None


class AssetDiff(BaseModel):
    """Differences in assets/ entries and their Shannon entropy."""

    total_added: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_unchanged: int = 0
    entries: list[FileEntryDiff] = Field(default_factory=list)
    entropy_changes: list[AssetEntropyChange] = Field(default_factory=list)


class EmbeddedDiff(BaseModel):
    """Differences in embedded APKs, DEX files, and binaries."""

    apks_added: list[str] = Field(default_factory=list)
    apks_removed: list[str] = Field(default_factory=list)
    dex_added: list[str] = Field(default_factory=list)
    dex_removed: list[str] = Field(default_factory=list)
    executables_added: list[str] = Field(default_factory=list)
    executables_removed: list[str] = Field(default_factory=list)


class CertificateDiff(BaseModel):
    """Differences in signing certificates."""

    status: str = "UNCHANGED"  # "SAME", "CHANGED", "ADDED", "REMOVED"
    count_before: int = 0
    count_after: int = 0
    certificates_before: list[dict[str, Any]] = Field(default_factory=list)
    certificates_after: list[dict[str, Any]] = Field(default_factory=list)
    fingerprint_changes: list[DiffChange] = Field(default_factory=list)


class DiffSummary(BaseModel):
    """Aggregated quantitative summary of differences."""

    permissions_added: int = 0
    permissions_removed: int = 0
    components_added: int = 0
    components_removed: int = 0
    components_modified: int = 0
    dex_files_added: int = 0
    dex_files_removed: int = 0
    dex_files_modified: int = 0
    classes_added: int = 0
    classes_removed: int = 0
    classes_modified: int = 0
    native_libraries_added: int = 0
    native_libraries_removed: int = 0
    native_libraries_modified: int = 0
    domains_added: int = 0
    domains_removed: int = 0
    urls_added: int = 0
    urls_removed: int = 0
    files_added: int = 0
    files_removed: int = 0
    files_modified: int = 0
    files_renamed: int = 0
    certificate_status: str = "UNCHANGED"
    text_lines: list[str] = Field(default_factory=list)


class DiffResult(BaseModel):
    """Complete, structured, and serialisable result of comparing two APKs."""

    status: AnalysisStatus = AnalysisStatus.COMPLETE
    apk_a: PackageIdentity
    apk_b: PackageIdentity

    identity: IdentityDiff
    manifest: ManifestDiff
    permissions: PermissionDiff
    components: ComponentDiff
    dex: DEXDiff
    strings: StringDiff
    network: NetworkDiff
    native: NativeDiff
    resources: ResourceDiff
    assets: AssetDiff
    embedded: EmbeddedDiff
    certificates: CertificateDiff
    files: FileDiff

    summary: DiffSummary

    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def original(self) -> PackageIdentity:
        """Alias for apk_a for backward compatibility."""
        return self.apk_a

    @property
    def modified(self) -> PackageIdentity:
        """Alias for apk_b for backward compatibility."""
        return self.apk_b
