"""APKForge inspection package — Phase 2.

The inspection engine takes the normalized :class:`~apkforge.intake.AndroidPackage`
produced by Phase 1 and creates a detailed technical inventory of what is
actually inside the APK.

Phase 2 is **descriptive and evidence-oriented**.  It answers:

    What is actually inside this APK?

It does NOT:

- Classify anything as malicious or safe.
- Execute APK/DEX/native code.
- Connect to discovered URLs/IPs.
- Perform reputation lookups.

Architecture
------------
The inspection pipeline is composed of independent inspectors, each with a
clear responsibility::

    InspectionEngine
          │
          ├── ManifestInspector
          ├── DEXInspector
          ├── NativeInspector
          ├── ResourceInspector
          ├── AssetInspector
          ├── NetworkInspector
          ├── EmbeddedFileInspector
          └── ObfuscationInspector

All inspectors produce structured Pydantic models that serialize cleanly
to JSON.
"""

from apkforge.inspection.assets import AssetInspector
from apkforge.inspection.dex import DEXInspector
from apkforge.inspection.embedded import EmbeddedFileInspector
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.manifest import ManifestInspector
from apkforge.inspection.models import (
    ActivityInfo,
    ApplicationInfo,
    AssetEntry,
    AssetInspection,
    BroadcastReceiverInfo,
    ClassInfo,
    ContentProviderInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    DomainReference,
    EmbeddedAPKInfo,
    EmbeddedDEXInfo,
    EmbeddedFileInspection,
    EvidenceSource,
    ExecutableFileInfo,
    FieldInfo,
    InspectionResult,
    IntentDataInfo,
    IntentFilterInfo,
    IPAddressReference,
    ManifestInspection,
    MethodInfo,
    NativeInspection,
    NativeLibraryInspection,
    NativeStringReference,
    NetworkInspection,
    ObfuscationIndicators,
    ObfuscationInspection,
    PackageInventory,
    PermissionInfo,
    ResourceInspection,
    ResourceTypeCount,
    ServiceInfo,
    StringReference,
    URLReference,
)
from apkforge.inspection.native import NativeInspector
from apkforge.inspection.network import NetworkInspector
from apkforge.inspection.obfuscation import ObfuscationInspector
from apkforge.inspection.resources import ResourceInspector
from apkforge.inspection.strings import StringInspector

__all__ = [
    "ActivityInfo",
    "ApplicationInfo",
    "AssetEntry",
    "AssetInspection",
    "AssetInspector",
    "BroadcastReceiverInfo",
    "ClassInfo",
    "ContentProviderInfo",
    "DEXClassInventory",
    "DEXFileInspection",
    "DEXInspection",
    "DEXInspector",
    "DomainReference",
    "EmbeddedAPKInfo",
    "EmbeddedDEXInfo",
    "EmbeddedFileInspection",
    "EmbeddedFileInspector",
    "EvidenceSource",
    "ExecutableFileInfo",
    "FieldInfo",
    "IPAddressReference",
    "InspectionEngine",
    "InspectionResult",
    "IntentDataInfo",
    "IntentFilterInfo",
    "ManifestInspection",
    "ManifestInspector",
    "MethodInfo",
    "NativeInspection",
    "NativeInspector",
    "NativeLibraryInspection",
    "NativeStringReference",
    "NetworkInspection",
    "NetworkInspector",
    "ObfuscationIndicators",
    "ObfuscationInspection",
    "ObfuscationInspector",
    "PackageInventory",
    "PermissionInfo",
    "ResourceInspection",
    "ResourceInspector",
    "ResourceTypeCount",
    "ServiceInfo",
    "StringInspector",
    "StringReference",
    "URLReference",
]
