"""APKForge diff package — Phase 3.

Provides comprehensive static comparison between two Android APK packages.
Answers: "What changed between APK A and APK B?"
"""

from __future__ import annotations

from apkforge.diff.assets import AssetDiffer
from apkforge.diff.certificates import CertificateDiffer
from apkforge.diff.components import ComponentDiffer
from apkforge.diff.dex import DEXDiffer
from apkforge.diff.embedded import EmbeddedDiffer
from apkforge.diff.engine import DiffEngine
from apkforge.diff.files import FileDiffer
from apkforge.diff.identity import IdentityDiffer
from apkforge.diff.manifest import ManifestDiffer
from apkforge.diff.models import (
    AssetDiff,
    AssetEntropyChange,
    CertificateDiff,
    ChangeType,
    ClassDiff,
    ComponentChange,
    ComponentDiff,
    DEXDiff,
    DiffChange,
    DiffResult,
    DiffSummary,
    EmbeddedDiff,
    FieldDiff,
    FileDiff,
    FileEntryDiff,
    IdentityDiff,
    IntentFilterDiff,
    ManifestDiff,
    MethodDiff,
    NativeDiff,
    NativeLibraryDiff,
    NetworkDiff,
    PackageIdentity,
    PermissionDiff,
    ResourceDiff,
    SignificanceCategory,
    StringDiff,
    URLDiffItem,
)
from apkforge.diff.native import NativeDiffer
from apkforge.diff.network import NetworkDiffer
from apkforge.diff.permissions import PermissionDiffer
from apkforge.diff.resources import ResourceDiffer
from apkforge.diff.strings import StringDiffer
from apkforge.diff.summary import SummaryEngine

__all__ = [
    "AssetDiff",
    "AssetDiffer",
    "AssetEntropyChange",
    "CertificateDiff",
    "CertificateDiffer",
    "ChangeType",
    "ClassDiff",
    "ComponentChange",
    "ComponentDiff",
    "ComponentDiffer",
    "DEXDiff",
    "DEXDiffer",
    "DiffChange",
    "DiffEngine",
    "DiffResult",
    "DiffSummary",
    "EmbeddedDiff",
    "EmbeddedDiffer",
    "FieldDiff",
    "FileDiff",
    "FileDiffer",
    "FileEntryDiff",
    "IdentityDiff",
    "IdentityDiffer",
    "IntentFilterDiff",
    "ManifestDiff",
    "ManifestDiffer",
    "MethodDiff",
    "NativeDiff",
    "NativeDiffer",
    "NativeLibraryDiff",
    "NetworkDiff",
    "NetworkDiffer",
    "PackageIdentity",
    "PermissionDiff",
    "PermissionDiffer",
    "ResourceDiff",
    "ResourceDiffer",
    "SignificanceCategory",
    "StringDiff",
    "StringDiffer",
    "SummaryEngine",
    "URLDiffItem",
]
