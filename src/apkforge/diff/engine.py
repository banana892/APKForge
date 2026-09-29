"""Diff engine — coordinates all Phase 3 comparison operations.

The DiffEngine runs static inspections on both APK packages and coordinates
specialized differs to compute a structured, evidence-based delta.

Security Invariants:
- Never executes application code.
- Never connects to discovered network endpoints.
- Purely static, descriptive, and evidence-oriented.
- Errors in individual differs are isolated.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

from apkforge.core.config import APKForgeConfig, load_default_config
from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus
from apkforge.diff.assets import AssetDiffer
from apkforge.diff.certificates import CertificateDiffer
from apkforge.diff.components import ComponentDiffer
from apkforge.diff.dex import DEXDiffer
from apkforge.diff.embedded import EmbeddedDiffer
from apkforge.diff.files import FileDiffer
from apkforge.diff.identity import IdentityDiffer
from apkforge.diff.manifest import ManifestDiffer
from apkforge.diff.models import (
    AssetDiff,
    CertificateDiff,
    ComponentDiff,
    DEXDiff,
    DiffResult,
    EmbeddedDiff,
    FileDiff,
    IdentityDiff,
    ManifestDiff,
    NativeDiff,
    NetworkDiff,
    PackageIdentity,
    PermissionDiff,
    ResourceDiff,
    StringDiff,
)
from apkforge.diff.native import NativeDiffer
from apkforge.diff.network import NetworkDiffer
from apkforge.diff.permissions import PermissionDiffer
from apkforge.diff.resources import ResourceDiffer
from apkforge.diff.strings import StringDiffer
from apkforge.diff.summary import SummaryEngine
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.models import InspectionResult

__all__ = ["DiffEngine"]

_T = TypeVar("_T")

_log = get_logger(__name__)


class DiffEngine:
    """Orchestrates comprehensive, cross-category comparison between two APKs."""

    def __init__(self, config: APKForgeConfig | None = None) -> None:
        self.config = config or load_default_config()
        self._inspection_engine = InspectionEngine(config=self.config)
        self._identity_differ = IdentityDiffer()
        self._file_differ = FileDiffer()
        self._manifest_differ = ManifestDiffer()
        self._permission_differ = PermissionDiffer()
        self._component_differ = ComponentDiffer()
        self._dex_differ = DEXDiffer()
        self._string_differ = StringDiffer()
        self._network_differ = NetworkDiffer()
        self._native_differ = NativeDiffer()
        self._resource_differ = ResourceDiffer()
        self._asset_differ = AssetDiffer()
        self._embedded_differ = EmbeddedDiffer()
        self._certificate_differ = CertificateDiffer()
        self._summary_engine = SummaryEngine()

    def diff(
        self,
        apk_a: Path | str | InspectionResult,
        apk_b: Path | str | InspectionResult,
        keep_workspace: bool = False,
    ) -> DiffResult:
        """Compare two APK packages and produce a comprehensive DiffResult."""
        # 1. Resolve Inspection A
        insp_a: InspectionResult
        if isinstance(apk_a, InspectionResult):
            insp_a = apk_a
        else:
            path_a = Path(apk_a).resolve()
            insp_a = self._inspection_engine.inspect(path_a, keep_workspace=keep_workspace)

        # 2. Resolve Inspection B
        insp_b: InspectionResult
        if isinstance(apk_b, InspectionResult):
            insp_b = apk_b
        else:
            path_b = Path(apk_b).resolve()
            insp_b = self._inspection_engine.inspect(path_b, keep_workspace=keep_workspace)

        # 3. Overall status and initial limits
        warnings: list[str] = []
        errors: list[str] = []
        limitations: list[str] = []

        warnings.extend(insp_a.warnings)
        warnings.extend(insp_b.warnings)
        errors.extend(insp_a.errors)
        errors.extend(insp_b.errors)
        limitations.extend(insp_a.limitations)
        limitations.extend(insp_b.limitations)

        status = AnalysisStatus.COMPLETE
        if insp_a.status == AnalysisStatus.FAILED or insp_b.status == AnalysisStatus.FAILED:
            status = AnalysisStatus.FAILED
        elif insp_a.status == AnalysisStatus.PARTIAL or insp_b.status == AnalysisStatus.PARTIAL:
            status = AnalysisStatus.PARTIAL

        # 4. Build PackageIdentity representations
        id_a = self._build_package_identity(insp_a)
        id_b = self._build_package_identity(insp_b)

        # 5. Execute Diff Operations with error isolation
        identity_diff = self._safe_run(
            "identity",
            lambda: self._identity_differ.diff(insp_a, insp_b),
            default=IdentityDiff(),
            limitations=limitations,
        )

        if not identity_diff.is_same_package:
            warnings.append(
                f"Package identities differ: '{id_a.package_name}' vs '{id_b.package_name}'"
            )

        file_diff = self._safe_run(
            "file",
            lambda: self._file_differ.diff(insp_a, insp_b),
            default=FileDiff(),
            limitations=limitations,
        )

        manifest_diff = self._safe_run(
            "manifest",
            lambda: self._manifest_differ.diff(insp_a, insp_b),
            default=ManifestDiff(),
            limitations=limitations,
        )

        perm_diff = self._safe_run(
            "permission",
            lambda: self._permission_differ.diff(insp_a, insp_b),
            default=PermissionDiff(),
            limitations=limitations,
        )

        comp_diff = self._safe_run(
            "component",
            lambda: self._component_differ.diff(insp_a, insp_b),
            default=ComponentDiff(),
            limitations=limitations,
        )

        dex_diff = self._safe_run(
            "dex",
            lambda: self._dex_differ.diff(insp_a, insp_b),
            default=DEXDiff(),
            limitations=limitations,
        )

        string_diff = self._safe_run(
            "string",
            lambda: self._string_differ.diff(insp_a, insp_b),
            default=StringDiff(),
            limitations=limitations,
        )

        net_diff = self._safe_run(
            "network",
            lambda: self._network_differ.diff(insp_a, insp_b),
            default=NetworkDiff(),
            limitations=limitations,
        )

        nat_diff = self._safe_run(
            "native",
            lambda: self._native_differ.diff(insp_a, insp_b),
            default=NativeDiff(),
            limitations=limitations,
        )

        res_diff = self._safe_run(
            "resource",
            lambda: self._resource_differ.diff(insp_a, insp_b, file_diff=file_diff),
            default=ResourceDiff(),
            limitations=limitations,
        )

        asset_diff = self._safe_run(
            "asset",
            lambda: self._asset_differ.diff(insp_a, insp_b, file_diff=file_diff),
            default=AssetDiff(),
            limitations=limitations,
        )

        embedded_diff = self._safe_run(
            "embedded",
            lambda: self._embedded_differ.diff(insp_a, insp_b),
            default=EmbeddedDiff(),
            limitations=limitations,
        )

        cert_diff = self._safe_run(
            "certificate",
            lambda: self._certificate_differ.diff(insp_a, insp_b),
            default=CertificateDiff(),
            limitations=limitations,
        )

        # 6. Build Summary
        summary = self._summary_engine.build_summary(
            file_diff=file_diff,
            perm_diff=perm_diff,
            comp_diff=comp_diff,
            dex_diff=dex_diff,
            nat_diff=nat_diff,
            net_diff=net_diff,
            cert_diff=cert_diff,
        )

        return DiffResult(
            status=status,
            apk_a=id_a,
            apk_b=id_b,
            identity=identity_diff,
            manifest=manifest_diff,
            permissions=perm_diff,
            components=comp_diff,
            dex=dex_diff,
            strings=string_diff,
            network=net_diff,
            native=nat_diff,
            resources=res_diff,
            assets=asset_diff,
            embedded=embedded_diff,
            certificates=cert_diff,
            files=file_diff,
            summary=summary,
            warnings=warnings,
            errors=errors,
            limitations=limitations,
        )

    def _safe_run(
        self, name: str, func: Callable[[], _T], default: _T, limitations: list[str]
    ) -> _T:
        """Run a differ with error isolation."""
        try:
            return func()
        except Exception as exc:
            _log.exception("Diff failed for category %s: %s", name, exc)
            limitations.append(f"Comparison failed for category '{name}': {exc}")
            return default

    @staticmethod
    def _build_package_identity(insp: InspectionResult) -> PackageIdentity:
        """Extract PackageIdentity model from InspectionResult."""
        pkg_name = insp.metadata.package_name
        vname = insp.metadata.version_name
        vcode = insp.metadata.version_code
        min_sdk = insp.metadata.min_sdk
        target_sdk = insp.metadata.target_sdk
        sha256 = insp.hashes.sha256 if insp.hashes else None
        fname = insp.input_path.name if insp.input_path else None

        return PackageIdentity(
            package_name=pkg_name,
            version_name=vname,
            version_code=vcode,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            sha256=sha256,
            file_name=fname,
        )
