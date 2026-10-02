"""Inspection engine — orchestrates all Phase 2 static inspectors.

The InspectionEngine coordinates independent, specialized inspectors to build
a comprehensive technical inventory of an APK's contents.

Security invariants:
- Never executes application code (DEX or native).
- Never connects to discovered network endpoints (URLs, domains, IPs).
- Does not categorize items as malware or classify permissions as dangerous.
- Purely static, descriptive, and evidence-oriented analysis.
- Errors in individual inspectors are isolated and recorded as limitations.
"""

from __future__ import annotations

import contextlib
import shutil
import zipfile
from pathlib import Path

from apkforge.core.config import APKForgeConfig, load_default_config
from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus
from apkforge.inspection.assets import AssetInspector
from apkforge.inspection.dex import DEXInspector
from apkforge.inspection.embedded import EmbeddedFileInspector
from apkforge.inspection.manifest import ManifestInspector
from apkforge.inspection.models import (
    InspectionResult,
    PackageInventory,
)
from apkforge.inspection.native import NativeInspector
from apkforge.inspection.network import NetworkInspector
from apkforge.inspection.obfuscation import ObfuscationInspector
from apkforge.inspection.resources import ResourceInspector
from apkforge.intake import AndroidPackage, APKIntakeService
from apkforge.intake.handlers.split import SplitType

__all__ = ["InspectionEngine"]

_log = get_logger(__name__)


class InspectionEngine:
    """Orchestrates all static APK inspection sub-engines.

    Coordinates manifest, DEX, native library, resource, asset, network,
    embedded file, and obfuscation inspection.  Maintains error isolation
    so that failure in one inspector does not terminate the rest of the
    pipeline.
    """

    def __init__(
        self,
        config: APKForgeConfig | None = None,
        *,
        manifest_inspector: ManifestInspector | None = None,
        dex_inspector: DEXInspector | None = None,
        native_inspector: NativeInspector | None = None,
        resource_inspector: ResourceInspector | None = None,
        asset_inspector: AssetInspector | None = None,
        network_inspector: NetworkInspector | None = None,
        embedded_inspector: EmbeddedFileInspector | None = None,
        obfuscation_inspector: ObfuscationInspector | None = None,
    ) -> None:
        self._config = config or load_default_config()
        self._manifest_inspector = manifest_inspector or ManifestInspector()
        self._dex_inspector = dex_inspector or DEXInspector()
        self._native_inspector = native_inspector or NativeInspector()
        self._resource_inspector = resource_inspector or ResourceInspector()
        self._asset_inspector = asset_inspector or AssetInspector()
        self._network_inspector = network_inspector or NetworkInspector()
        self._embedded_inspector = embedded_inspector or EmbeddedFileInspector(
            limits=self._config.extraction
        )
        self._obfuscation_inspector = obfuscation_inspector or ObfuscationInspector()

    def inspect(
        self,
        target: Path | str | AndroidPackage,
        *,
        package: AndroidPackage | None = None,
        keep_workspace: bool | None = None,
        enabled_inspectors: set[str] | None = None,
    ) -> InspectionResult:
        """Run complete static inspection on an APK or normalized AndroidPackage.

        Args:
            target: Path to target (APK, APKS, XAPK, split dir) or an AndroidPackage.
            package: Pre-computed AndroidPackage (optional).
            keep_workspace: Whether to retain temporary extraction workspace.
            enabled_inspectors: Optional subset of inspectors to run (e.g. {'manifest', 'dex'}).
                If None, all inspectors are executed.

        Returns:
            InspectionResult with all extracted inventory and sub-inspector data.
        """
        # 1. Resolve normalized AndroidPackage and primary APK path
        created_workspace = False
        pkg: AndroidPackage

        if isinstance(target, AndroidPackage):
            pkg = target
            apk_path = self._resolve_apk_path(pkg)
        else:
            path = Path(target).resolve()
            if package is not None:
                pkg = package
                apk_path = self._resolve_apk_path(pkg, fallback_path=path)
            else:
                intake_service = APKIntakeService(self._config)
                # Keep workspace temporarily during inspection so extracted splits remain available
                pkg = intake_service.process(path, keep_workspace=True)
                created_workspace = True
                apk_path = self._resolve_apk_path(pkg, fallback_path=path)

        # 2. Check if intake failed fatally
        if pkg.status == AnalysisStatus.FAILED:
            return InspectionResult(
                status=AnalysisStatus.FAILED,
                input_path=pkg.input_path,
                package_type=pkg.package_type,
                metadata=pkg.metadata,
                hashes=pkg.hashes,
                package=pkg,
                errors=list(pkg.errors) or ["Package intake failed."],
                warnings=list(pkg.warnings),
                limitations=["Intake failed: could not extract or locate valid APK archive."],
            )

        if apk_path is None or not apk_path.is_file():
            return InspectionResult(
                status=AnalysisStatus.FAILED,
                input_path=pkg.input_path,
                package_type=pkg.package_type,
                metadata=pkg.metadata,
                hashes=pkg.hashes,
                package=pkg,
                errors=[f"APK file not accessible at: {apk_path}"],
                limitations=["Primary APK path does not exist on disk."],
            )

        result = InspectionResult(
            status=AnalysisStatus.COMPLETE,
            input_path=pkg.input_path,
            package_type=pkg.package_type,
            metadata=pkg.metadata,
            hashes=pkg.hashes,
            package=pkg,
            warnings=list(pkg.warnings),
            errors=list(pkg.errors),
        )

        active = enabled_inspectors or {
            "manifest",
            "dex",
            "native",
            "resources",
            "assets",
            "network",
            "embedded",
            "obfuscation",
        }

        # 3. Run Manifest Inspector
        if "manifest" in active:
            try:
                manifest_res, m_warnings = self._manifest_inspector.inspect(apk_path, package=pkg)
                result.manifest = manifest_res
                result.warnings.extend(m_warnings)
                result.inspector_statuses["manifest"] = "partial" if m_warnings else "complete"
                if manifest_res.package_name and not result.metadata.package_name:
                    result.metadata.package_name = manifest_res.package_name
            except Exception as exc:
                _log.exception("Manifest inspection failed: %s", exc)
                result.limitations.append(f"Manifest inspection failed: {exc}")
                result.inspector_statuses["manifest"] = "failed"

        # 4. Run DEX Inspector
        if "dex" in active:
            try:
                dex_res, d_warnings = self._dex_inspector.inspect(apk_path, package=pkg)
                result.dex = dex_res
                result.warnings.extend(d_warnings)
                result.inspector_statuses["dex"] = "partial" if d_warnings else "complete"
            except Exception as exc:
                _log.exception("DEX inspection failed: %s", exc)
                result.limitations.append(f"DEX inspection failed: {exc}")
                result.inspector_statuses["dex"] = "failed"

        # 5. Run Native Library Inspector
        if "native" in active:
            try:
                native_res, n_warnings = self._native_inspector.inspect(apk_path, package=pkg)
                result.native = native_res
                result.warnings.extend(n_warnings)
                result.inspector_statuses["native"] = "partial" if n_warnings else "complete"
            except Exception as exc:
                _log.exception("Native inspection failed: %s", exc)
                result.limitations.append(f"Native inspection failed: {exc}")
                result.inspector_statuses["native"] = "failed"

        # 6. Run Resource Inspector
        if "resources" in active:
            try:
                res_res, r_warnings = self._resource_inspector.inspect(apk_path, package=pkg)
                result.resources = res_res
                result.warnings.extend(r_warnings)
                result.inspector_statuses["resources"] = "partial" if r_warnings else "complete"
            except Exception as exc:
                _log.exception("Resource inspection failed: %s", exc)
                result.limitations.append(f"Resource inspection failed: {exc}")
                result.inspector_statuses["resources"] = "failed"

        # 7. Run Asset Inspector
        if "assets" in active:
            try:
                asset_res, a_warnings = self._asset_inspector.inspect(apk_path, package=pkg)
                result.assets = asset_res
                result.warnings.extend(a_warnings)
                result.inspector_statuses["assets"] = "partial" if a_warnings else "complete"
            except Exception as exc:
                _log.exception("Asset inspection failed: %s", exc)
                result.limitations.append(f"Asset inspection failed: {exc}")
                result.inspector_statuses["assets"] = "failed"

        # 8. Run Network Inspector
        if "network" in active:
            try:
                dex_strings = result.dex.strings if result.dex else []
                native_strings = []
                if result.native:
                    for lib in result.native.libraries:
                        native_strings.extend(lib.strings)
                manifest_strings: list[str] = []
                if result.manifest:
                    if result.manifest.package_name:
                        manifest_strings.append(result.manifest.package_name)
                    manifest_strings.extend(p.name for p in result.manifest.permissions)
                    for act in result.manifest.activities:
                        for ifilt in act.intent_filters:
                            for d in ifilt.data:
                                if d.host:
                                    manifest_strings.append(d.host)
                                if d.scheme:
                                    manifest_strings.append(d.scheme)

                net_res, net_warnings = self._network_inspector.inspect(
                    dex_strings=dex_strings,
                    native_strings=native_strings,
                    manifest_strings=manifest_strings,
                )
                result.network = net_res
                result.warnings.extend(net_warnings)
                result.inspector_statuses["network"] = "partial" if net_warnings else "complete"
            except Exception as exc:
                _log.exception("Network inspection failed: %s", exc)
                result.limitations.append(f"Network inspection failed: {exc}")
                result.inspector_statuses["network"] = "failed"

        # 9. Run Embedded File Inspector
        if "embedded" in active:
            try:
                emb_res, emb_warnings = self._embedded_inspector.inspect(apk_path, package=pkg)
                result.embedded = emb_res
                result.warnings.extend(emb_warnings)
                result.inspector_statuses["embedded"] = "partial" if emb_warnings else "complete"
            except Exception as exc:
                _log.exception("Embedded file inspection failed: %s", exc)
                result.limitations.append(f"Embedded file inspection failed: {exc}")
                result.inspector_statuses["embedded"] = "failed"

        # 10. Run Obfuscation Inspector
        if "obfuscation" in active:
            try:
                obf_res, obf_warnings = self._obfuscation_inspector.inspect(
                    dex_inspection=result.dex
                )
                result.obfuscation = obf_res
                result.warnings.extend(obf_warnings)
                result.inspector_statuses["obfuscation"] = "partial" if obf_warnings else "complete"
            except Exception as exc:
                _log.exception("Obfuscation inspection failed: %s", exc)
                result.limitations.append(f"Obfuscation inspection failed: {exc}")
                result.inspector_statuses["obfuscation"] = "failed"

        # 11. Compile Package Inventory
        result.inventory = self._compile_inventory(apk_path, pkg, result)

        # 12. Determine Final Status
        failed_count = sum(1 for s in result.inspector_statuses.values() if s == "failed")
        if failed_count == len(result.inspector_statuses) and result.inspector_statuses:
            result.status = AnalysisStatus.FAILED
        elif failed_count > 0 or result.errors or result.limitations or result.warnings:
            result.status = AnalysisStatus.PARTIAL
        else:
            result.status = AnalysisStatus.COMPLETE

        # 13. Clean up workspace if we created one and not asked to keep it
        if created_workspace and not keep_workspace:
            self._cleanup_workspace_if_needed(apk_path)

        return result

    def _resolve_apk_path(
        self,
        package: AndroidPackage,
        fallback_path: Path | None = None,
    ) -> Path | None:
        """Resolve the primary APK file path to inspect."""
        # Check splits first (for APKS / XAPK / SPLIT bundles)
        if package.splits:
            for s in package.splits:
                if s.split_type == SplitType.BASE and s.path.is_file():
                    return s.path
            for s in package.splits:
                if s.path.is_file():
                    return s.path

        # If package input_path is a file (standalone APK)
        if package.input_path.is_file():
            return package.input_path

        # Check fallback path
        if fallback_path and fallback_path.is_file():
            return fallback_path

        return None

    def _compile_inventory(
        self,
        apk_path: Path,
        package: AndroidPackage,
        result: InspectionResult,
    ) -> PackageInventory:
        """Aggregate total inventory counts across all inspectors."""
        inv = PackageInventory()

        # Manifest count
        if (result.manifest and result.manifest.package_name) or package.metadata.package_name:
            inv.manifest_count = 1

        # DEX count
        if result.dex:
            inv.dex_count = len(result.dex.dex_files)
        else:
            inv.dex_count = len(package.dex_files)

        # Native library count
        if result.native:
            inv.native_library_count = len(result.native.libraries)
        else:
            inv.native_library_count = len(package.native_libraries)

        # Resource count
        if result.resources:
            inv.resource_count = result.resources.resource_file_count

        # Asset count
        if result.assets:
            inv.asset_count = result.assets.total_assets

        # Embedded file counts
        if result.embedded:
            inv.embedded_apk_count = len(result.embedded.embedded_apks)
            inv.embedded_dex_count = len(result.embedded.embedded_dex)
            inv.executable_file_count = len(result.embedded.executable_files)

        # Certificate count
        inv.certificate_count = len(package.certificates)

        # Total file count
        if package.files:
            inv.total_file_count = len(package.files)
        else:
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    inv.total_file_count = len([i for i in zf.infolist() if not i.is_dir()])
            except Exception:
                inv.total_file_count = 0

        return inv

    def _cleanup_workspace_if_needed(self, apk_path: Path) -> None:
        """Attempt to remove temporary extracted files in workspace."""
        # Find if apk_path is inside an APKForge workspace and clean up
        with contextlib.suppress(Exception):
            for parent in apk_path.parents:
                if parent.name.startswith("apkforge_"):
                    shutil.rmtree(parent, ignore_errors=True)
                    break
