"""Security Analysis Engine coordinator.

Orchestrates declarative rules, malware analyzers, spyware analyzers, vulnerability analyzers,
and diff-aware security analysis over structured inspection and privacy evidence.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from apkforge.core.models import AnalysisStatus, Severity
from apkforge.diff.models import ChangeType
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.models import InspectionResult
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.diff_analyzer import DiffSecurityAnalyzer
from apkforge.security.malware import MalwareAnalyzer
from apkforge.security.models import (
    SecurityFinding,
    SecurityResult,
    SecurityStatus,
    SecuritySummary,
)
from apkforge.security.rules import SecurityEvidenceIndex, SecurityRuleEngine
from apkforge.security.spyware import SpywareAnalyzer
from apkforge.security.vulnerabilities import VulnerabilityAnalyzer

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkforge.core.config import APKForgeConfig
    from apkforge.diff.models import DiffResult
    from apkforge.intake.models import AndroidPackage
    from apkforge.privacy.models import PrivacyResult

_log = logging.getLogger(__name__)
_T = TypeVar("_T")

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class SecurityEngine:
    """Orchestrates comprehensive static security analysis for Android applications."""

    def __init__(
        self,
        config: APKForgeConfig | None = None,
        rule_engine: SecurityRuleEngine | None = None,
        custom_rules_dir: Path | None = None,
    ) -> None:
        self._config = config
        if rule_engine:
            self._rule_engine = rule_engine
        else:
            self._rule_engine = SecurityRuleEngine()
            self._rule_engine.load_builtins()
            if custom_rules_dir and custom_rules_dir.is_dir():
                self._rule_engine.load_from_directory(custom_rules_dir)

        # Specialized analyzers
        self._malware_analyzer = MalwareAnalyzer()
        self._spyware_analyzer = SpywareAnalyzer()
        self._vulnerability_analyzer = VulnerabilityAnalyzer()
        self._diff_analyzer = DiffSecurityAnalyzer()

    def analyze(
        self,
        target: Path | str | InspectionResult | None = None,
        *,
        inspection: InspectionResult | None = None,
        diff: DiffResult | Path | str | None = None,
        privacy: PrivacyResult | None = None,
        package: AndroidPackage | None = None,
        apk_path: Path | str | None = None,
        keep_workspace: bool = False,
    ) -> SecurityResult:
        """Execute complete static security analysis on an APK or inspection result."""
        warnings: list[str] = []
        errors: list[str] = []
        limitations: list[str] = [
            "Static security analysis identifies capabilities, configuration states, and potential "
            "vulnerability patterns. It does not establish that code is actively executed, that "
            "vulnerabilities are exploitable in context, or that the application is malicious."
        ]

        # 1. Resolve Phase 2 InspectionResult
        resolved_target = target or inspection or apk_path
        if resolved_target is None:
            raise ValueError(
                "Target APK path or InspectionResult must be provided to SecurityEngine.analyze()"
            )

        resolved_inspection: InspectionResult
        if isinstance(resolved_target, InspectionResult):
            resolved_inspection = resolved_target
            package = package or resolved_inspection.package
        else:
            apk_p = Path(resolved_target)
            if not apk_p.exists():
                raise FileNotFoundError(f"Target APK does not exist: {apk_p}")

            inspection_engine = InspectionEngine(self._config)
            resolved_inspection = inspection_engine.inspect(apk_p, keep_workspace=keep_workspace)
            package = package or resolved_inspection.package
            warnings.extend(resolved_inspection.warnings)
            errors.extend(resolved_inspection.errors)
            limitations.extend(resolved_inspection.limitations)

        inspection = resolved_inspection

        # 2. Resolve Phase 4 PrivacyResult
        if privacy is None:
            try:
                privacy_engine = PrivacyEngine(config=self._config)
                privacy = privacy_engine.analyze(inspection)
            except Exception as e:
                _log.warning("Privacy analysis could not be completed for security index: %s", e)
                limitations.append(f"Privacy capability correlation degraded: {e}")

        # 3. Resolve Phase 3 DiffResult if provided
        resolved_diff: DiffResult | None = None
        if diff is not None:
            if hasattr(diff, "status") and hasattr(diff, "permissions"):
                resolved_diff = diff  # type: ignore[assignment]
            else:
                try:
                    from apkforge.diff.engine import DiffEngine

                    diff_engine = DiffEngine(self._config)
                    resolved_diff = diff_engine.diff(target, diff, keep_workspace=keep_workspace)
                except Exception as e:
                    _log.warning("Diff execution failed during security analysis: %s", e)
                    limitations.append(f"Diff-aware security analysis degraded: {e}")

        # Package identity
        pkg_name: str | None = None
        ver_name: str | None = None
        ver_code: str | None = None
        if package and package.identity:
            pkg_name = package.identity.package_name
            ver_name = package.identity.version_name
            if package.identity.version_code is not None:
                ver_code = str(package.identity.version_code)
        elif inspection.manifest:
            pkg_name = inspection.manifest.package_name
            ver_name = inspection.manifest.version_name
            if inspection.manifest.version_code is not None:
                ver_code = str(inspection.manifest.version_code)

        # 4. Build SecurityEvidenceIndex
        index = self._build_security_evidence_index(
            inspection=inspection,
            package=package,
            privacy=privacy,
            diff=resolved_diff,
            package_name=pkg_name,
        )

        all_findings: list[SecurityFinding] = []

        # 5. Run Declarative Rule Engine
        rule_findings = self._safe_run(
            "rule_engine",
            lambda: self._rule_engine.evaluate(index),
            default=[],
            limitations=limitations,
        )
        all_findings.extend(rule_findings)

        # 6. Run Malware Analyzer
        malware_findings = self._safe_run(
            "malware",
            lambda: self._malware_analyzer.analyze(index),
            default=[],
            limitations=limitations,
        )
        all_findings.extend(malware_findings)

        # 7. Run Spyware Analyzer
        spyware_findings = self._safe_run(
            "spyware",
            lambda: self._spyware_analyzer.analyze(index),
            default=[],
            limitations=limitations,
        )
        all_findings.extend(spyware_findings)

        # 8. Run Vulnerability Analyzer
        vuln_findings = self._safe_run(
            "vulnerabilities",
            lambda: self._vulnerability_analyzer.analyze(index),
            default=[],
            limitations=limitations,
        )
        all_findings.extend(vuln_findings)

        # 9. Run Diff Analyzer (if diff present)
        diff_findings: list[SecurityFinding] = []
        if resolved_diff:
            diff_findings = self._safe_run(
                "diff_security",
                lambda: self._diff_analyzer.analyze(resolved_diff),
                default=[],
                limitations=limitations,
            )
            all_findings.extend(diff_findings)

        # 10. Deduplicate findings by ID
        unique_findings: dict[str, SecurityFinding] = {}
        for f in all_findings:
            if f.id not in unique_findings:
                unique_findings[f.id] = f
            else:
                # Merge evidence
                existing = unique_findings[f.id]
                existing_ev_locs = {e.location for e in existing.evidence}
                for new_ev in f.evidence:
                    if new_ev.location not in existing_ev_locs:
                        existing.evidence.append(new_ev)
                        existing_ev_locs.add(new_ev.location)

        # Sort findings deterministically (by severity descending, then by id)
        sorted_findings = sorted(
            unique_findings.values(),
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.id),
        )

        # Categorize findings
        malware_list = [
            f
            for f in sorted_findings
            if f.category in ("malware_indicator", "code_execution", "dynamic_code", "payload")
        ]
        spyware_list = [
            f
            for f in sorted_findings
            if f.category in ("spyware_indicator", "surveillance", "collection", "persistence")
        ]
        vuln_list = [
            f
            for f in sorted_findings
            if f.category
            in (
                "vulnerability",
                "configuration",
                "exported_component",
                "crypto",
                "credential_access",
            )
        ]
        diff_list = [f for f in sorted_findings if f.category == "diff_modification"]

        # 11. Compile SecuritySummary
        summary = SecuritySummary(
            total_findings=len(sorted_findings),
            critical_count=sum(1 for f in sorted_findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in sorted_findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in sorted_findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in sorted_findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in sorted_findings if f.severity == Severity.INFORMATIONAL),
            malware_indicator_count=len(malware_list),
            spyware_indicator_count=len(spyware_list),
            vulnerability_count=len(vuln_list),
            diff_security_change_count=len(diff_list),
            overall_security_status=(
                SecurityStatus.FINDINGS_PRESENT
                if sorted_findings
                else SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS
            ),
        )

        # Overall analysis status
        overall_status = inspection.status
        if overall_status == AnalysisStatus.FAILED and (
            inspection.manifest or inspection.dex or inspection.package
        ):
            overall_status = AnalysisStatus.COMPLETE

        if overall_status == AnalysisStatus.FAILED:
            summary.overall_security_status = SecurityStatus.ANALYSIS_INCOMPLETE
        elif overall_status == AnalysisStatus.PARTIAL or errors:
            overall_status = AnalysisStatus.PARTIAL
            if summary.overall_security_status == SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS:
                summary.overall_security_status = SecurityStatus.ANALYSIS_INCOMPLETE

        if (
            inspection.status == AnalysisStatus.PARTIAL
            or not inspection.dex
            or not getattr(inspection.dex, "dex_files", [])
        ):
            limitations.append(
                "DEX inspection was not completed or no DEX files were analyzed; "
                "bytecode-based security rules were evaluated partially."
            )

        return SecurityResult(
            status=overall_status,
            security_status=summary.overall_security_status,
            package_name=pkg_name,
            version_name=ver_name,
            version_code=ver_code,
            summary=summary,
            findings=sorted_findings,
            malware_indicators=malware_list,
            spyware_indicators=spyware_list,
            vulnerability_indicators=vuln_list,
            diff_findings=diff_list,
            warnings=sorted(set(warnings)),
            errors=sorted(set(errors)),
            limitations=sorted(set(limitations)),
        )

    def _build_security_evidence_index(
        self,
        inspection: InspectionResult,
        package: AndroidPackage | None,
        privacy: PrivacyResult | None,
        diff: DiffResult | None,
        package_name: str | None,
    ) -> SecurityEvidenceIndex:
        """Construct the SecurityEvidenceIndex from all upstream phase data."""
        permissions: set[str] = set()
        prot_levels: dict[str, str] = {}
        apis: set[str] = set()
        classes: set[str] = set()
        methods: set[str] = set()
        strings: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        url_prov: dict[str, list[str]] = {}
        components: dict[str, list[dict[str, Any]]] = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        manifest_attrs: dict[str, Any] = {}
        embedded_files: list[dict[str, Any]] = []
        high_entropy_assets: list[dict[str, Any]] = []
        native_libs: set[str] = set()
        privacy_caps: set[str] = set()
        detected_sdks: list[str] = []
        diff_changes: set[str] = set()

        # 1. Manifest data
        if inspection.manifest:
            for p in inspection.manifest.permissions:
                pname = p.name if hasattr(p, "name") else str(p)
                permissions.add(pname)
                if hasattr(p, "protection_level") and p.protection_level:
                    prot_levels[pname] = p.protection_level

            # Components
            for a in inspection.manifest.activities:
                components["activities"].append(
                    {
                        "name": a.name,
                        "exported": a.exported,
                        "permission": a.permission,
                        "actions": [
                            act
                            for f in getattr(a, "intent_filters", [])
                            for act in getattr(f, "actions", [])
                        ],
                    }
                )
            for s in inspection.manifest.services:
                components["services"].append(
                    {
                        "name": s.name,
                        "exported": s.exported,
                        "permission": s.permission,
                        "foreground_service_type": getattr(s, "foreground_service_type", None),
                        "actions": [
                            act
                            for f in getattr(s, "intent_filters", [])
                            for act in getattr(f, "actions", [])
                        ],
                    }
                )
            for r in inspection.manifest.receivers:
                components["receivers"].append(
                    {
                        "name": r.name,
                        "exported": r.exported,
                        "permission": r.permission,
                        "actions": [
                            act
                            for f in getattr(r, "intent_filters", [])
                            for act in getattr(f, "actions", [])
                        ],
                    }
                )
            for pr in inspection.manifest.providers:
                components["providers"].append(
                    {
                        "name": pr.name,
                        "exported": pr.exported,
                        "permission": getattr(pr, "permission", None),
                    }
                )

            # Application attributes
            app_info = getattr(inspection.manifest, "application", None)
            for snake, camel in (
                ("debuggable", "debuggable"),
                ("allow_backup", "allowBackup"),
                ("test_only", "testOnly"),
                ("uses_cleartext_traffic", "usesCleartextTraffic"),
            ):
                val = getattr(app_info, snake, None) if app_info else None
                if val is None:
                    val = getattr(inspection.manifest, snake, None)
                if val is None:
                    val = getattr(inspection.manifest, camel, None)
                if val is not None:
                    manifest_attrs[snake] = val
                    manifest_attrs[camel] = val

        # 2. DEX data
        if inspection.dex:
            for df in inspection.dex.dex_files:
                inv = getattr(df, "inventory", None)
                for c in getattr(inv, "classes", []):
                    classes.add(c.name)
                for m in getattr(inv, "methods", []):
                    methods.add(m.name)
                    methods.add(f"{m.class_name}.{m.name}")
                apis.update(getattr(df, "api_references", []) or [])
                if hasattr(df, "strings") and df.strings:
                    for s in df.strings:
                        val = s.value if hasattr(s, "value") else str(s)
                        strings.add(val)

            apis.update(getattr(inspection.dex, "api_references", []) or [])

            if hasattr(inspection.dex, "strings") and inspection.dex.strings:
                for s in inspection.dex.strings:
                    val = s.value if hasattr(s, "value") else str(s)
                    strings.add(val)

        # 3. Network data
        if inspection.network:
            for d in inspection.network.domains:
                domains.add(d.domain.strip().lower())
            for u in inspection.network.urls:
                u_str = u.url.strip()
                urls.add(u_str)
                try:
                    from urllib.parse import urlparse

                    host = urlparse(u_str).hostname
                    if host:
                        domains.add(host.lower())
                except ValueError:
                    _log.debug("Failed to parse hostname from URL: %s", u_str)
                if hasattr(u, "source") and u.source:
                    src = u.source
                    loc_parts = []
                    file_val = getattr(src, "file", None) or getattr(src, "file_path", None)
                    if file_val:
                        loc_parts.append(str(file_val))
                    if src.class_name:
                        loc_parts.append(src.class_name)
                    if src.method_name:
                        loc_parts.append(src.method_name)
                    url_prov[u_str] = loc_parts

        # 4. Embedded files
        # 4. Embedded files
        if inspection.embedded:
            for ed in getattr(inspection.embedded, "embedded_dex", []) or []:
                embedded_files.append(
                    {"path": ed.path, "type": "dex", "size": getattr(ed, "size", 0)}
                )
            for ea in getattr(inspection.embedded, "embedded_apks", []) or []:
                embedded_files.append(
                    {"path": ea.path, "type": "apk", "size": getattr(ea, "size", 0)}
                )
            for ef in getattr(inspection.embedded, "executable_files", []) or []:
                ftype = getattr(ef, "detected_type", "executable").lower()
                embedded_files.append(
                    {"path": ef.path, "type": ftype, "size": getattr(ef, "size", 0)}
                )

        # 5. Assets & Entropy
        if inspection.assets and inspection.assets.assets:
            for ast in inspection.assets.assets:
                ent = getattr(ast, "entropy", 0.0)
                if ent >= 7.0:
                    high_entropy_assets.append(
                        {
                            "path": ast.path,
                            "entropy": ent,
                            "size": getattr(ast, "size", 0),
                        }
                    )

        # 6. Native libraries
        if inspection.native and inspection.native.libraries:
            for nl in inspection.native.libraries:
                native_libs.add(nl.name)

        # 7. Privacy results
        if privacy:
            if hasattr(privacy, "data_collection") and privacy.data_collection:
                for cap in privacy.data_collection.capabilities:
                    cap_name = (
                        cap.capability.value
                        if hasattr(cap.capability, "value")
                        else str(cap.capability)
                    )
                    privacy_caps.add(cap_name.lower())
            if hasattr(privacy, "advertising") and privacy.advertising:
                for ad in privacy.advertising.detected_advertising_sdks:
                    detected_sdks.append(ad.name)
            if hasattr(privacy, "analytics") and privacy.analytics:
                for an in privacy.analytics.detected_analytics_sdks:
                    detected_sdks.append(an.name)
            if hasattr(privacy, "trackers") and privacy.trackers:
                for tr in privacy.trackers.detected_trackers:
                    detected_sdks.append(tr.name)

        # 8. Diff changes
        if diff:
            if hasattr(diff, "permissions") and diff.permissions:
                for ap in getattr(diff.permissions, "added", []) or []:
                    p_name = ap.name if hasattr(ap, "name") else str(ap)
                    diff_changes.add(f"added_permission:{p_name}")
            if hasattr(diff, "certificates") and diff.certificates:
                status = getattr(diff.certificates, "status", "UNCHANGED")
                if status not in ("UNCHANGED", "SAME"):
                    diff_changes.add("certificate_changed")
            if hasattr(diff, "components") and diff.components:
                for comp_list in (
                    getattr(diff.components, "activities", []),
                    getattr(diff.components, "services", []),
                    getattr(diff.components, "receivers", []),
                    getattr(diff.components, "providers", []),
                ):
                    for ac in comp_list:
                        if getattr(ac, "change_type", None) == ChangeType.ADDED:
                            diff_changes.add(f"added_component:{ac.name}")
            if hasattr(diff, "network") and diff.network:
                for ad in getattr(diff.network, "domains_added", []) or []:
                    diff_changes.add(f"added_domain:{ad}")

        return SecurityEvidenceIndex(
            package_name=package_name,
            permissions=permissions,
            protection_levels=prot_levels,
            apis=apis,
            classes=classes,
            methods=methods,
            strings=strings,
            domains=domains,
            urls=urls,
            url_provenance=url_prov,
            components=components,
            manifest_attributes=manifest_attrs,
            embedded_files=embedded_files,
            high_entropy_assets=high_entropy_assets,
            native_libraries=native_libs,
            privacy_capabilities=privacy_caps,
            detected_sdks=detected_sdks,
            diff_changes=diff_changes,
        )

    def _safe_run(
        self,
        name: str,
        func: Callable[[], _T],
        *,
        default: _T,
        limitations: list[str],
    ) -> _T:
        """Execute a sub-analyzer with error isolation."""
        try:
            return func()
        except Exception as e:
            _log.error("Security analysis failed for category %s: %s", name, e, exc_info=True)
            limitations.append(f"Security analysis degraded for {name}: {e}")
            return default
