"""Privacy and Tracker Engine coordinator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from apkforge.core.models import AnalysisStatus, Evidence, Severity
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.models import InspectionResult
from apkforge.privacy.advertising import AdvertisingDetector
from apkforge.privacy.analytics import AnalyticsDetector
from apkforge.privacy.data_collection import DataCollectionAnalyzer
from apkforge.privacy.endpoints import EndpointAnalyzer
from apkforge.privacy.models import (
    AdvertisingResult,
    AnalyticsResult,
    DataCollectionResult,
    EndpointResult,
    PermissionPrivacyResult,
    PrivacyFinding,
    PrivacyResult,
    TelemetryResult,
    TrackerResult,
)
from apkforge.privacy.permissions import PermissionAnalyzer
from apkforge.privacy.rules import EvidenceIndex, RuleEngine
from apkforge.privacy.telemetry import TelemetryDetector
from apkforge.privacy.trackers import TrackerDetector

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkforge.core.config import APKForgeConfig
    from apkforge.intake import AndroidPackage

_log = logging.getLogger(__name__)
_T = TypeVar("_T")


class PrivacyEngine:
    """Orchestrates privacy, tracker, advertising, analytics, and data-capability detectors."""

    def __init__(
        self,
        config: APKForgeConfig | None = None,
        rule_engine: RuleEngine | None = None,
        custom_rules_dir: Path | None = None,
    ) -> None:
        self._config = config
        if rule_engine:
            self._rule_engine = rule_engine
        else:
            self._rule_engine = RuleEngine()
            self._rule_engine.load_builtins()
            if custom_rules_dir and custom_rules_dir.is_dir():
                self._rule_engine.load_from_directory(custom_rules_dir)

        # Specialized detectors
        self._permission_analyzer = PermissionAnalyzer()
        self._tracker_detector = TrackerDetector(self._rule_engine)
        self._advertising_detector = AdvertisingDetector(self._rule_engine)
        self._analytics_detector = AnalyticsDetector(self._rule_engine)
        self._telemetry_detector = TelemetryDetector(self._rule_engine)
        self._endpoint_analyzer = EndpointAnalyzer(self._rule_engine)
        self._data_collection_analyzer = DataCollectionAnalyzer()

    def analyze(
        self,
        apk_or_inspection: Path | str | InspectionResult,
        package: AndroidPackage | None = None,
        keep_workspace: bool = False,
    ) -> PrivacyResult:
        """Execute complete static privacy analysis on an APK or inspection result."""
        warnings: list[str] = []
        errors: list[str] = []
        limitations: list[str] = []
        degraded_categories: list[str] = []

        # 1. Resolve inspection and intake package
        if isinstance(apk_or_inspection, InspectionResult):
            inspection = apk_or_inspection
            package = inspection.package
        else:
            apk_path = Path(apk_or_inspection)
            if not apk_path.exists():
                raise FileNotFoundError(f"Target APK does not exist: {apk_path}")

            inspection_engine = InspectionEngine(self._config)
            inspection = inspection_engine.inspect(apk_path, keep_workspace=keep_workspace)
            package = inspection.package
            warnings.extend(inspection.warnings)
            errors.extend(inspection.errors)
            limitations.extend(inspection.limitations)

        # Determine package identity
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

        # 2. Build EvidenceIndex for fast single-pass evaluation
        index = self._build_evidence_index(inspection, package, pkg_name)

        # 3. Run Permission Privacy Analysis
        perm_result = self._safe_run(
            "permissions",
            lambda: self._permission_analyzer.analyze(inspection, index),
            default=PermissionPrivacyResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )

        # 4. Run SDK / Tracker Detectors
        tracker_result = self._safe_run(
            "trackers",
            lambda: self._tracker_detector.detect(index),
            default=TrackerResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )
        advertising_result = self._safe_run(
            "advertising",
            lambda: self._advertising_detector.detect(index),
            default=AdvertisingResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )
        analytics_result = self._safe_run(
            "analytics",
            lambda: self._analytics_detector.detect(index),
            default=AnalyticsResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )
        telemetry_result = self._safe_run(
            "telemetry",
            lambda: self._telemetry_detector.detect(index),
            default=TelemetryResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )

        # Collect all detected SDKs for correlation
        all_detected_sdks = (
            tracker_result.detected_trackers
            + advertising_result.detected_advertising_sdks
            + analytics_result.detected_analytics_sdks
            + telemetry_result.detected_telemetry_sdks
        )

        # 5. Run Endpoint Analysis
        endpoint_result = self._safe_run(
            "endpoints",
            lambda: self._endpoint_analyzer.analyze(
                inspection, index, detected_sdks=all_detected_sdks
            ),
            default=EndpointResult(),
            limitations=limitations,
            degraded=degraded_categories,
        )

        # 6. Run Data Collection Capability Analysis
        data_collection_result, capability_findings = self._safe_run(
            "data_collection",
            lambda: self._data_collection_analyzer.analyze(
                inspection,
                index,
                detected_sdks=all_detected_sdks,
                endpoints=endpoint_result,
            ),
            default=(DataCollectionResult(), []),
            limitations=limitations,
            degraded=degraded_categories,
        )

        # 7. Synthesize Privacy Findings
        findings: list[PrivacyFinding] = list(capability_findings)

        # Add findings for third-party SDKs
        for sdk in all_detected_sdks:
            sdk_sev = Severity.INFORMATIONAL
            if sdk.category.value in ("advertising", "tracking", "attribution"):
                sdk_sev = Severity.LOW

            sdk_ev = list(sdk.evidence)
            if not sdk_ev:
                sdk_ev = [
                    Evidence(
                        description=f"Matched third-party SDK: {sdk.name}",
                        location=f"sdk:{sdk.category.value}",
                        snippet=f"Matched {sdk.name}",
                    )
                ]

            cat_title = sdk.category.value.replace("_", " ").capitalize()
            desc = (
                sdk.description or f"Third-party library {sdk.name} detected via static inspection."
            )
            findings.append(
                PrivacyFinding(
                    id=f"PRIV-SDK-{sdk.id.upper().replace('.', '-')}",
                    category=sdk.category.value,
                    title=f"Third-Party {cat_title} SDK Detected: {sdk.name}",
                    description=desc,
                    severity=sdk_sev,
                    confidence=sdk.confidence,
                    evidence=sdk_ev,
                    limitations=[
                        "Static presence does not establish whether or when this SDK transmits "
                        "user data at runtime."
                    ],
                )
            )

        # Global analysis limitations (informational static-analysis disclaimer)
        limitations.append(
            "Static analysis cannot establish actual runtime data collection, transmission, "
            "or dynamic execution."
        )

        # Status resolution
        overall_status = AnalysisStatus.COMPLETE
        if inspection.status == AnalysisStatus.FAILED:
            overall_status = AnalysisStatus.FAILED
        elif inspection.status == AnalysisStatus.PARTIAL or degraded_categories:
            overall_status = AnalysisStatus.PARTIAL


        return PrivacyResult(
            status=overall_status,
            package_name=pkg_name,
            version_name=ver_name,
            version_code=ver_code,
            permissions=perm_result,
            trackers=tracker_result,
            advertising=advertising_result,
            analytics=analytics_result,
            telemetry=telemetry_result,
            endpoints=endpoint_result,
            data_collection=data_collection_result,
            findings=sorted(findings, key=lambda f: (f.severity.value, f.id)),
            warnings=sorted(set(warnings)),
            errors=sorted(set(errors)),
            limitations=sorted(set(limitations)),
        )

    def _build_evidence_index(
        self,
        inspection: InspectionResult,
        package: AndroidPackage | None,
        package_name: str | None,
    ) -> EvidenceIndex:
        """Extract and index classes, methods, strings, APIs, domains, and permissions."""
        classes: set[str] = set()
        methods: set[str] = set()
        strings: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        apis: set[str] = set()
        permissions: set[str] = set()

        # Classes, methods, APIs from DEX inspection
        if inspection.dex:
            for df in inspection.dex.dex_files:
                if df.inventory:
                    for c in df.inventory.classes:
                        classes.add(c.name)
                    for m in df.inventory.methods:
                        methods.add(m.name)
                        methods.add(f"{m.class_name}.{m.name}")
                if df.api_references:
                    apis.update(df.api_references)

            # Direct fallback if inventory/api_references attached
            inv = getattr(inspection.dex, "inventory", None)
            if inv:
                for c in getattr(inv, "classes", []):
                    classes.add(c.name)
                for m in getattr(inv, "methods", []):
                    methods.add(m.name)
                    methods.add(f"{m.class_name}.{m.name}")
            apis.update(getattr(inspection.dex, "api_references", None) or [])

            # Strings from DEX
            if hasattr(inspection.dex, "strings") and inspection.dex.strings:
                for s in inspection.dex.strings:
                    strings.add(s.value)

        # Network URLs & Domains
        if inspection.network:
            for d in inspection.network.domains:
                domains.add(d.domain.strip().lower())
            for u in inspection.network.urls:
                urls.add(u.url.strip())

        # Declared permissions
        if inspection.manifest and inspection.manifest.permissions:
            for p in inspection.manifest.permissions:
                if isinstance(p, str):
                    permissions.add(p)
                elif hasattr(p, "name"):
                    permissions.add(p.name)

        return EvidenceIndex(
            classes=classes,
            methods=methods,
            strings=strings,
            domains=domains,
            urls=urls,
            apis=apis,
            permissions=permissions,
            package_name=package_name,
        )

    def _safe_run(
        self,
        category: str,
        func: Callable[[], _T],
        default: _T,
        limitations: list[str],
        degraded: list[str] | None = None,
    ) -> _T:
        """Run an analysis task with error isolation."""
        try:
            return func()
        except Exception as exc:
            _log.exception("Privacy analysis failed for category %s: %s", category, exc)
            limitations.append(f"Privacy analysis failed for {category}: {exc}")
            if degraded is not None:
                degraded.append(category)
            return default

