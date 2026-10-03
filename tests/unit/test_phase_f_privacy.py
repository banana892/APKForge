"""Unit tests for Phase F: Privacy, Tracker & Ads Intelligence Layer.

Covers:
- Known SDK package signature detection
- Known SDK domain classification
- Unknown domain preservation
- Potentially sensitive endpoint classification
- Sensitive permission correlation (API + component)
- Sensitive API indicators (telephony IDs, clipboard, dynamic code, reflection, scheduling)
- Boot receiver persistence indicators
- Multiple correlated indicators
- Conflicting and incomplete evidence
- False positive prevention on generic words
- SDK present without network usage evidence
- PrivacyReport structure and sections (no privacy score, no spyware probability)
- Phase B security cross-check
- Programmatic PrivacyAnalysisService
- CLI --json ANSI-free output with FORCE_COLOR set
- CLI --report file output
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus, Confidence, Evidence, Severity
from apkforge.inspection.models import (
    BroadcastReceiverInfo,
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    DomainReference,
    EvidenceSource,
    InspectionResult,
    IntentFilterInfo,
    ManifestInspection,
    MethodInfo,
    NetworkInspection,
    PermissionInfo,
    StringReference,
    URLReference,
)
from apkforge.privacy import (
    AnalysisCompleteness,
    BehaviorAnalyzer,
    EndpointCategory,
    EvidenceIndex,
    EvidenceState,
    PermissionUsageStatus,
    PhaseBComparisonResult,
    PrivacyAnalysisService,
    PrivacyEngine,
    PrivacyFinding,
    PrivacyReport,
    PrivacyResult,
    compare_privacy_with_security,
)
from apkforge.security.models import SecurityFinding, SecurityResult, SecurityStatus
from tests.fixtures import create_synthetic_apk

runner = CliRunner()


def test_known_sdk_package_signature() -> None:
    """Known SDK package namespace triggers detection with traceable evidence and confidence."""
    engine = PrivacyEngine()
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="h_admob",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.google.android.gms.ads.AdView"),
                ClassInfo(name="com.google.android.gms.ads.MobileAds"),
            ]
        ),
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        dex=DEXInspection(dex_files=[dex_file]),
    )

    result = engine.analyze(inspection)
    admob = next(
        (
            sdk
            for sdk in result.advertising.detected_advertising_sdks
            if sdk.id == "ad.google.admob"
        ),
        None,
    )
    assert admob is not None
    assert admob.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
    assert "com.google.android.gms.ads" in admob.matched_packages
    assert any("com.google.android.gms.ads.AdView" in c for c in admob.matched_classes)
    assert admob.actual_network_use_observed is False
    assert admob.network_use_status == "CANNOT_DETERMINE_STATICALLY"
    assert "Static presence does not prove" in admob.network_use_determination

    finding = next((f for f in result.findings if f.id == "PRIV-SDK-AD-GOOGLE-ADMOB"), None)
    assert finding is not None
    assert finding.evidence_state == EvidenceState.OBSERVED
    assert finding.is_direct is True
    assert "Google AdMob" in finding.title
    assert "malware" not in finding.title.lower()
    assert "spyware" not in finding.title.lower()


def test_known_sdk_domain_classification() -> None:
    """Known SDK domain is classified correctly with provenance and disclaimer."""
    engine = PrivacyEngine()
    network = NetworkInspection(
        domains=[
            DomainReference(domain="googleads.g.doubleclick.net"),
            DomainReference(domain="sentry.io"),
        ]
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        network=network,
    )

    result = engine.analyze(inspection)
    ep_map = {ep.endpoint: ep for ep in result.endpoints.classified_endpoints}

    assert "googleads.g.doubleclick.net" in ep_map
    ad_ep = ep_map["googleads.g.doubleclick.net"]
    assert ad_ep.category == EndpointCategory.ADVERTISING
    assert ad_ep.associated_sdk == "Google AdMob / Google Mobile Ads"
    assert ad_ep.transmission_verified is False
    assert "does not prove data is transmitted" in ad_ep.disclaimer

    sentry_ep = ep_map["sentry.io"]
    assert sentry_ep.category == EndpointCategory.CRASH_REPORTING
    assert sentry_ep.associated_sdk == "Sentry"


def test_unknown_domain_preservation() -> None:
    """Unmapped domain remains UNKNOWN and preserves raw evidence without guessing."""
    engine = PrivacyEngine()
    network = NetworkInspection(
        domains=[DomainReference(domain="unrecognized-custom-endpoint.org")]
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        network=network,
    )

    result = engine.analyze(inspection)
    ep = next(
        ep
        for ep in result.endpoints.classified_endpoints
        if ep.endpoint == "unrecognized-custom-endpoint.org"
    )
    assert ep.category == EndpointCategory.UNKNOWN
    assert ep.raw_evidence == "unrecognized-custom-endpoint.org"
    assert ep.is_first_party is False
    assert "unknown" in result.endpoints.by_category


def test_potentially_sensitive_endpoints() -> None:
    """Raw IP endpoints and unencrypted HTTP auth URLs are classified as potentially sensitive."""
    engine = PrivacyEngine()
    network = NetworkInspection(
        domains=[DomainReference(domain="192.168.1.50")],
        urls=[
            URLReference(
                url="http://example.com/api/v1/auth/login",
                source=EvidenceSource(file="classes.dex"),
            ),
            URLReference(
                url="https://example.com/api/v1/content", source=EvidenceSource(file="classes.dex")
            ),
        ],
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        network=network,
    )

    result = engine.analyze(inspection)
    ep_map = {ep.endpoint: ep for ep in result.endpoints.classified_endpoints}

    assert ep_map["192.168.1.50"].category == EndpointCategory.POTENTIALLY_SENSITIVE
    assert "IP address" in ep_map["192.168.1.50"].purpose

    assert (
        ep_map["http://example.com/api/v1/auth/login"].category
        == EndpointCategory.POTENTIALLY_SENSITIVE
    )
    assert "Unencrypted HTTP" in ep_map["http://example.com/api/v1/auth/login"].purpose


def test_permission_component_and_api_correlation() -> None:
    """Sensitive permissions correlate with APIs and manifest components, or report uncertainty."""
    engine = PrivacyEngine()

    manifest = ManifestInspection(
        package_name="com.test.app",
        permissions=[
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
            PermissionInfo(name="android.permission.RECEIVE_BOOT_COMPLETED"),
            PermissionInfo(name="android.permission.RECORD_AUDIO"),
            PermissionInfo(name="android.permission.CAMERA"),
        ],
        receivers=[
            BroadcastReceiverInfo(
                name="com.test.app.BootReceiver",
                intent_filters=[IntentFilterInfo(actions=["android.intent.action.BOOT_COMPLETED"])],
            )
        ],
    )

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="h_corr",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.test.app.LocationHelper"),
                ClassInfo(name="com.test.app.BootReceiver"),
            ]
        ),
        api_references=[
            "android.location.LocationManager",
        ],
    )

    inspection = InspectionResult(
        manifest=manifest,
        dex=DEXInspection(dex_files=[dex_file]),
    )

    result = engine.analyze(inspection)
    usage_map = {u.permission: u for u in result.permissions.usage_details}

    # 1. Location: declared + API observed
    loc = usage_map["android.permission.ACCESS_FINE_LOCATION"]
    assert loc.usage_status in (
        PermissionUsageStatus.DECLARED_AND_REFERENCED,
        PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION,
    )
    assert "android.location.LocationManager" in loc.related_apis

    # 2. Boot: declared + receiver component observed
    boot = usage_map["android.permission.RECEIVE_BOOT_COMPLETED"]
    assert boot.usage_status == PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION
    assert "com.test.app.BootReceiver" in boot.classes

    # 3. Camera: declared only without API/component references
    cam = usage_map["android.permission.CAMERA"]
    assert cam.usage_status == PermissionUsageStatus.DECLARED_ONLY
    assert any("actual runtime use remains uncertain" in lim for lim in cam.limitations)


def test_static_behavior_indicators() -> None:
    """Static behavior analyzer catches telephony IDs, clipboard, dynamic code,
    reflection, and scheduling.
    """
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=2000,
        sha256="h_behav",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="android.content.ClipboardManager"),
                ClassInfo(name="dalvik.system.DexClassLoader"),
                ClassInfo(name="androidx.work.WorkManager"),
                ClassInfo(name="android.webkit.WebView"),
            ],
            methods=[
                MethodInfo(name="getDeviceId", class_name="android.telephony.TelephonyManager"),
                MethodInfo(name="getPrimaryClip", class_name="android.content.ClipboardManager"),
                MethodInfo(name="loadClass", class_name="dalvik.system.DexClassLoader"),
                MethodInfo(name="invoke", class_name="java.lang.reflect.Method"),
            ],
        ),
        api_references=[
            "android.content.ClipboardManager",
            "dalvik.system.DexClassLoader",
            "androidx.work.WorkManager",
            "android.webkit.WebView",
            "java.lang.reflect.Method",
        ],
    )
    dex_strings = [
        StringReference(value="ANDROID_ID", dex_file="classes.dex"),
        StringReference(value="android.os.SystemProperties", dex_file="classes.dex"),
    ]

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        dex=DEXInspection(dex_files=[dex_file], strings=dex_strings),
    )

    analyzer = BehaviorAnalyzer()
    idx = EvidenceIndex(
        classes={
            "android.content.ClipboardManager",
            "dalvik.system.DexClassLoader",
            "androidx.work.WorkManager",
            "android.webkit.WebView",
        },
        methods={"getDeviceId", "getPrimaryClip", "loadClass", "invoke"},
        apis={
            "android.content.ClipboardManager",
            "dalvik.system.DexClassLoader",
            "androidx.work.WorkManager",
            "android.webkit.WebView",
            "java.lang.reflect.Method",
        },
        strings={"ANDROID_ID", "android.os.SystemProperties"},
    )
    findings = analyzer.analyze(inspection, idx)
    finding_ids = [f.id for f in findings]

    assert "PRIV-API-DEVICE-IDENTIFIER" in finding_ids
    assert "PRIV-API-CLIPBOARD" in finding_ids
    assert "PRIV-API-DYNAMIC-CODE" in finding_ids
    assert "PRIV-API-SCHEDULING" in finding_ids
    assert "PRIV-API-WEBVIEW" in finding_ids
    assert "PRIV-API-REFLECTION" in finding_ids

    # Every finding must have concrete evidence locations and values
    for f in findings:
        assert len(f.evidence_locations) >= 1
        assert len(f.evidence_values) >= 1
        assert f.evidence_state == EvidenceState.OBSERVED
        assert f.analysis_completeness == AnalysisCompleteness.COMPLETE
        assert f.remediation_relevance is not None


def test_sdk_present_without_network_usage_evidence() -> None:
    """SDK detected in bytecode without network endpoints clearly states network
    behavior cannot be determined statically.
    """
    engine = PrivacyEngine()
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="h_sentry",
        inventory=DEXClassInventory(classes=[ClassInfo(name="io.sentry.Sentry")]),
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.test.app"),
        dex=DEXInspection(dex_files=[dex_file]),
        network=NetworkInspection(domains=[]),  # No network endpoints!
    )

    result = engine.analyze(inspection)
    assert len(result.telemetry.detected_telemetry_sdks) == 1
    sentry = result.telemetry.detected_telemetry_sdks[0]
    assert sentry.id == "telemetry.sentry"
    assert sentry.actual_network_use_observed is False
    assert sentry.network_use_status == "CANNOT_DETERMINE_STATICALLY"
    assert "network use cannot be determined statically" in sentry.network_use_determination.lower()


def test_false_positive_prevention_on_internal_generic_classes() -> None:
    """Internal app classes with generic names (Tracker, Analytics) do not trigger
    third-party catalog matches.
    """
    engine = PrivacyEngine()
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="h_custom",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.myapp.core.InternalTracker"),
                ClassInfo(name="com.myapp.util.AnalyticsHelper"),
                ClassInfo(name="com.myapp.ad.CustomAdBanner"),
            ]
        ),
    )
    dex_strings = [
        StringReference(value="ad", dex_file="classes.dex"),
        StringReference(value="tracking", dex_file="classes.dex"),
        StringReference(value="analytics", dex_file="classes.dex"),
    ]
    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.myapp"),
        dex=DEXInspection(dex_files=[dex_file], strings=dex_strings),
    )

    result = engine.analyze(inspection)
    assert result.trackers.total_trackers == 0
    assert result.advertising.total_advertising_sdks == 0
    assert result.analytics.total_analytics_sdks == 0


def test_incomplete_or_truncated_analysis_marks_partial() -> None:
    """Degraded or partial intake/inspection marks PrivacyResult as PARTIAL without
    dropping data.
    """
    engine = PrivacyEngine()
    inspection = InspectionResult(
        status=AnalysisStatus.PARTIAL,
        manifest=ManifestInspection(
            package_name="com.test.app",
            permissions=[PermissionInfo(name="android.permission.INTERNET")],
        ),
        limitations=["Embedded DEX inspection truncated due to size threshold."],
    )

    result = engine.analyze(inspection)
    assert result.status == AnalysisStatus.PARTIAL
    assert any("truncated" in lim for lim in result.limitations)


def test_privacy_report_structure_and_no_score() -> None:
    """PrivacyReport separates all sections and strictly avoids scores or spyware probability."""
    engine = PrivacyEngine()
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="h_rep",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.google.android.gms.ads.AdView"),
                ClassInfo(name="android.location.LocationManager"),
            ]
        ),
        api_references=["android.location.LocationManager"],
    )
    inspection = InspectionResult(
        manifest=ManifestInspection(
            package_name="com.test.reportapp",
            version_name="1.5.0",
            permissions=[
                PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
                PermissionInfo(name="android.permission.INTERNET"),
            ],
        ),
        dex=DEXInspection(dex_files=[dex_file]),
        network=NetworkInspection(domains=[DomainReference(domain="googleads.g.doubleclick.net")]),
    )

    result = engine.analyze(inspection)
    report = result.to_report()

    assert isinstance(report, PrivacyReport)
    assert report.package_name == "com.test.reportapp"
    assert report.version_name == "1.5.0"
    assert len(report.permissions.declared_permissions) == 2
    assert len(report.sdks.detected_sdks) >= 1
    assert report.endpoints.total_endpoints >= 1

    md = report.to_markdown()
    assert "Section A: Permissions" in md
    assert "Section B: Components & Capabilities" in md
    assert "Section C: SDK & Library Indicators" in md
    assert "Section D: Domains & Endpoints" in md
    assert "Section E: Sensitive API Indicators" in md
    assert "Section F: Correlated Findings" in md
    assert "Section G: Unknown / Partial Analysis" in md
    assert "Section H: Evidence Limitations" in md

    # Security Boundaries Verification
    assert "privacy score" not in md.lower()
    assert "spyware probability" not in md.lower()
    assert "malware" not in md.lower()
    assert "safe" not in md.lower()

    # JSON export
    report_json = report.to_json()
    parsed = json.loads(report_json)
    assert "permissions" in parsed
    assert "sdks" in parsed
    assert "endpoints" in parsed
    assert "sensitive_apis" in parsed
    assert "correlated_findings" in parsed
    assert "unknown_partial" in parsed


def test_phase_b_security_cross_check() -> None:
    """compare_privacy_with_security reconciles findings without altering either analyzer."""
    priv_result = PrivacyResult(
        package_name="com.test.crosscheck",
        findings=[
            PrivacyFinding(
                id="PRIV-REC-BOOT",
                category="persistence",
                title="Boot & Package Replacement Receivers",
                description="Boot receiver detected.",
                evidence_locations=["receiver:com.test.BootReceiver:action:BOOT_COMPLETED"],
                evidence_values=["BOOT_COMPLETED"],
                evidence_state=EvidenceState.OBSERVED,
            ),
            PrivacyFinding(
                id="PRIV-SDK-AD-GOOGLE-ADMOB",
                category="advertising",
                title="Third-Party Advertising SDK Detected: Google AdMob",
                description="AdMob library detected.",
                evidence_locations=["class:com.google.android.gms.ads.AdView"],
                evidence_state=EvidenceState.OBSERVED,
            ),
        ],
    )

    sec_result = SecurityResult(
        status=AnalysisStatus.COMPLETE,
        security_status=SecurityStatus.FINDINGS_PRESENT,
        findings=[
            SecurityFinding(
                id="SEC-SURV-PERSISTENCE-001",
                category="persistence",
                title="Application Registers Boot Completed Receiver",
                description="Receiver listening to BOOT_COMPLETED.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=[Evidence(description="Boot receiver", location="receiver:BootReceiver")],
            ),
            SecurityFinding(
                id="SEC-CONF-CLEARTEXT-001",
                category="configuration",
                title="Cleartext HTTP Traffic Permitted",
                description="Network config permits HTTP.",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=[Evidence(description="Cleartext permitted", location="manifest")],
            ),
        ],
    )

    comp = compare_privacy_with_security(priv_result, sec_result)
    assert isinstance(comp, PhaseBComparisonResult)
    assert len(comp.overlapping_findings) == 1
    assert comp.overlapping_findings[0]["topic"] == "Boot Persistence"
    assert len(comp.new_privacy_findings) == 1
    assert comp.new_privacy_findings[0]["id"] == "PRIV-SDK-AD-GOOGLE-ADMOB"
    assert len(comp.security_only_findings) == 1
    assert comp.security_only_findings[0]["id"] == "SEC-CONF-CLEARTEXT-001"
    assert len(comp.strengthened_findings) == 1


def test_programmatic_privacy_analysis_service(tmp_path: Path) -> None:
    """PrivacyAnalysisService exposes class and instance methods returning
    structured PrivacyResult.
    """
    apk_path = tmp_path / "service_test.apk"
    create_synthetic_apk(apk_path, package_name="com.example.serviceapp", version_name="1.0")

    result = PrivacyAnalysisService.analyze(apk_path)
    assert isinstance(result, PrivacyResult)
    assert result.package_name == "com.example.serviceapp"

    service = PrivacyAnalysisService()
    result2 = service.run_analysis(apk_path)
    assert result2.package_name == "com.example.serviceapp"

    report = PrivacyAnalysisService.generate_report(result)
    assert isinstance(report, PrivacyReport)


def test_cli_privacy_json_deterministic_and_ansi_free_with_force_color(
    tmp_path: Path, monkeypatch
) -> None:
    """CLI apkforge privacy --json must remain strictly ANSI-free even when FORCE_COLOR is set."""
    apk_path = tmp_path / "ansi_test.apk"
    create_synthetic_apk(apk_path, package_name="com.example.ansitest", version_name="3.0")

    # Test with FORCE_COLOR=3 and FORCE_COLOR=1
    for color_val in ("1", "3"):
        monkeypatch.setenv("FORCE_COLOR", color_val)
        res = runner.invoke(app, ["privacy", str(apk_path), "--json"])
        assert res.exit_code == 0
        raw_output = res.stdout

        # Verify no ANSI escape codes are in raw output
        assert "\x1b[" not in raw_output
        assert "\033[" not in raw_output

        # Verify valid JSON parse
        parsed = json.loads(raw_output)
        assert parsed["package_name"] == "com.example.ansitest"


def test_cli_privacy_report_file_output(tmp_path: Path) -> None:
    """CLI apkforge privacy <apk> --report <path> writes structured report to file."""
    apk_path = tmp_path / "report_cli.apk"
    create_synthetic_apk(apk_path, package_name="com.example.clireport", version_name="1.1")

    # 1. Markdown report
    md_path = tmp_path / "report.md"
    res_md = runner.invoke(app, ["privacy", str(apk_path), "--report", str(md_path)])
    assert res_md.exit_code == 0
    assert md_path.exists()
    content_md = md_path.read_text(encoding="utf-8")
    assert "# Privacy & Tracker Intelligence Report" in content_md
    assert "com.example.clireport" in content_md

    # 2. JSON report
    json_path = tmp_path / "report.json"
    res_json = runner.invoke(app, ["privacy", str(apk_path), "--report", str(json_path)])
    assert res_json.exit_code == 0
    assert json_path.exists()
    data_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert data_json["package_name"] == "com.example.clireport"
    assert "permissions" in data_json
    assert "sdks" in data_json
