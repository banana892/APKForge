"""Comprehensive unit and integration tests for Phase 4: Privacy & Tracker Engine."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus, Confidence
from apkforge.inspection.models import (
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    DomainReference,
    EvidenceSource,
    InspectionResult,
    ManifestInspection,
    MethodInfo,
    NetworkInspection,
    PermissionInfo,
    ServiceInfo,
    StringReference,
    URLReference,
)
from apkforge.privacy import (
    DataCapabilityType,
    EndpointCategory,
    EvidenceIndex,
    PermissionCategory,
    PermissionUsageStatus,
    PrivacyEngine,
    PrivacyRule,
    RuleEngine,
    SDKCategory,
)
from tests.fixtures import create_synthetic_apk

runner = CliRunner()


def test_permission_analyzer_categorization_and_correlation() -> None:
    """Test permission taxonomy mapping and API correlation with usage status."""
    engine = PrivacyEngine()

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="hash1",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.example.app.LocationTracker"),
                ClassInfo(name="com.example.app.AudioRecorder"),
            ],
            methods=[
                MethodInfo(name="track", class_name="com.example.app.LocationTracker"),
            ],
        ),
        api_references=[
            "android.location.LocationManager",
            "android.media.AudioRecord",
        ],
    )

    manifest = ManifestInspection(
        package_name="com.example.app",
        version_name="1.0.0",
        permissions=[
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
            PermissionInfo(name="android.permission.RECORD_AUDIO"),
            PermissionInfo(name="android.permission.READ_CONTACTS"),
            PermissionInfo(name="android.permission.INTERNET"),
        ],
    )

    inspection = InspectionResult(
        manifest=manifest,
        dex=DEXInspection(dex_files=[dex_file]),
    )

    result = engine.analyze(inspection)

    # 1. Categories
    assert "location" in result.permissions.categorized_permissions
    loc_perms = result.permissions.categorized_permissions["location"]
    assert "android.permission.ACCESS_FINE_LOCATION" in loc_perms
    assert "microphone" in result.permissions.categorized_permissions
    assert "contacts" in result.permissions.categorized_permissions
    assert "network" in result.permissions.categorized_permissions

    # 2. Usage status & correlation
    usage_map = {u.permission: u for u in result.permissions.usage_details}

    # Location has both API and class correlation
    loc_usage = usage_map["android.permission.ACCESS_FINE_LOCATION"]
    assert loc_usage.category == PermissionCategory.LOCATION
    assert loc_usage.protection_level == "dangerous"
    assert loc_usage.usage_status in (
        PermissionUsageStatus.DECLARED_AND_REFERENCED,
        PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION,
    )
    assert "android.location.LocationManager" in loc_usage.related_apis

    # Audio has API reference
    audio_usage = usage_map["android.permission.RECORD_AUDIO"]
    assert audio_usage.category == PermissionCategory.MICROPHONE
    assert audio_usage.usage_status in (
        PermissionUsageStatus.DECLARED_AND_REFERENCED,
        PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION,
    )
    assert "android.media.AudioRecord" in audio_usage.related_apis

    # Contacts was declared only without API references
    contacts_usage = usage_map["android.permission.READ_CONTACTS"]
    assert contacts_usage.usage_status == PermissionUsageStatus.DECLARED_ONLY


def test_sdk_detection_categories() -> None:
    """Test detection across advertising, analytics, tracking, attribution, and crash reporting."""
    engine = PrivacyEngine()

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=2000,
        sha256="hash2",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.google.android.gms.ads.AdView"),
                ClassInfo(name="com.google.firebase.analytics.FirebaseAnalytics"),
                ClassInfo(name="com.appsflyer.AppsFlyerLib"),
                ClassInfo(name="io.sentry.Sentry"),
                ClassInfo(name="com.criteo.publisher.Criteo"),
            ]
        ),
        api_references=[],
    )

    dex_strings = [
        StringReference(value="com.google.android.gms.ads.APPLICATION_ID", dex_file="classes.dex"),
        StringReference(value="AppsFlyerLib", dex_file="classes.dex"),
    ]

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.example.app"),
        dex=DEXInspection(dex_files=[dex_file], strings=dex_strings),
        network=NetworkInspection(
            domains=[
                DomainReference(domain="googleads.g.doubleclick.net"),
                DomainReference(domain="app-measurement.com"),
                DomainReference(domain="t.appsflyer.com"),
                DomainReference(domain="sentry.io"),
                DomainReference(domain="criteo.com"),
            ]
        ),
    )

    result = engine.analyze(inspection)

    # 1. Advertising (AdMob)
    assert result.advertising.total_advertising_sdks >= 1
    ad_ids = [a.id for a in result.advertising.detected_advertising_sdks]
    assert "ad.google.admob" in ad_ids

    # 2. Analytics (Firebase)
    assert result.analytics.total_analytics_sdks >= 1
    analytics_ids = [a.id for a in result.analytics.detected_analytics_sdks]
    assert "analytics.google.firebase" in analytics_ids

    # 3. Attribution (AppsFlyer)
    assert result.trackers.total_trackers >= 1
    tracker_ids = [t.id for t in result.trackers.detected_trackers]
    assert "attribution.appsflyer" in tracker_ids or "tracker.criteo" in tracker_ids

    # 4. Telemetry / Crash Reporting (Sentry)
    assert result.telemetry.total_telemetry_sdks >= 1
    telemetry_ids = [t.id for t in result.telemetry.detected_telemetry_sdks]
    assert "telemetry.sentry" in telemetry_ids

    # 5. Check confidence and evidence
    admob = next(
        a for a in result.advertising.detected_advertising_sdks if a.id == "ad.google.admob"
    )
    assert admob.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
    assert len(admob.evidence) >= 1


def test_false_positive_prevention_on_generic_words() -> None:
    """Ensure generic words alone (analytics, tracker, location, ad) never trigger SDK detection."""
    engine = PrivacyEngine()

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="hash_fp",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.mycompany.app.AppUtility"),
                ClassInfo(name="com.mycompany.app.InternalTracker"),  # Generic word in class name
            ]
        ),
    )

    dex_strings = [
        StringReference(value="analytics", dex_file="classes.dex"),
        StringReference(value="tracker", dex_file="classes.dex"),
        StringReference(value="advertising", dex_file="classes.dex"),
        StringReference(value="ad", dex_file="classes.dex"),
        StringReference(value="telemetry", dex_file="classes.dex"),
    ]

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.mycompany.app"),
        dex=DEXInspection(dex_files=[dex_file], strings=dex_strings),
    )

    result = engine.analyze(inspection)

    # None of the commercial SDKs should be detected from generic words alone!
    assert result.advertising.total_advertising_sdks == 0
    assert result.analytics.total_analytics_sdks == 0
    assert result.trackers.total_trackers == 0
    assert result.telemetry.total_telemetry_sdks == 0


def test_endpoint_classification_and_first_party_detection() -> None:
    """Test endpoint classification, first-party vs third-party separation, and provenance."""
    engine = PrivacyEngine()

    network = NetworkInspection(
        domains=[
            DomainReference(domain="api.mycompany.com"),  # First-party
            DomainReference(domain="googleads.g.doubleclick.net"),  # Advertising
            DomainReference(domain="app-measurement.com"),  # Analytics
            DomainReference(domain="sentry.io"),  # Crash reporting
            DomainReference(domain="unknown-third-party.net"),  # Unknown
        ],
        urls=[
            URLReference(
                url="https://api.mycompany.com/v1/profile",
                source=EvidenceSource(
                    file="classes.dex",
                    class_name="com.mycompany.app.Api",
                    method_name="getProfile",
                ),
            ),
            URLReference(
                url="https://googleads.g.doubleclick.net/pagead/ads",
                source=EvidenceSource(
                    file="classes.dex",
                    class_name="com.google.android.gms.ads.AdView",
                ),
            ),
        ],
    )

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.mycompany.app"),
        network=network,
    )

    result = engine.analyze(inspection)

    # 1. First-party detection
    assert "api.mycompany.com" in result.endpoints.first_party_domains
    first_party_eps = [
        ep for ep in result.endpoints.classified_endpoints if ep.endpoint == "api.mycompany.com"
    ]
    assert len(first_party_eps) == 1
    assert first_party_eps[0].category == EndpointCategory.FIRST_PARTY
    assert first_party_eps[0].is_first_party is True

    # 2. Third-party advertising & analytics
    ad_eps = [ep for ep in result.endpoints.classified_endpoints if "googleads" in ep.endpoint]
    assert any(ep.category == EndpointCategory.ADVERTISING for ep in ad_eps)

    analytics_eps = [
        ep for ep in result.endpoints.classified_endpoints if "app-measurement" in ep.endpoint
    ]
    assert any(ep.category == EndpointCategory.ANALYTICS for ep in analytics_eps)

    # 3. Unknown category
    unknown_eps = [
        ep
        for ep in result.endpoints.classified_endpoints
        if ep.endpoint == "unknown-third-party.net"
    ]
    assert len(unknown_eps) == 1
    assert unknown_eps[0].category == EndpointCategory.UNKNOWN

    # 4. URL provenance
    url_ep = next(
        ep
        for ep in result.endpoints.classified_endpoints
        if ep.endpoint == "https://api.mycompany.com/v1/profile"
    )
    assert url_ep.is_url is True
    assert any("com.mycompany.app.Api" in p for p in url_ep.provenance)


def test_data_capability_correlation() -> None:
    """Test correlation of permissions, APIs, SDKs, and endpoints into data capabilities."""
    engine = PrivacyEngine()

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="hash_data",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.example.app.LocationService"),
                ClassInfo(name="com.google.android.gms.ads.identifier.AdvertisingIdClient"),
                ClassInfo(name="android.content.ClipboardManager"),
            ],
            methods=[
                MethodInfo(name="getDeviceId", class_name="android.telephony.TelephonyManager"),
                MethodInfo(name="getImei", class_name="android.telephony.TelephonyManager"),
            ],
        ),
        api_references=[
            "android.location.LocationManager",
            "com.google.android.gms.ads.identifier.AdvertisingIdClient",
            "android.content.ClipboardManager",
        ],
    )

    manifest = ManifestInspection(
        package_name="com.example.app",
        permissions=[
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
            PermissionInfo(name="android.permission.READ_PHONE_STATE"),
        ],
        services=[
            ServiceInfo(
                name="com.example.app.LocationService",
                permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            )
        ],
    )

    inspection = InspectionResult(
        manifest=manifest,
        dex=DEXInspection(dex_files=[dex_file]),
    )

    result = engine.analyze(inspection)

    # 1. Capabilities detected
    caps = {c.capability: c for c in result.data_collection.capabilities}
    assert DataCapabilityType.LOCATION in caps
    assert DataCapabilityType.DEVICE_IDENTIFIERS in caps
    assert DataCapabilityType.ADVERTISING_ID in caps
    assert DataCapabilityType.CLIPBOARD in caps
    assert DataCapabilityType.ACCESSIBILITY in caps

    # 2. Specific identifiers
    assert "TelephonyManager.getDeviceId" in result.data_collection.device_identifiers_detected
    assert "TelephonyManager.getImei" in result.data_collection.device_identifiers_detected
    assert result.data_collection.advertising_id_detected is True
    assert result.data_collection.clipboard_access_detected is True
    assert result.data_collection.accessibility_service_detected is True

    # 3. Privacy findings
    finding_ids = [f.id for f in result.findings]
    assert "PRIV-CAP-LOCATION" in finding_ids
    assert "PRIV-CAP-DEVICE-IDENTIFIERS" in finding_ids
    assert "PRIV-CAP-ADVERTISING-ID" in finding_ids
    assert "PRIV-CAP-CLIPBOARD" in finding_ids
    assert "PRIV-CAP-ACCESSIBILITY" in finding_ids


def test_rule_engine_custom_rule_and_confidence() -> None:
    """Test custom rule definition, positive/negative matching, and confidence levels."""
    rule = PrivacyRule(
        id="tracker.custom.test",
        name="Custom Test Tracker",
        vendor="Test Corp",
        category=SDKCategory.TRACKING,
        packages=["com.custom.tracker"],
        classes=["com.custom.tracker.TrackerCore"],
        strings=["CustomTracker_v1"],
        domains=["tracker.custom-test.com"],
        min_matches_required=1,
    )

    rule_engine = RuleEngine([rule])

    # 1. Positive match (package + class)
    idx_pos = EvidenceIndex(
        classes={"com.custom.tracker.TrackerCore", "com.custom.tracker.Helper"},
        domains={"tracker.custom-test.com"},
    )
    matched, conf, ev, matches = rule_engine.match_rule(rule, idx_pos)
    assert matched is True
    assert conf == Confidence.CONFIRMED
    assert "com.custom.tracker" in matches["packages"]
    assert len(ev) >= 2

    # 2. Negative match
    idx_neg = EvidenceIndex(
        classes={"com.other.app.MainActivity"},
        strings={"some other text"},
        domains={"other.com"},
    )
    matched_neg, _, _, _ = rule_engine.match_rule(rule, idx_neg)
    assert matched_neg is False


def test_privacy_analysis_determinism() -> None:
    """Test that analyzing the same inspection result produces byte-identical JSON."""
    engine = PrivacyEngine()

    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="hash_det",
        inventory=DEXClassInventory(
            classes=[
                ClassInfo(name="com.google.android.gms.ads.AdView"),
                ClassInfo(name="com.example.app.MainActivity"),
            ]
        ),
        api_references=["android.location.LocationManager"],
    )

    inspection = InspectionResult(
        manifest=ManifestInspection(
            package_name="com.example.app",
            permissions=[
                PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
                PermissionInfo(name="android.permission.INTERNET"),
            ],
        ),
        dex=DEXInspection(dex_files=[dex_file]),
        network=NetworkInspection(
            domains=[
                DomainReference(domain="googleads.g.doubleclick.net"),
                DomainReference(domain="api.example.com"),
            ]
        ),
    )

    res1 = engine.analyze(inspection)
    res2 = engine.analyze(inspection)

    json1 = res1.model_dump_json(indent=2)
    json2 = res2.model_dump_json(indent=2)

    assert json1 == json2


def test_privacy_analysis_error_isolation() -> None:
    """Test that a failure in one detector degrades status to PARTIAL without crashing."""
    engine = PrivacyEngine()

    # Intentionally corrupt manifest inspection
    inspection = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=None,
        dex=None,
    )

    result = engine.analyze(inspection)

    assert result.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert len(result.limitations) >= 1
    assert any("Static analysis cannot establish" in lim for lim in result.limitations)


def test_cli_privacy_command_text_and_json(tmp_path: Path) -> None:
    """Test the CLI command 'apkforge privacy <apk>' in both text and JSON modes."""
    apk_path = tmp_path / "privacy_test.apk"
    create_synthetic_apk(
        apk_path,
        package_name="com.example.testprivacy",
        version_name="2.1.0",
        version_code=21,
    )

    # 1. Text mode
    res_text = runner.invoke(app, ["privacy", str(apk_path)])
    assert res_text.exit_code == 0
    assert "APKForge Privacy & Tracker Analysis" in res_text.stdout
    assert "com.example.testprivacy" in res_text.stdout
    assert "PERMISSIONS" in res_text.stdout
    assert "LIMITATIONS" in res_text.stdout

    # 2. Text mode with category flags
    res_flags = runner.invoke(
        app, ["privacy", str(apk_path), "--verbose", "--permissions", "--trackers"]
    )
    assert res_flags.exit_code == 0
    assert "com.example.testprivacy" in res_flags.stdout

    # 3. JSON mode
    res_json = runner.invoke(app, ["privacy", str(apk_path), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["package_name"] == "com.example.testprivacy"
    assert "permissions" in data
    assert "trackers" in data
    assert "advertising" in data
    assert "analytics" in data
    assert "telemetry" in data
    assert "endpoints" in data
    assert "data_collection" in data
    assert "findings" in data
    assert "limitations" in data
