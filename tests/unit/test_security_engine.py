"""Comprehensive unit and integration tests for Phase 5: Security Analysis Engine."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus, Confidence, Severity
from apkforge.diff.models import (
    AssetDiff,
    CertificateDiff,
    ChangeType,
    ComponentDiff,
    DEXDiff,
    DiffResult,
    DiffSummary,
    EmbeddedDiff,
    FileDiff,
    IdentityDiff,
    ManifestDiff,
    NativeDiff,
    NativeLibraryDiff,
    NetworkDiff,
    PackageIdentity,
    PermissionDiff,
    ResourceDiff,
    StringDiff,
)
from apkforge.inspection.models import (
    ApplicationInfo,
    AssetEntry,
    AssetInspection,
    BroadcastReceiverInfo,
    ContentProviderInfo,
    DEXFileInspection,
    DEXInspection,
    EmbeddedDEXInfo,
    EmbeddedFileInspection,
    EvidenceSource,
    InspectionResult,
    IntentFilterInfo,
    ManifestInspection,
    NativeInspection,
    NativeLibraryInspection,
    NetworkInspection,
    PermissionInfo,
    ServiceInfo,
    StringReference,
    URLReference,
)
from apkforge.security import (
    SecurityCategory,
    SecurityCondition,
    SecurityEngine,
    SecurityEvidenceIndex,
    SecurityRuleEngine,
    SecurityStatus,
)
from apkforge.security.vulnerabilities.crypto import mask_secret
from tests.fixtures import create_synthetic_apk

runner = CliRunner()


# ===========================================================================
# 1. Rule Engine & Conditions
# ===========================================================================


def test_rule_engine_loading_and_builtins() -> None:
    """Verify built-in security rules are properly discovered and loaded."""
    rule_engine = SecurityRuleEngine()
    rules = rule_engine.load_rules()
    assert len(rules) >= 20

    rule_ids = {r.id for r in rules}
    # Verify core rules from all 4 categories exist
    assert "SEC-SPY-AUDIO-001" in rule_ids
    assert "SEC-SPY-CAMERA-001" in rule_ids
    assert "SEC-SPY-LOCATION-001" in rule_ids
    assert "SEC-MAL-EXEC-001" in rule_ids
    assert "SEC-MAL-DYNLOAD-001" in rule_ids
    assert "SEC-VULN-DEBUGGABLE-001" in rule_ids
    assert "SEC-VULN-CLEARTEXT-001" in rule_ids
    assert "SEC-COMB-SURVEILLANCE-SUITE" in rule_ids


def test_rule_engine_logical_conditions() -> None:
    """Test ALL, ANY, NONE logical operator evaluation in rule engine."""
    index = SecurityEvidenceIndex()
    index.permissions.add("android.permission.RECORD_AUDIO")
    index.apis.add("android.media.AudioRecord")
    index.services.append(ServiceInfo(name="com.example.BackgroundService"))

    # 1. ALL matches
    cond_all = SecurityCondition(
        all=[
            SecurityCondition(permission="android.permission.RECORD_AUDIO"),
            SecurityCondition(api="android.media.AudioRecord"),
        ]
    )
    matches, ev = cond_all.evaluate(index)
    assert matches is True
    assert len(ev) == 2

    # 2. ALL fails if one missing
    cond_all_fail = SecurityCondition(
        all=[
            SecurityCondition(permission="android.permission.RECORD_AUDIO"),
            SecurityCondition(permission="android.permission.CAMERA"),
        ]
    )
    matches, _ = cond_all_fail.evaluate(index)
    assert matches is False

    # 3. ANY succeeds
    cond_any = SecurityCondition(
        any=[
            SecurityCondition(permission="android.permission.CAMERA"),
            SecurityCondition(permission="android.permission.RECORD_AUDIO"),
        ]
    )
    matches, ev = cond_any.evaluate(index)
    assert matches is True
    assert len(ev) == 1

    # 4. NONE operator
    cond_none = SecurityCondition(
        none=[
            SecurityCondition(permission="android.permission.CAMERA"),
        ]
    )
    matches, _ = cond_none.evaluate(index)
    assert matches is True


# ===========================================================================
# 2. Surveillance Capability Analyzers (Spyware Indicators)
# ===========================================================================


def test_audio_surveillance_analysis() -> None:
    """Verify background audio surveillance indicator detection."""
    manifest = ManifestInspection(
        package_name="com.example.covert",
        permissions=[
            PermissionInfo(name="android.permission.RECORD_AUDIO", protection_level="dangerous")
        ],
        services=[ServiceInfo(name="com.example.AudioService", is_foreground=True)],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["android.media.AudioRecord", "android.media.MediaRecorder"],
            )
        ]
    )
    network = NetworkInspection(
        urls=[
            URLReference(
                url="https://exfil.example.com/audio",
                host="exfil.example.com",
                source=EvidenceSource(file="classes.dex"),
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex, network=network)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    finding = next((f for f in result.findings if f.id == "SEC-SPY-AUDIO-001"), None)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.confidence in (Confidence.HIGH, Confidence.MEDIUM)
    assert any("RECORD_AUDIO" in ev.description for ev in finding.evidence)
    assert any("AudioRecord" in ev.description for ev in finding.evidence)
    assert any("AudioService" in ev.description for ev in finding.evidence)
    assert finding.limitations  # Must contain explicit limitation stating static analysis


def test_surveillance_suite_combination() -> None:
    """Verify multi-vector surveillance suite combination rule fires when >= 3 channels exist."""
    manifest = ManifestInspection(
        package_name="com.example.spyware",
        permissions=[
            PermissionInfo(name="android.permission.RECORD_AUDIO"),
            PermissionInfo(name="android.permission.CAMERA"),
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
        ],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=[
                    "android.media.AudioRecord",
                    "android.hardware.camera2.CameraManager",
                    "android.location.LocationManager",
                ],
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    finding = next((f for f in result.findings if f.id == "SEC-COMB-SURVEILLANCE-SUITE"), None)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.category == SecurityCategory.SPYWARE_INDICATOR


# ===========================================================================
# 3. Collection & Privacy Abuse Analyzers
# ===========================================================================


def test_sms_interception_indicators() -> None:
    """Verify SMS interception capabilities and OTP keywords detection."""
    manifest = ManifestInspection(
        package_name="com.example.smsstealer",
        permissions=[
            PermissionInfo(name="android.permission.RECEIVE_SMS"),
            PermissionInfo(name="android.permission.READ_SMS"),
        ],
        receivers=[
            BroadcastReceiverInfo(
                name="com.example.SmsReceiver",
                intent_filters=[
                    IntentFilterInfo(actions=["android.provider.Telephony.SMS_RECEIVED"])
                ],
            )
        ],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["android.telephony.SmsMessage", "android.telephony.SmsManager"],
            )
        ],
        strings=[StringReference(value="Verification code: 123456", dex_file="classes.dex")],
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    finding = next((f for f in result.findings if f.id == "SEC-SPY-SMS-001"), None)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.category == SecurityCategory.SPYWARE_INDICATOR


def test_hardware_device_identifier_harvesting() -> None:
    """Verify detection of hardware device identifier access (IMEI/IMSI)."""
    manifest = ManifestInspection(
        package_name="com.example.tracker",
        permissions=[PermissionInfo(name="android.permission.READ_PHONE_STATE")],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["android.telephony.TelephonyManager.getDeviceId"],
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    finding = next((f for f in result.findings if f.id == "SEC-SPY-DEVICE-IDENTIFIERS"), None)
    assert finding is not None
    assert finding.severity == Severity.MEDIUM


def test_accessibility_and_overlay_capabilities() -> None:
    """Verify accessibility service extraction and window overlay findings."""
    manifest = ManifestInspection(
        package_name="com.example.overlayapp",
        permissions=[PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW")],
        services=[
            ServiceInfo(
                name="com.example.MyAccessibilityService",
                permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            )
        ],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=[
                    "android.accessibilityservice.AccessibilityService",
                    "android.view.WindowManager",
                ],
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    acc_finding = next((f for f in result.findings if f.id == "SEC-SPY-ACCESSIBILITY-001"), None)
    assert acc_finding is not None

    overlay_finding = next((f for f in result.findings if f.id == "SEC-SPY-OVERLAY-001"), None)
    assert overlay_finding is not None


# ===========================================================================
# 4. Malware & Execution Analyzers
# ===========================================================================


def test_command_execution_detection() -> None:
    """Verify command execution APIs and shell binary references detection."""
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["java.lang.Runtime.exec", "java.lang.ProcessBuilder"],
            )
        ],
        strings=[StringReference(value="/system/bin/sh -c id", dex_file="classes.dex")],
    )
    insp = InspectionResult(dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    exec_finding = next((f for f in result.findings if f.id == "SEC-MAL-EXEC-001"), None)
    assert exec_finding is not None
    assert exec_finding.severity == Severity.HIGH
    assert exec_finding.category == SecurityCategory.MALWARE_INDICATOR


def test_dynamic_code_loading_and_embedded_payloads() -> None:
    """Verify dynamic DEX class loading and embedded DEX payload detection."""
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["dalvik.system.DexClassLoader"],
            )
        ]
    )
    embedded = EmbeddedFileInspection(
        embedded_dex=[EmbeddedDEXInfo(path="assets/hidden.dex", size=2048, sha256="hashdex")]
    )
    assets = AssetInspection(
        assets=[AssetEntry(path="assets/encrypted.dat", size=50000, entropy=7.6, sha256="hashent")]
    )

    insp = InspectionResult(dex=dex, embedded=embedded, assets=assets)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    dyn_finding = next((f for f in result.findings if f.id == "SEC-MAL-DYNLOAD-001"), None)
    assert dyn_finding is not None

    comb_finding = next((f for f in result.findings if f.id == "SEC-COMB-DYNLOAD-PAYLOAD"), None)
    assert comb_finding is not None
    assert comb_finding.severity == Severity.HIGH

    entropy_finding = next((f for f in result.findings if "ENTROPY" in f.id), None)
    assert entropy_finding is not None


def test_boot_persistence_indicators() -> None:
    """Verify boot persistence receiver and background execution detection."""
    manifest = ManifestInspection(
        package_name="com.example.persist",
        permissions=[PermissionInfo(name="android.permission.RECEIVE_BOOT_COMPLETED")],
        receivers=[
            BroadcastReceiverInfo(
                name="com.example.BootReceiver",
                intent_filters=[IntentFilterInfo(actions=["android.intent.action.BOOT_COMPLETED"])],
            )
        ],
        services=[ServiceInfo(name="com.example.BackgroundService", is_foreground=True)],
    )

    insp = InspectionResult(manifest=manifest)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    boot_finding = next((f for f in result.findings if f.id == "SEC-MAL-BOOT-001"), None)
    assert boot_finding is not None
    assert boot_finding.category == SecurityCategory.MALWARE_INDICATOR


# ===========================================================================
# 5. Network Security & Correlation
# ===========================================================================


def test_network_direct_ip_and_sensitive_data_correlation() -> None:
    """Verify detection of hardcoded IP URLs and sensitive capability network correlation."""
    manifest = ManifestInspection(
        package_name="com.example.exfil",
        permissions=[
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
            PermissionInfo(name="android.permission.INTERNET"),
        ],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["android.location.LocationManager", "okhttp3.OkHttpClient"],
            )
        ]
    )
    network = NetworkInspection(
        urls=[
            URLReference(
                url="http://198.51.100.1:8080/upload",
                host="198.51.100.1",
                source=EvidenceSource(file="classes.dex"),
            ),
            URLReference(
                url="http://api.backend.com/geo",
                host="api.backend.com",
                source=EvidenceSource(file="classes.dex"),
            ),
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex, network=network)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    # 1. Direct IP finding
    ip_finding = next((f for f in result.findings if f.id == "SEC-NET-DIRECT-IP"), None)
    assert ip_finding is not None
    assert any("198.51.100.1" in ev.description for ev in ip_finding.evidence)

    # 2. Sensitive data exfiltration correlation
    corr_finding = next((f for f in result.findings if f.id == "SEC-NET-CAPABILITY-FLOW"), None)
    assert corr_finding is not None
    assert corr_finding.severity == Severity.MEDIUM


# ===========================================================================
# 6. Vulnerabilities & Secret Masking
# ===========================================================================


def test_secret_masking_utility() -> None:
    """Verify secret masking obscures sensitive characters while preserving token format."""
    masked = mask_secret("AKIA1234567890ABCDEF")
    assert masked.startswith("AKIA")
    assert masked.endswith("CDEF")
    assert "************" in masked
    assert "1234567890" not in masked

    # Short secret
    short_masked = mask_secret("abcdef")
    assert short_masked == "ab****ef"


def test_vulnerability_manifest_flags() -> None:
    """Verify detection of debuggable, allowBackup, and cleartext traffic manifest flags."""
    manifest = ManifestInspection(
        package_name="com.example.vulnerable",
        application=ApplicationInfo(
            debuggable=True,
            allow_backup=True,
            uses_cleartext_traffic=True,
            test_only=True,
        ),
    )

    insp = InspectionResult(manifest=manifest)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    debug_finding = next((f for f in result.findings if f.id == "SEC-VULN-DEBUGGABLE-001"), None)
    assert debug_finding is not None
    assert debug_finding.severity == Severity.HIGH

    backup_finding = next((f for f in result.findings if f.id == "SEC-VULN-BACKUP-001"), None)
    assert backup_finding is not None

    cleartext_finding = next((f for f in result.findings if f.id == "SEC-VULN-CLEARTEXT-001"), None)
    assert cleartext_finding is not None


def test_vulnerability_exported_components() -> None:
    """Verify exported component without permission protection detection."""
    manifest = ManifestInspection(
        package_name="com.example.vulncomponents",
        providers=[
            ContentProviderInfo(name="com.example.DataProvider", exported=True, permission=None)
        ],
        services=[ServiceInfo(name="com.example.CommandService", exported=True, permission=None)],
    )

    insp = InspectionResult(manifest=manifest)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    prov_finding = next((f for f in result.findings if f.id == "SEC-VULN-EXPORTED-PROVIDER"), None)
    assert prov_finding is not None
    assert prov_finding.severity == Severity.HIGH

    svc_finding = next((f for f in result.findings if f.id == "SEC-VULN-EXPORTED-SERVICE"), None)
    assert svc_finding is not None


def test_vulnerability_weak_crypto_and_secret_detection() -> None:
    """Verify weak cipher modes (ECB), weak hashes (MD5), and masked AWS keys."""
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["java.security.MessageDigest.getInstance"],
            )
        ],
        strings=[
            StringReference(value="AES/ECB/PKCS5Padding", dex_file="classes.dex"),
            StringReference(value="MD5", dex_file="classes.dex"),
            StringReference(value="AKIAIOSFODNN7EXAMPLE", dex_file="classes.dex"),
        ],
    )

    insp = InspectionResult(dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    ecb_finding = next((f for f in result.findings if f.id == "SEC-VULN-WEAK-CIPHER-001"), None)
    assert ecb_finding is not None

    md5_finding = next((f for f in result.findings if f.id == "SEC-VULN-WEAK-HASH-001"), None)
    assert md5_finding is not None

    secret_finding = next((f for f in result.findings if "SECRET" in f.id), None)
    assert secret_finding is not None
    # Crucial: verify that the raw key is NOT exposed in the evidence description!
    assert "AKIAIOSFODNN7EXAMPLE" not in secret_finding.evidence[0].description
    assert "AKIA" in secret_finding.evidence[0].description
    assert "****" in secret_finding.evidence[0].description


# ===========================================================================
# 7. Diff-Aware Security Analysis
# ===========================================================================


def test_diff_aware_security_analysis() -> None:
    """Verify detection of security-relevant differences between APK A and APK B."""
    diff_res = DiffResult(
        apk_a=PackageIdentity(file_name="app_a.apk", sha256="1111"),
        apk_b=PackageIdentity(file_name="app_b.apk", sha256="2222"),
        identity=IdentityDiff(),
        manifest=ManifestDiff(),
        permissions=PermissionDiff(
            added=["android.permission.RECORD_AUDIO", "android.permission.SEND_SMS"],
            removed=[],
        ),
        components=ComponentDiff(),
        dex=DEXDiff(
            api_references_added=["dalvik.system.DexClassLoader", "java.lang.Runtime.exec"]
        ),
        strings=StringDiff(),
        network=NetworkDiff(
            domains_added=["c2.evil.com"],
        ),
        native=NativeDiff(
            libraries_added=[
                NativeLibraryDiff(
                    path="lib/arm64-v8a/libinjected.so",
                    abi="arm64-v8a",
                    change_type=ChangeType.ADDED,
                )
            ],
        ),
        resources=ResourceDiff(),
        assets=AssetDiff(),
        embedded=EmbeddedDiff(),
        certificates=CertificateDiff(
            status="CHANGED",
        ),
        files=FileDiff(),
        summary=DiffSummary(),
    )

    engine = SecurityEngine()
    result = engine.analyze(inspection=InspectionResult(), diff=diff_res)

    # 1. Added dangerous permission
    perm_finding = next(
        (f for f in result.findings if f.id == "SEC-DIFF-ADDED-DANGEROUS-PERMISSIONS"), None
    )
    assert perm_finding is not None
    assert perm_finding.severity == Severity.HIGH
    assert any("RECORD_AUDIO" in ev.description for ev in perm_finding.evidence)

    # 2. Certificate change
    cert_finding = next(
        (f for f in result.findings if f.id == "SEC-DIFF-CERTIFICATE-CHANGED"), None
    )
    assert cert_finding is not None
    assert cert_finding.severity == Severity.HIGH

    # 3. Added native library
    nat_finding = next((f for f in result.findings if f.id == "SEC-DIFF-ADDED-NATIVE-LIBS"), None)
    assert nat_finding is not None

    # 4. Added external endpoint
    net_finding = next((f for f in result.findings if f.id == "SEC-DIFF-ADDED-ENDPOINTS"), None)
    assert net_finding is not None

    # 5. Added dynamic class loading / command execution
    exec_finding = next(
        (f for f in result.findings if f.id == "SEC-DIFF-ADDED-EXECUTION-APIS"), None
    )
    assert exec_finding is not None


# ===========================================================================
# 8. Negative Tests & False-Positive Controls
# ===========================================================================


def test_negative_legitimate_audio_recorder_app() -> None:
    """Legitimate audio recorder: RECORD_AUDIO + AudioRecord, but NO background service.

    Must NOT produce a covert surveillance finding or classify as malware.
    """
    manifest = ManifestInspection(
        package_name="com.tools.audiorecorder",
        permissions=[
            PermissionInfo(name="android.permission.RECORD_AUDIO", protection_level="dangerous")
        ],
        services=[],  # No background services!
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["android.media.AudioRecord"],
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    # The background audio spyware rule SEC-SPY-AUDIO-001 requires background service
    covert_finding = next((f for f in result.findings if f.id == "SEC-SPY-AUDIO-001"), None)
    assert covert_finding is None

    # And top-level security status remains neutral
    assert result.security_status in (
        SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS,
        SecurityStatus.FINDINGS_PRESENT,
    )


def test_negative_clean_calculator_app() -> None:
    """Standard calculator app with no sensitive capabilities.

    Must produce zero High/Critical security findings and NO_SIGNIFICANT_STATIC_FINDINGS status.
    """
    manifest = ManifestInspection(
        package_name="com.example.calculator",
        version_name="1.0.0",
        permissions=[],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["java.lang.Math.sin", "java.lang.Math.cos"],
            )
        ]
    )

    insp = InspectionResult(manifest=manifest, dex=dex)
    engine = SecurityEngine()
    result = engine.analyze(insp)

    assert result.security_status == SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS
    assert result.summary.critical_count == 0
    assert result.summary.high_count == 0


# ===========================================================================
# 9. Determinism & Partial Analysis
# ===========================================================================


def test_security_engine_determinism() -> None:
    """Running security analysis twice on identical evidence produces identical findings."""
    manifest = ManifestInspection(
        package_name="com.example.sample",
        permissions=[PermissionInfo(name="android.permission.RECORD_AUDIO")],
        debuggable=True,
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1000,
                sha256="abc",
                api_references=["java.lang.Runtime.exec"],
            )
        ]
    )
    insp = InspectionResult(manifest=manifest, dex=dex)

    engine = SecurityEngine()
    res1 = engine.analyze(insp)
    res2 = engine.analyze(insp)

    assert len(res1.findings) == len(res2.findings)
    assert [f.id for f in res1.findings] == [f.id for f in res2.findings]
    assert [f.severity for f in res1.findings] == [f.severity for f in res2.findings]


def test_partial_analysis_when_dex_parsing_incomplete() -> None:
    """When DEX parsing is missing or failed, security analysis status reflects partial analysis."""
    manifest = ManifestInspection(
        package_name="com.example.corruptdex",
        permissions=[PermissionInfo(name="android.permission.CAMERA")],
    )
    # No dex files inspected
    insp = InspectionResult(
        status=AnalysisStatus.PARTIAL, manifest=manifest, dex=DEXInspection(dex_files=[])
    )

    engine = SecurityEngine()
    res = engine.analyze(insp)

    assert res.status == AnalysisStatus.PARTIAL
    assert any("DEX inspection was not completed" in lim for lim in res.limitations)


# ===========================================================================
# 10. CLI Integration Tests
# ===========================================================================


def test_cli_security_command(tmp_path: Path) -> None:
    """Test `apkforge security <apk>` CLI command."""
    apk_file = tmp_path / "test_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.clisecurity")

    result = runner.invoke(app, ["security", str(apk_file)])
    assert result.exit_code == 0
    assert "APKForge Security Analysis" in result.stdout
    assert "com.example.clisecurity" in result.stdout


def test_cli_security_json_output(tmp_path: Path) -> None:
    """Test `apkforge security <apk> --json` CLI command produces valid SecurityResult JSON."""
    apk_file = tmp_path / "test_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.jsonsec")

    result = runner.invoke(app, ["security", str(apk_file), "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["package_name"] == "com.example.jsonsec"
    assert "security_status" in parsed
    assert "summary" in parsed
    assert "findings" in parsed


def test_cli_analyze_command(tmp_path: Path) -> None:
    """Test `apkforge analyze <apk>` unified analysis orchestrating engines."""
    apk_file = tmp_path / "test_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.unified")

    result = runner.invoke(app, ["analyze", str(apk_file)])
    assert result.exit_code == 0
    assert "APKForge Unified Analysis" in result.stdout
    assert "Inspection Status:" in result.stdout
    assert "Privacy Status:" in result.stdout
    assert "Security Status:" in result.stdout


def test_cli_analyze_json_output(tmp_path: Path) -> None:
    """Test `apkforge analyze <apk> --json` produces valid FullAnalysisResult JSON."""
    apk_file = tmp_path / "test_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.unifiedjson")

    result = runner.invoke(app, ["analyze", str(apk_file), "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["package_name"] == "com.example.unifiedjson"
    assert "inspection_summary" in parsed
    assert "privacy_summary" in parsed
    assert "security_summary" in parsed


def test_security_engine_with_native_libraries() -> None:
    """Regression test: SecurityEngine handles NativeLibraryInspection without AttributeError."""
    nl1 = NativeLibraryInspection(
        path="lib/arm64-v8a/libnative-core.so",
        size=50000,
        sha256="abc1234",
        abi="arm64-v8a",
    )
    nl2 = NativeLibraryInspection(
        path="lib/x86_64/libhelper.so",
        size=30000,
        sha256="def5678",
        abi="x86_64",
    )
    # Verify the property on the model directly
    assert nl1.name == "libnative-core.so"
    assert nl2.name == "libhelper.so"

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.example.nativetest"),
        native=NativeInspection(
            libraries=[nl1, nl2],
            total_libraries=2,
            abis_found=["arm64-v8a", "x86_64"],
        ),
    )

    engine = SecurityEngine()
    result = engine.analyze(inspection)

    assert result.status == AnalysisStatus.COMPLETE
    assert result.package_name == "com.example.nativetest"
    assert len(result.errors) == 0


def test_security_engine_with_none_entropy_assets() -> None:
    """Regression test: SecurityEngine handles assets with None entropy without TypeError."""
    ast_none = AssetEntry(path="assets/config.json", size=150, entropy=None)
    ast_high = AssetEntry(path="assets/encrypted_blob.dat", size=8192, entropy=7.8)
    ast_normal = AssetEntry(path="assets/plain.txt", size=500, entropy=4.2)

    inspection = InspectionResult(
        manifest=ManifestInspection(package_name="com.example.entropytest"),
        assets=AssetInspection(
            assets=[ast_none, ast_high, ast_normal],
            total_assets=3,
        ),
    )

    engine = SecurityEngine()
    result = engine.analyze(inspection)

    assert result.status == AnalysisStatus.COMPLETE
    assert result.package_name == "com.example.entropytest"
    assert len(result.errors) == 0

