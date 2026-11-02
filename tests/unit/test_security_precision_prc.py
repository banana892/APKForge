"""Unit and regression tests for security precision fixes: PRC-05, PRC-07, and PRC-08.

Covers:
1. PRC-05: Nested APK payload detection. Code-free framework APKs (containing only
   resources.arsc and AndroidManifest.xml) must not trigger SEC-MAL-PAYLOAD-APK findings,
   while APKs with executable code (classes.dex or native libraries) still trigger detection.
2. PRC-07: Key detection precision. Standalone PEM armor headers without plausible base64 key
   material must not trigger SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER, while genuine
   private/public key material is still detected and masked.
3. PRC-08: Crypto-string attribution. Algorithm strings from bundled dependencies/libraries
   (such as org.bouncycastle) must not be attributed as application vulnerabilities, while
   application-owned cryptographic weaknesses remain detected.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from apkforge.core.models import Severity
from apkforge.inspection.embedded import EmbeddedFileInspector
from apkforge.inspection.models import (
    ApplicationInfo,
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    EmbeddedAPKInfo,
    EmbeddedFileInspection,
    InspectionResult,
    ManifestInspection,
    StringReference,
)
from apkforge.security import SecurityEngine, SecurityEvidenceIndex, SecurityRuleEngine
from apkforge.security.malware.payloads import PayloadAnalyzer
from apkforge.security.vulnerabilities.crypto import CryptoVulnerabilityAnalyzer

# ===========================================================================
# PRC-05: Nested APK payload detection
# ===========================================================================


class TestPRC05NestedAPKPayload:
    """PRC-05 regression tests for nested APK payload detection."""

    def test_code_free_framework_apk_suppresses_payload_finding(self, tmp_path: Path) -> None:
        """Reproduces AppManager frameworks/android/android-NN.apk: resources only, no code."""
        # Create an inner code-free framework APK (resources.arsc + AndroidManifest.xml only)
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner_zf:
            inner_zf.writestr("AndroidManifest.xml", b"<manifest/>")
            inner_zf.writestr("resources.arsc", b"\x02\x00\x0c\x00\x00\x00\x00\x00")
        inner_data = inner_buf.getvalue()

        # Wrap inside outer APK
        outer_apk = tmp_path / "app_with_framework_res.apk"
        with zipfile.ZipFile(outer_apk, "w") as outer_zf:
            outer_zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
            outer_zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
            outer_zf.writestr("frameworks/android/android-23.apk", inner_data)

        inspector = EmbeddedFileInspector()
        inspection, _warnings = inspector.inspect(outer_apk)

        assert len(inspection.embedded_apks) == 1
        assert inspection.embedded_apks[0].path == "frameworks/android/android-23.apk"
        assert inspection.embedded_apks[0].has_code is False
        # Code-free APK must not be listed in executable_files
        assert not any(
            ef.path == "frameworks/android/android-23.apk" for ef in inspection.executable_files
        )

        # Run SecurityEngine: must NOT produce SEC-MAL-PAYLOAD-APK finding
        engine = SecurityEngine()
        result = engine.analyze(
            InspectionResult(
                manifest=ManifestInspection(package_name="com.example.app"),
                embedded=inspection,
            )
        )
        payload_findings = [f for f in result.findings if "SEC-MAL-PAYLOAD-APK" in f.id]
        assert len(payload_findings) == 0

    def test_genuine_nested_apk_with_code_is_detected(self, tmp_path: Path) -> None:
        """Genuine nested APK containing classes.dex must still be detected as payload."""
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner_zf:
            inner_zf.writestr("AndroidManifest.xml", b"<manifest/>")
            inner_zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        inner_data = inner_buf.getvalue()

        outer_apk = tmp_path / "app_with_payload.apk"
        with zipfile.ZipFile(outer_apk, "w") as outer_zf:
            outer_zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
            outer_zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
            outer_zf.writestr("assets/dropped_payload.apk", inner_data)

        inspector = EmbeddedFileInspector()
        inspection, _warnings = inspector.inspect(outer_apk)

        assert len(inspection.embedded_apks) == 1
        assert inspection.embedded_apks[0].path == "assets/dropped_payload.apk"
        assert inspection.embedded_apks[0].has_code is True

        engine = SecurityEngine()
        result = engine.analyze(
            InspectionResult(
                manifest=ManifestInspection(package_name="com.example.app"),
                embedded=inspection,
            )
        )
        payload_findings = [f for f in result.findings if "SEC-MAL-PAYLOAD-APK" in f.id]
        assert len(payload_findings) == 1
        assert payload_findings[0].severity == Severity.HIGH
        assert "assets/dropped_payload.apk" in payload_findings[0].title

    def test_payload_analyzer_unit_respects_has_code_flag(self) -> None:
        """PayloadAnalyzer direct test checking has_code filtering for 14 framework APKs."""
        analyzer = PayloadAnalyzer()

        # 14 simulated code-free framework APKs (as in AppManager)
        code_free_apks = [
            {
                "path": f"frameworks/android/android-{api}.apk",
                "type": "apk",
                "size": 150000,
                "has_code": False,
            }
            for api in range(23, 37)
        ]
        index_clean = SecurityEvidenceIndex(embedded_files=code_free_apks)
        findings_clean = analyzer.analyze(index_clean)
        assert len(findings_clean) == 0

        # Positive case with executable code
        index_positive = SecurityEvidenceIndex(
            embedded_files=[
                {"path": "assets/real_payload.apk", "type": "apk", "size": 50000, "has_code": True}
            ]
        )
        findings_pos = analyzer.analyze(index_positive)
        assert len(findings_pos) == 1
        assert findings_pos[0].id == "SEC-MAL-PAYLOAD-APK-assets_real_payload_apk"


# ===========================================================================
# PRC-07: Key detection (PEM armor / marker strings)
# ===========================================================================


class TestPRC07KeyDetection:
    """PRC-07 regression tests for PEM key detection."""

    def test_pem_armor_marker_alone_suppresses_secret_finding(self) -> None:
        """Standalone PEM header string (e.g. BC parser constant) must not trigger secret."""
        analyzer = CryptoVulnerabilityAnalyzer()

        # Strings present in AppManager without actual key body
        index = SecurityEvidenceIndex(
            strings={
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
                "-----BEGIN PUBLIC KEY-----",
                "-----BEGIN RSA PRIVATE KEY----- %s",
            }
        )
        findings = analyzer.analyze(index)
        secret_findings = [f for f in findings if "SECRET" in f.id]
        assert len(secret_findings) == 0

    def test_genuine_private_key_material_is_detected_and_masked(self) -> None:
        """Actual PEM private key with base64 body must trigger finding and be masked."""
        analyzer = CryptoVulnerabilityAnalyzer()

        real_key_string = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0m4p5W2K94sflw9iZ2f3Q2dG817vA8bH7x6y\n"
            "5z1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y\n"
            "-----END RSA PRIVATE KEY-----"
        )
        index = SecurityEvidenceIndex(strings={real_key_string})
        findings = analyzer.analyze(index)

        secret_findings = [f for f in findings if "SECRET" in f.id]
        assert len(secret_findings) == 1
        finding = secret_findings[0]
        assert finding.id == "SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER"
        assert finding.severity == Severity.HIGH
        # Raw key body must be masked
        assert "MIIEowIBAAKCAQEA0m4p5W2K" not in finding.evidence[0].description
        assert "****" in finding.evidence[0].description

    def test_genuine_public_key_material_is_detected(self) -> None:
        """Actual PEM public key with base64 body is also detected."""
        analyzer = CryptoVulnerabilityAnalyzer()

        pub_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef\n"
            "-----END PUBLIC KEY-----"
        )
        index = SecurityEvidenceIndex(strings={pub_key})
        findings = analyzer.analyze(index)

        secret_findings = [f for f in findings if "SECRET" in f.id]
        assert len(secret_findings) == 1


# ===========================================================================
# PRC-08: Crypto-string attribution
# ===========================================================================


def _custom_crypto_rules() -> SecurityRuleEngine:
    """A user-supplied crypto rule: the rule engine applies the same attribution to it."""
    engine = SecurityRuleEngine()
    engine.load_from_dict({"rules": [{
        "id": "CUSTOM-WEAK-CRYPTO", "title": "Weak crypto", "category": "crypto",
        "severity": "low", "confidence": "medium", "description": "d", "assessment": "a",
        "conditions": {"any": [{"string_any": ["DESede", "MD5", "SHA1", "SHA-1",
                                               "DES/CBC/PKCS5Padding", "Blowfish"]}]},
    }]})  # fmt: skip
    return engine


class TestPRC08CryptoStringAttribution:
    """PRC-08 regression tests for crypto-string library attribution."""

    def test_bundled_bouncycastle_strings_not_attributed_to_app(self) -> None:
        """AppManager: algorithm strings inside org.bouncycastle must not trigger findings."""
        # Setup index simulating AppManager bundling BouncyCastle
        index = SecurityEvidenceIndex(
            package_name="io.github.muntashirakon.AppManager",
            classes={
                "io.github.muntashirakon.AppManager.MainActivity",
                "org.bouncycastle.crypto.engines.DESEngine",
                "org.bouncycastle.crypto.engines.DESedeEngine",
                "org.bouncycastle.crypto.engines.BlowfishEngine",
                "org.bouncycastle.crypto.digests.SHA1Digest",
            },
            strings={
                "DES/CBC/PKCS5Padding",
                "DESede",
                "Blowfish",
                "SHA1",
                "SHA-1",
            },
            string_provenance={
                "DES/CBC/PKCS5Padding": ["org.bouncycastle.cms.jcajce.EnvelopedDataHelper"],
                "DESede": ["org.bouncycastle.crypto.engines.DESedeEngine"],
                "Blowfish": ["org.bouncycastle.crypto.engines.BlowfishEngine"],
                "SHA1": ["org.bouncycastle.cert.crmf.jcajce.CRMFHelper"],
                "SHA-1": ["org.bouncycastle.crypto.digests.SHA1Digest"],
            },
        )

        # 1. CryptoVulnerabilityAnalyzer
        analyzer = CryptoVulnerabilityAnalyzer()
        vuln_findings = analyzer.analyze(index)
        assert not any(f.id == "SEC-VULN-CRYPTO-WEAK-CIPHER" for f in vuln_findings)
        assert not any(f.id == "SEC-VULN-CRYPTO-WEAK-HASH" for f in vuln_findings)

        # 2. SecurityRuleEngine: a custom crypto rule gets the same attribution
        assert _custom_crypto_rules().evaluate(index) == []

    def test_genuine_app_crypto_weakness_is_detected(self) -> None:
        """When the application itself references DESede and MD5, findings MUST be detected."""
        index = SecurityEvidenceIndex(
            package_name="com.example.vulnerable",
            classes={
                "com.example.vulnerable.MainActivity",
                "com.example.vulnerable.crypto.InsecureCryptoHelper",
            },
            strings={
                "DESede",
                "DES/CBC/PKCS5Padding",
                "MD5",
            },
            string_provenance={
                "DESede": ["com.example.vulnerable.crypto.InsecureCryptoHelper"],
                "DES/CBC/PKCS5Padding": ["com.example.vulnerable.crypto.InsecureCryptoHelper"],
                "MD5": ["com.example.vulnerable.crypto.InsecureCryptoHelper"],
            },
        )

        # 1. CryptoVulnerabilityAnalyzer
        analyzer = CryptoVulnerabilityAnalyzer()
        vuln_findings = analyzer.analyze(index)
        cipher_finding = next(
            (f for f in vuln_findings if f.id == "SEC-VULN-CRYPTO-WEAK-CIPHER"), None
        )
        assert cipher_finding is not None
        # transformation strings count too (they were only matched by SEC-VULN-WEAK-CIPHER-001)
        assert "DES/CBC/PKCS5Padding" in cipher_finding.description
        assert "InsecureCryptoHelper" in cipher_finding.evidence[0].description
        loc = cipher_finding.evidence[0].location
        assert loc is not None and "class:com.example.vulnerable.crypto.InsecureCryptoHelper" in loc

        hash_finding = next((f for f in vuln_findings if f.id == "SEC-VULN-CRYPTO-WEAK-HASH"), None)
        assert hash_finding is not None
        assert "InsecureCryptoHelper" in hash_finding.evidence[0].description

        # 2. SecurityRuleEngine: a custom crypto rule fires; no built-in rule repeats it
        assert [f.id for f in _custom_crypto_rules().evaluate(index)] == ["CUSTOM-WEAK-CRYPTO"]
        builtins = SecurityRuleEngine()
        builtins.load_builtins()
        assert not [f for f in builtins.evaluate(index) if "crypto" in f.tags]

    def test_unestablished_ownership_with_bundled_provider_suppresses(self) -> None:
        """When ownership cannot be established safely and bundled provider exists, suppress."""
        index = SecurityEvidenceIndex(
            package_name="com.example.app",
            classes={
                "com.example.app.MainActivity",
                "org.bouncycastle.crypto.engines.DESEngine",
            },
            strings={"DESede", "Blowfish"},
            string_provenance={},  # Provenance unavailable
        )

        analyzer = CryptoVulnerabilityAnalyzer()
        findings = analyzer.analyze(index)
        assert not any(f.id == "SEC-VULN-CRYPTO-WEAK-CIPHER" for f in findings)


# ===========================================================================
# End-to-end regression covering the 22 reviewed False Positives
# ===========================================================================


class TestReviewedFalsePositivesRegression:
    """Verify regression coverage for all 22 reviewed false positives."""

    def test_prc05_all_14_framework_apks_eliminated(self) -> None:
        """All 14 framework APK payload findings are covered and eliminated."""
        embedded = [
            EmbeddedAPKInfo(
                path=f"frameworks/android/android-{api}.apk",
                size=150000,
                sha256="abc",
                has_code=False,
            )
            for api in range(23, 37)
        ]
        insp = InspectionResult(
            manifest=ManifestInspection(package_name="io.github.muntashirakon.AppManager"),
            embedded=EmbeddedFileInspection(embedded_apks=embedded),
        )
        engine = SecurityEngine()
        result = engine.analyze(insp)
        for api in range(23, 37):
            fid = f"SEC-MAL-PAYLOAD-APK-frameworks_android_android-{api}_apk"
            assert not any(f.id == fid for f in result.findings)

    def test_prc07_generic_private_key_header_eliminated(self) -> None:
        """Generic private key header false positive is eliminated on bare header."""
        analyzer = CryptoVulnerabilityAnalyzer()
        index = SecurityEvidenceIndex(
            package_name="io.github.muntashirakon.AppManager",
            strings={"-----BEGIN RSA PRIVATE KEY-----"},
        )
        findings = analyzer.analyze(index)
        assert not any(f.id == "SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER" for f in findings)

    def test_prc08_four_crypto_weakness_findings_eliminated(self) -> None:
        """All 4 crypto findings on bundled BouncyCastle strings are eliminated."""
        engine = SecurityEngine()
        dex = DEXInspection(
            dex_files=[
                DEXFileInspection(
                    path="classes6.dex",
                    size=10000,
                    sha256="abc",
                    inventory=DEXClassInventory(
                        classes=[
                            ClassInfo(name="org.bouncycastle.crypto.engines.DESedeEngine"),
                            ClassInfo(name="org.bouncycastle.cms.jcajce.EnvelopedDataHelper"),
                        ]
                    ),
                )
            ],
            strings=[
                StringReference(
                    value="DES/CBC/PKCS5Padding",
                    dex_file="classes6.dex",
                    class_name="org.bouncycastle.cms.jcajce.EnvelopedDataHelper",
                ),
                StringReference(
                    value="DESede",
                    dex_file="classes6.dex",
                    class_name="org.bouncycastle.crypto.engines.DESedeEngine",
                ),
                StringReference(
                    value="Blowfish",
                    dex_file="classes6.dex",
                    class_name="org.bouncycastle.crypto.engines.BlowfishEngine",
                ),
                StringReference(
                    value="SHA1",
                    dex_file="classes6.dex",
                    class_name="org.bouncycastle.cert.crmf.jcajce.CRMFHelper",
                ),
                StringReference(
                    value="SHA-1",
                    dex_file="classes6.dex",
                    class_name="org.bouncycastle.crypto.digests.SHA1Digest",
                ),
            ],
        )
        insp = InspectionResult(
            manifest=ManifestInspection(
                package_name="io.github.muntashirakon.AppManager",
                application=ApplicationInfo(allow_backup=True),
            ),
            dex=dex,
        )
        result = engine.analyze(insp)

        crypto_finding_ids = {
            "SEC-VULN-WEAK-CIPHER-001",
            "SEC-VULN-CRYPTO-WEAK-CIPHER",
            "SEC-VULN-CRYPTO-WEAK-HASH",
            "SEC-VULN-WEAK-HASH-001",
        }
        found_crypto_ids = {f.id for f in result.findings if f.id in crypto_finding_ids}
        assert len(found_crypto_ids) == 0, f"Unexpected crypto findings: {found_crypto_ids}"
