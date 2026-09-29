"""Manifest configuration vulnerability analyzer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.security.rules import SecurityEvidenceIndex

_log = logging.getLogger(__name__)


class ManifestVulnerabilityAnalyzer:
    """Analyzes AndroidManifest.xml declarations for dangerous configuration flags."""

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Inspect manifest attributes for security misconfigurations."""
        findings: list[SecurityFinding] = []
        attrs = index.manifest_attributes

        # 1. Debuggable build flag
        if str(attrs.get("debuggable", "")).lower() == "true":
            ev = [
                Evidence(
                    description="Manifest declaration: android:debuggable='true'",
                    location="manifest:application:debuggable",
                    snippet="android:debuggable='true'",
                )
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-MANIFEST-DEBUGGABLE",
                    category="configuration",
                    title="Application Package is Configured as Debuggable",
                    description=(
                        "The application manifest explicitly sets android:debuggable='true'. "
                        "This exposes the Java Debug Wire Protocol (JDWP) port on the device."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "An attacker or malicious application with USB debugging enabled can"
                        "attach a debugger,"
                        "execute arbitrary code within the application process, and access all"
                        "private app storage."
                    ),
                    limitations=[
                        "Debug builds are standard during development but must be disabled"
                        "before production release."
                    ],
                    references=["CWE-215: Insertion of Sensitive Information Into Debugging Code"],
                    tags=["manifest", "debuggable", "vulnerability"],
                )
            )

        # 2. Cleartext network traffic
        if str(attrs.get("usesCleartextTraffic", "")).lower() == "true":
            ev = [
                Evidence(
                    description="Manifest declaration: android:usesCleartextTraffic='true'",
                    location="manifest:application:usesCleartextTraffic",
                    snippet="android:usesCleartextTraffic='true'",
                )
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-MANIFEST-CLEARTEXT",
                    category="configuration",
                    title="Cleartext Network Traffic Allowed by Manifest",
                    description=(
                        "The application manifest declares android:usesCleartextTraffic='true', "
                        "disabling Android's default requirement for TLS/HTTPS communication."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Unencrypted HTTP communication allows network eavesdroppers and man-in-"
                        "the-middle (MITM)"
                        "adversaries to intercept credentials, personal data, and session tokens."
                    ),
                    limitations=[
                        "Legacy APIs and IoT local network communications occasionally require"
                        "unencrypted HTTP."
                    ],
                    references=["CWE-319: Cleartext Transmission of Sensitive Information"],
                    tags=["manifest", "cleartext", "network", "vulnerability"],
                )
            )

        # 3. AllowBackup flag
        if str(attrs.get("allowBackup", "")).lower() == "true":
            ev = [
                Evidence(
                    description="Manifest declaration: android:allowBackup='true'",
                    location="manifest:application:allowBackup",
                    snippet="android:allowBackup='true'",
                )
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-MANIFEST-BACKUP",
                    category="configuration",
                    title="Application Data Backup Enabled (allowBackup=true)",
                    description=(
                        "The application manifest sets android:allowBackup='true'. "
                        "Application private databases and shared preferences can be backed up"
                        "via ADB."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Anyone with physical access to an unlocked device or ADB authorization"
                        "can run 'adb backup'"
                        "to extract the application's internal files and local credentials."
                    ),
                    limitations=[
                        "Google Drive auto-backup relies on allowBackup; applications may use"
                        "android:fullBackupContent rules."
                    ],
                    references=["CWE-200: Exposure of Sensitive Information"],
                    tags=["manifest", "backup", "vulnerability"],
                )
            )

        # 4. TestOnly flag
        if str(attrs.get("testOnly", "")).lower() == "true":
            ev = [
                Evidence(
                    description="Manifest declaration: android:testOnly='true'",
                    location="manifest:application:testOnly",
                    snippet="android:testOnly='true'",
                )
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-MANIFEST-TESTONLY",
                    category="configuration",
                    title="Application Package is Marked as Test-Only (testOnly=true)",
                    description=(
                        "The manifest declares android:testOnly='true', preventing standard user"
                        "installation."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "This APK is a development/test build and cannot be installed on end-"
                        "user devices without ADB '-t' flags."
                    ),
                    limitations=["Intended for development environments."],
                    references=["CWE-1188: Insecure Default Initialization of Resource"],
                    tags=["manifest", "test", "vulnerability"],
                )
            )

        return sorted(findings, key=lambda f: f.id)
