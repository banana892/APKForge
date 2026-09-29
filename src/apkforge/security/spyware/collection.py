"""Personal data collection and harvesting analyzer: contacts, SMS, device IDs, accessibility."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.security.rules import SecurityEvidenceIndex

_log = logging.getLogger(__name__)


class CollectionAnalyzer:
    """Analyzes data harvesting capabilities (SMS, contacts, hardware IDs, accessibility)."""

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Inspect data extraction and exfiltration indicators."""
        findings: list[SecurityFinding] = []

        # 1. SMS Interception & OTP Harvesting
        has_sms_perm = index.has_permission("RECEIVE_SMS") or index.has_permission("READ_SMS")
        has_sms_api = index.has_api("android.telephony.SmsManager")
        otp_strings = [
            s
            for s in index.strings
            if any(
                term in s.lower()
                for term in ("otp", "verification code", "auth code", "bank", "token")
            )
        ]

        if has_sms_perm and has_sms_api:
            ev = [
                Evidence(
                    description="Declared permission: RECEIVE_SMS / READ_SMS",
                    location="permission:sms",
                    snippet="SMS permission",
                ),
                Evidence(
                    description="SmsManager framework API referenced",
                    location="api:android.telephony.SmsManager",
                    snippet="SmsManager API",
                ),
            ]
            if otp_strings:
                ev.append(
                    Evidence(
                        description="OTP / verification keyword strings found in DEX string pool",
                        location="dex:strings",
                        snippet=f"Keywords sample: {', '.join(otp_strings[:3])}",
                    )
                )

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-SMS-HARVEST",
                    category="collection",
                    title="SMS Message Interception & Processing Capability",
                    description=(
                        "Application requests SMS reception/reading permissions and references"
                        "SmsManager APIs"
                        + (", with OTP/verification keyword strings." if otp_strings else ".")
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH if otp_strings else Confidence.MEDIUM,
                    evidence=ev,
                    assessment=(
                        "The application contains code paths capable of reading incoming SMS"
                        "messages."
                        "This technical capability can be used for automated 2FA/OTP code"
                        "interception."
                    ),
                    limitations=[
                        "Legitimate banking apps, chat apps, and autofill utilities use SMS"
                        "permissions for automated login verification."
                    ],
                    references=[
                        "CWE-200: Exposure of Sensitive Information",
                        "CWE-359: Exposure of Private Personal Information",
                    ],
                    tags=["sms", "otp", "interception", "spyware"],
                )
            )

        # 2. Hardware & Telephony Device Identifier Extraction
        id_methods = [
            m
            for m in (index.methods | index.apis)
            if any(
                term in m
                for term in ("getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber")
            )
        ]
        has_android_id = index.has_string("android_id")
        has_serial = index.has_string("SERIAL") or "Build.SERIAL" in index.apis

        if id_methods or (has_android_id and has_serial):
            ev = []
            for m in id_methods:
                ev.append(
                    Evidence(
                        description=f"Telephony hardware identifier method reference: {m}",
                        location=f"method:{m}",
                        snippet=m,
                    )
                )
            if has_android_id:
                ev.append(
                    Evidence(
                        description="Settings.Secure.ANDROID_ID reference",
                        location="dex:strings",
                        snippet="android_id",
                    )
                )
            if has_serial:
                ev.append(
                    Evidence(
                        description="Build.SERIAL hardware serial number reference",
                        location="dex:strings",
                        snippet="Build.SERIAL",
                    )
                )

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-DEVICE-IDENTIFIERS",
                    category="collection",
                    title="Hardware & Persistent Device Identifier Collection Capability",
                    description=(
                        "Application references persistent hardware identifiers (IMEI, IMSI,"
                        "Serial Number, or Android ID)."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    assessment=(
                        "The APK queries non-resettable hardware identifiers, which allow"
                        "persistent cross-install"
                        "and cross-application device tracking that bypasses user privacy controls."
                    ),
                    limitations=[
                        "Legacy SDKs and device management tools frequently query hardware"
                        "identifiers for licensing."
                    ],
                    references=["CWE-359: Exposure of Private Personal Information"],
                    tags=["identifiers", "hardware", "tracking"],
                )
            )

        # 3. Accessibility Service Abuse Capability
        has_accessibility = index.has_api("android.accessibilityservice.AccessibilityService")
        services = index.components.get("services", [])
        acc_services = [
            s
            for s in services
            if s.get("permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ]

        if has_accessibility or acc_services:
            ev = []
            for s in acc_services:
                ev.append(
                    Evidence(
                        description=f"Declared AccessibilityService component: {s.get('name')}",
                        location=f"manifest:service:{s.get('name')}",
                        snippet=f"Service: {s.get('name')} (BIND_ACCESSIBILITY_SERVICE)",
                    )
                )
            if not ev:
                ev.append(
                    Evidence(
                        description="AccessibilityService API referenced in bytecode",
                        location="api:android.accessibilityservice.AccessibilityService",
                        snippet="AccessibilityService API",
                    )
                )

            findings.append(
                SecurityFinding(
                    id="SEC-SPY-ACCESSIBILITY-ABUSE",
                    category="collection",
                    title="Android Accessibility Service Implementation",
                    description="Application implements an AccessibilityService component.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED if acc_services else Confidence.HIGH,
                    evidence=ev,
                    assessment=(
                        "Accessibility Services possess broad permissions to inspect screen"
                        "content, inject gestures,"
                        "and read text across all applications on the device."
                    ),
                    limitations=[
                        "Accessibility services are an essential Android feature for assistive"
                        "technologies, screen readers, and automation."
                    ],
                    references=["CWE-250: Execution with Unnecessary Privileges"],
                    tags=["accessibility", "privilege", "surveillance"],
                )
            )

        return sorted(findings, key=lambda f: f.id)
