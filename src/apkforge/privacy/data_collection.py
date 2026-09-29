"""Data collection capability analysis and cross-domain evidence correlation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.privacy.models import (
    DataCapabilityAssessment,
    DataCapabilityType,
    DataCollectionResult,
    PrivacyFinding,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.privacy.models import DetectedSDK, EndpointResult
    from apkforge.privacy.rules import EvidenceIndex


class DataCollectionAnalyzer:
    """Correlates permissions, APIs, SDKs, and endpoints to evaluate data capabilities."""

    def analyze(
        self,
        inspection: InspectionResult,
        index: EvidenceIndex,
        detected_sdks: list[DetectedSDK] | None = None,
        endpoints: EndpointResult | None = None,
    ) -> tuple[DataCollectionResult, list[PrivacyFinding]]:
        """Evaluate data collection capabilities and generate privacy findings."""
        detected_sdks = detected_sdks or []
        capabilities: list[DataCapabilityAssessment] = []
        findings: list[PrivacyFinding] = []

        device_ids_found: list[str] = []
        has_ad_id = False
        has_clipboard = False
        has_accessibility = False
        background_caps: list[str] = []

        # 1. Device Identifiers Scan
        id_signatures = {
            "TelephonyManager.getDeviceId": ["getDeviceId"],
            "TelephonyManager.getImei": ["getImei"],
            "TelephonyManager.getMeid": ["getMeid"],
            "TelephonyManager.getSubscriberId": ["getSubscriberId"],
            "TelephonyManager.getSimSerialNumber": ["getSimSerialNumber"],
            "Settings.Secure.ANDROID_ID": ["ANDROID_ID", "android_id"],
            "Build.SERIAL": ["getSerial", "Build.SERIAL"],
            "MacAddress": ["getMacAddress"],
        }
        for label, patterns in id_signatures.items():
            matched = False
            for p in patterns:
                in_strings = any(p in s for s in index.strings)
                in_methods = any(p in m for m in index.methods)
                in_apis = any(p in a for a in index.apis)
                if in_strings or in_methods or in_apis:
                    matched = True
                    break
            if matched:
                device_ids_found.append(label)

        # 2. Advertising ID Scan
        ad_id_patterns = [
            "AdvertisingIdClient",
            "getAdvertisingIdInfo",
            "com.google.android.gms.ads.identifier",
        ]
        if any(any(p in s for s in index.strings) for p in ad_id_patterns) or any(
            any(p in c for p in ad_id_patterns) for c in index.classes
        ):
            has_ad_id = True

        # 3. Clipboard Access Scan
        clipboard_patterns = [
            "android.content.ClipboardManager",
            "ClipboardManager",
            "getPrimaryClip",
        ]
        if any(any(p in c for p in clipboard_patterns) for c in index.classes) or any(
            any(p in a for p in clipboard_patterns) for a in index.apis
        ):
            has_clipboard = True

        # 4. Accessibility Service Scan
        if inspection.manifest:
            for s in inspection.manifest.services:
                is_acc = (
                    s.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                    or "AccessibilityService" in s.name
                )
                if is_acc:
                    has_accessibility = True
                    break
        if not has_accessibility:
            has_accessibility = any("AccessibilityService" in c for c in index.classes)

        # 5. Background Components Correlation
        bg_components: list[str] = []
        if inspection.manifest:
            for s in inspection.manifest.services:
                bg_components.append(f"Service:{s.name}")
            for r in inspection.manifest.receivers:
                bg_components.append(f"Receiver:{r.name}")

        # 6. Evaluate Major Data Capabilities
        # Capability: Location
        loc_perms = [p for p in index.permissions if "LOCATION" in p]
        loc_apis = [a for a in index.apis if "location" in a.lower()]
        loc_sdks = [
            s.name
            for s in detected_sdks
            if s.category.value in ("advertising", "analytics", "tracking")
        ]
        loc_eps = [
            ep.endpoint
            for ep in (endpoints.classified_endpoints if endpoints else [])
            if ep.category.value in ("advertising", "analytics", "tracking")
        ][:5]

        if loc_perms or loc_apis:
            loc_evidence: list[Evidence] = []
            for lp in loc_perms:
                loc_evidence.append(
                    Evidence(
                        description=f"Declared location permission: {lp}",
                        location=f"permission:{lp}",
                        snippet=f"Declared permission: {lp}",
                    )
                )
            for la in loc_apis:
                loc_evidence.append(
                    Evidence(
                        description=f"Referenced location API: {la}",
                        location=f"api:{la}",
                        snippet=f"Referenced location API: {la}",
                    )
                )

            bg_loc = [c for c in bg_components if any("location" in c.lower() for _ in [1])]
            if bg_loc:
                background_caps.append("location")

            assessment_text = (
                "The APK declares location-related capabilities and static framework references."
            )
            if loc_sdks and loc_eps:
                assessment_text += (
                    " Third-party tracking or advertising SDKs and endpoints are also present."
                )

            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.LOCATION,
                    description=(
                        "Physical device location capability (GPS, Network, Fused Location)."
                    ),
                    permissions=loc_perms,
                    apis=loc_apis,
                    associated_sdks=loc_sdks[:5],
                    associated_endpoints=loc_eps,
                    components=bg_loc,
                    assessment=assessment_text,
                    evidence=loc_evidence,
                    limitations=[
                        "Static analysis cannot establish that physical location is collected "
                        "or transmitted during runtime."
                    ],
                )
            )

            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-LOCATION",
                    category="location",
                    title="Location Capability Detected",
                    description=(
                        f"Application declares location permissions ({', '.join(loc_perms)}) "
                        f"and references location APIs ({', '.join(loc_apis[:3])})."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH if (loc_perms and loc_apis) else Confidence.MEDIUM,
                    evidence=loc_evidence,
                    limitations=["Static analysis cannot establish runtime location collection."],
                )
            )

        # Capability: Microphone
        mic_perms = [p for p in index.permissions if "RECORD_AUDIO" in p]
        mic_apis = [
            a
            for a in index.apis
            if "AudioRecord" in a or "MediaRecorder" in a or "SpeechRecognizer" in a
        ]
        if mic_perms or mic_apis:
            mic_ev = [
                Evidence(
                    description=f"Declared microphone permission: {p}",
                    location=f"permission:{p}",
                    snippet=p,
                )
                for p in mic_perms
            ] + [
                Evidence(
                    description=f"Referenced audio API: {a}",
                    location=f"api:{a}",
                    snippet=a,
                )
                for a in mic_apis
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.MICROPHONE,
                    description="Audio recording and microphone capability.",
                    permissions=mic_perms,
                    apis=mic_apis,
                    associated_sdks=[],
                    associated_endpoints=[],
                    components=[],
                    assessment=(
                        "The APK declares microphone recording capabilities and related audio APIs."
                    ),
                    evidence=mic_ev,
                    limitations=["Static analysis cannot establish runtime audio recording."],
                )
            )
            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-MICROPHONE",
                    category="audio",
                    title="Microphone Audio Recording Capability Detected",
                    description=(
                        "Application requests audio recording permission and references "
                        "audio recording APIs."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH if (mic_perms and mic_apis) else Confidence.MEDIUM,
                    evidence=mic_ev,
                    limitations=["Static analysis cannot prove runtime microphone activation."],
                )
            )

        # Capability: Camera
        cam_perms = [p for p in index.permissions if "CAMERA" in p]
        cam_apis = [a for a in index.apis if "Camera" in a or "CameraManager" in a]
        if cam_perms or cam_apis:
            cam_ev = [
                Evidence(
                    description=f"Declared camera permission: {p}",
                    location=f"permission:{p}",
                    snippet=p,
                )
                for p in cam_perms
            ] + [
                Evidence(
                    description=f"Referenced camera API: {a}",
                    location=f"api:{a}",
                    snippet=a,
                )
                for a in cam_apis
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.CAMERA,
                    description="Device camera capture capability.",
                    permissions=cam_perms,
                    apis=cam_apis,
                    associated_sdks=[],
                    associated_endpoints=[],
                    components=[],
                    assessment="The APK declares camera capture capabilities.",
                    evidence=cam_ev,
                    limitations=["Static analysis cannot prove runtime camera usage."],
                )
            )

        # Capability: Contacts
        contacts_perms = [p for p in index.permissions if "CONTACTS" in p]
        contacts_apis = [a for a in index.apis if "ContactsContract" in a]
        if contacts_perms or contacts_apis:
            cont_ev = [
                Evidence(
                    description=f"Declared contacts permission: {p}",
                    location=f"permission:{p}",
                    snippet=p,
                )
                for p in contacts_perms
            ] + [
                Evidence(
                    description=f"Referenced contacts API: {a}",
                    location=f"api:{a}",
                    snippet=a,
                )
                for a in contacts_apis
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.CONTACTS,
                    description="Address book and contacts reading/writing capability.",
                    permissions=contacts_perms,
                    apis=contacts_apis,
                    associated_sdks=[],
                    associated_endpoints=[],
                    components=[],
                    assessment="The APK declares contact list access capabilities.",
                    evidence=cont_ev,
                    limitations=["Static analysis cannot establish runtime contacts extraction."],
                )
            )

        # Capability: Device Identifiers
        if device_ids_found:
            id_ev = [
                Evidence(
                    description=f"Referenced device identifier method: {i}",
                    location=f"dex:{i}",
                    snippet=f"Referenced device identifier method: {i}",
                )
                for i in device_ids_found
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.DEVICE_IDENTIFIERS,
                    description=(
                        "Hardware and persistent device identifier capability "
                        "(IMEI, MEID, Android ID, Serial)."
                    ),
                    permissions=[p for p in index.permissions if "PHONE_STATE" in p],
                    apis=device_ids_found,
                    associated_sdks=[s.name for s in detected_sdks][:5],
                    associated_endpoints=[],
                    components=[],
                    assessment="Static references to persistent device identifiers detected.",
                    evidence=id_ev,
                    limitations=[
                        "Static method references do not verify runtime execution or exfiltration."
                    ],
                )
            )
            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-DEVICE-IDENTIFIERS",
                    category="identifiers",
                    title="Device Identifier Access References Detected",
                    description=(
                        f"Static code references found for device identifiers: "
                        f"{', '.join(device_ids_found)}."
                    ),
                    severity=Severity.HIGH,
                    confidence=(
                        Confidence.CONFIRMED if len(device_ids_found) >= 2 else Confidence.HIGH
                    ),
                    evidence=id_ev,
                    limitations=[
                        "Static method reference does not establish that the identifier is sent "
                        "across the network."
                    ],
                )
            )

        # Capability: Advertising ID
        if has_ad_id:
            ad_ev = [
                Evidence(
                    description="Referenced Google AdvertisingIdClient API",
                    location="dex:com.google.android.gms.ads.identifier.AdvertisingIdClient",
                    snippet="Referenced Google AdvertisingIdClient API",
                )
            ]
            ad_sdks = [s.name for s in detected_sdks if s.category.value == "advertising"][:5]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.ADVERTISING_ID,
                    description="Google Play Services Advertising ID retrieval capability.",
                    permissions=[],
                    apis=["com.google.android.gms.ads.identifier.AdvertisingIdClient"],
                    associated_sdks=ad_sdks,
                    associated_endpoints=[],
                    components=[],
                    assessment="Application references Google AdvertisingIdClient for ad tracking.",
                    evidence=ad_ev,
                    limitations=[
                        "Static reference does not prove runtime advertising ID retrieval."
                    ],
                )
            )
            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-ADVERTISING-ID",
                    category="identifiers",
                    title="Advertising ID (AAID) Capability Detected",
                    description=(
                        "Application references Google Play Services AdvertisingIdClient "
                        "for advertising tracking."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=ad_ev,
                    limitations=["Static analysis cannot prove runtime AAID extraction."],
                )
            )

        # Capability: Clipboard
        if has_clipboard:
            clip_ev = [
                Evidence(
                    description="Referenced ClipboardManager API",
                    location="dex:android.content.ClipboardManager",
                    snippet="Referenced ClipboardManager API",
                )
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.CLIPBOARD,
                    description="Clipboard access capability.",
                    permissions=[],
                    apis=["android.content.ClipboardManager"],
                    associated_sdks=[],
                    associated_endpoints=[],
                    components=[],
                    assessment="Application references ClipboardManager.",
                    evidence=clip_ev,
                    limitations=[
                        "Clipboard reading cannot be confirmed without dynamic execution."
                    ],
                )
            )
            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-CLIPBOARD",
                    category="clipboard",
                    title="Clipboard Access Capability Detected",
                    description="Application references android.content.ClipboardManager API.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence=clip_ev,
                    limitations=["Static reference does not prove unprompted clipboard reading."],
                )
            )

        # Capability: Accessibility
        if has_accessibility:
            acc_ev = [
                Evidence(
                    description="Declared AccessibilityService component",
                    location="manifest:service",
                    snippet="Declared AccessibilityService component",
                )
            ]
            capabilities.append(
                DataCapabilityAssessment(
                    capability=DataCapabilityType.ACCESSIBILITY,
                    description="Android Accessibility Service capability.",
                    permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"],
                    apis=["android.accessibilityservice.AccessibilityService"],
                    associated_sdks=[],
                    associated_endpoints=[],
                    components=[],
                    assessment="Application declares or implements an AccessibilityService.",
                    evidence=acc_ev,
                    limitations=[
                        "Accessibility service execution requires explicit user authorization."
                    ],
                )
            )
            findings.append(
                PrivacyFinding(
                    id="PRIV-CAP-ACCESSIBILITY",
                    category="accessibility",
                    title="Accessibility Service Capability Detected",
                    description=(
                        "Application defines or references an Android AccessibilityService."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=acc_ev,
                    limitations=["Requires explicit user opt-in in Android system settings."],
                )
            )

        # Return sorted capabilities and findings
        return (
            DataCollectionResult(
                capabilities=sorted(capabilities, key=lambda c: c.capability.value),
                device_identifiers_detected=sorted(device_ids_found),
                advertising_id_detected=has_ad_id,
                clipboard_access_detected=has_clipboard,
                accessibility_service_detected=has_accessibility,
                background_data_capabilities=sorted(background_caps),
            ),
            sorted(findings, key=lambda f: f.id),
        )
