"""Static privacy-relevant behavior and sensitive API indicators analyzer.

Evaluates declarative catalog rules covering location, contacts, telephony IDs,
audio/video capture, clipboard, accessibility, notification listeners, WebViews,
background scheduling, boot persistence, dynamic code loading, and reflection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.privacy.models import (
    AnalysisCompleteness,
    EvidenceState,
    PrivacyFinding,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.privacy.rules import EvidenceIndex


@dataclass(frozen=True)
class StaticBehaviorRule:
    """Declarative definition for static privacy-relevant behavior patterns."""

    id: str
    category: str
    title: str
    description: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.HIGH
    remediation_relevance: str = "Informational review; verify legitimacy in application context."
    api_patterns: tuple[str, ...] = ()
    class_patterns: tuple[str, ...] = ()
    method_patterns: tuple[str, ...] = ()
    string_patterns: tuple[str, ...] = ()
    receiver_actions: tuple[str, ...] = ()
    service_permissions: tuple[str, ...] = ()
    related_permissions: tuple[str, ...] = ()


STATIC_BEHAVIOR_CATALOG: tuple[StaticBehaviorRule, ...] = (
    StaticBehaviorRule(
        id="PRIV-API-LOCATION",
        category="location",
        title="Location Framework API Invocations",
        description=(
            "Static references to Android LocationManager or Google Play Services location "
            "providers detected in bytecode."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Informational; examine whether precise or coarse location access is required for core "
            "functionality."
        ),
        api_patterns=(
            "android.location.LocationManager",
            "android.location.LocationListener",
            "com.google.android.gms.location.FusedLocationProviderClient",
            "com.google.android.gms.location.LocationRequest",
        ),
        class_patterns=(
            "android.location.LocationManager",
            "com.google.android.gms.location.FusedLocationProviderClient",
        ),
        method_patterns=("getLastKnownLocation", "requestLocationUpdates", "requestSingleUpdate"),
        related_permissions=(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ),
    ),
    StaticBehaviorRule(
        id="PRIV-API-CONTACTS",
        category="contacts",
        title="Contacts Provider API Access",
        description=(
            "Static references to ContactsContract or Contacts ContentProvider queries detected "
            "in bytecode."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Informational; review if address book access aligns with declared privacy policy."
        ),
        api_patterns=(
            "android.provider.ContactsContract",
            "android.provider.ContactsContract.Contacts",
            "android.provider.ContactsContract.CommonDataKinds.Phone",
        ),
        class_patterns=("android.provider.ContactsContract",),
        string_patterns=("content://com.android.contacts", "content://contacts"),
        related_permissions=(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
        ),
    ),
    StaticBehaviorRule(
        id="PRIV-API-DEVICE-IDENTIFIER",
        category="device_identifiers",
        title="Hardware & Device Identifier Access",
        description=(
            "Static references to persistent device identifiers (IMEI, MEID, SIM serial, or "
            "ANDROID_ID) detected."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Assess compliance with modern Android platform privacy guidelines (prefer resettable "
            "advertising IDs or app-scoped UUIDs over hardware identifiers)."
        ),
        api_patterns=("android.telephony.TelephonyManager",),
        method_patterns=(
            "getDeviceId",
            "getImei",
            "getMeid",
            "getSubscriberId",
            "getSimSerialNumber",
            "getSerial",
            "getMacAddress",
        ),
        string_patterns=("ANDROID_ID", "android_id", "Build.SERIAL"),
        related_permissions=(
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
        ),
    ),
    StaticBehaviorRule(
        id="PRIV-API-AUDIO-CAPTURE",
        category="microphone",
        title="Audio Recording / Microphone Capture APIs",
        description=(
            "Static references to AudioRecord or MediaRecorder audio capture facilities detected."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Ensure microphone usage is communicated to the user and required runtime permissions "
            "are requested."
        ),
        api_patterns=("android.media.AudioRecord", "android.media.MediaRecorder"),
        class_patterns=("android.media.AudioRecord", "android.media.MediaRecorder"),
        method_patterns=("startRecording", "setAudioSource"),
        related_permissions=("android.permission.RECORD_AUDIO",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-CAMERA",
        category="camera",
        title="Camera Hardware & Capture APIs",
        description="Static references to Camera, Camera2, or CameraX APIs detected in bytecode.",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Ensure camera hardware access is necessary and accompanied by runtime consent prompts."
        ),
        api_patterns=(
            "android.hardware.Camera",
            "android.hardware.camera2.CameraManager",
            "androidx.camera.core.Camera",
        ),
        class_patterns=(
            "android.hardware.Camera",
            "android.hardware.camera2.CameraManager",
            "androidx.camera.core.Camera",
        ),
        method_patterns=("openCamera", "takePicture", "startPreview"),
        related_permissions=("android.permission.CAMERA",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-CLIPBOARD",
        category="clipboard",
        title="Clipboard Access APIs",
        description="Static references to ClipboardManager clip access methods detected.",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance="Verify whether clipboard reads access user data unexpectedly.",
        api_patterns=("android.content.ClipboardManager",),
        class_patterns=("android.content.ClipboardManager", "ClipboardManager"),
        method_patterns=("getPrimaryClip", "setPrimaryClip", "getPrimaryClipDescription"),
    ),
    StaticBehaviorRule(
        id="PRIV-API-ACCESSIBILITY",
        category="accessibility",
        title="Accessibility Service Declaration & APIs",
        description="Declaration or implementation of an Android AccessibilityService detected.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Accessibility services have broad device observation capabilities; verify legitimate "
            "assistive use."
        ),
        api_patterns=("android.accessibilityservice.AccessibilityService",),
        class_patterns=("android.accessibilityservice.AccessibilityService",),
        service_permissions=("android.permission.BIND_ACCESSIBILITY_SERVICE",),
        related_permissions=("android.permission.BIND_ACCESSIBILITY_SERVICE",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-NOTIFICATION-LISTENER",
        category="notifications",
        title="Notification Listener Service APIs",
        description="Declaration or implementation of NotificationListenerService detected.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Notification listeners can intercept incoming notifications across all apps; verify "
            "necessity."
        ),
        api_patterns=("android.service.notification.NotificationListenerService",),
        class_patterns=("android.service.notification.NotificationListenerService",),
        service_permissions=("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",),
        related_permissions=("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-WEBVIEW",
        category="network",
        title="Embedded WebView & Web Interface APIs",
        description=(
            "Static references to Android WebView configuration and web execution interfaces "
            "detected."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Review WebView security settings (e.g. JavaScript execution and native interface "
            "bridges)."
        ),
        api_patterns=("android.webkit.WebView", "android.webkit.WebSettings"),
        class_patterns=("android.webkit.WebView", "android.webkit.WebSettings"),
        method_patterns=("setJavaScriptEnabled", "loadUrl", "addJavascriptInterface"),
    ),
    StaticBehaviorRule(
        id="PRIV-API-SCHEDULING",
        category="background_execution",
        title="Background Job Scheduling & Alarm APIs",
        description=(
            "Static references to WorkManager, JobScheduler, or AlarmManager background execution "
            "detected."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Evaluate whether background tasks perform unauthorized periodic synchronization "
            "or data transmission."
        ),
        api_patterns=(
            "androidx.work.WorkManager",
            "android.app.job.JobScheduler",
            "android.app.AlarmManager",
        ),
        class_patterns=(
            "androidx.work.WorkManager",
            "android.app.job.JobScheduler",
            "android.app.AlarmManager",
        ),
        method_patterns=("setRepeating", "setExactAndAllowWhileIdle", "enqueue"),
    ),
    StaticBehaviorRule(
        id="PRIV-REC-BOOT",
        category="persistence",
        title="Boot & Package Replacement Receivers",
        description=(
            "Manifest declarations for broadcast receivers listening to device boot or package "
            "replacement events."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        remediation_relevance="Review background startup persistence at device boot.",
        receiver_actions=(
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.LOCKED_BOOT_COMPLETED",
            "android.intent.action.MY_PACKAGE_REPLACED",
        ),
        related_permissions=("android.permission.RECEIVE_BOOT_COMPLETED",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-DYNAMIC-CODE",
        category="dynamic_code",
        title="Dynamic Code Loading Facilities",
        description=(
            "Static references to DexClassLoader, PathClassLoader, or InMemoryDexClassLoader "
            "detected."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        remediation_relevance=(
            "Dynamic loading allows runtime code execution bypassing static inspection; verify "
            "source and integrity."
        ),
        api_patterns=(
            "dalvik.system.DexClassLoader",
            "dalvik.system.PathClassLoader",
            "dalvik.system.InMemoryDexClassLoader",
        ),
        class_patterns=(
            "dalvik.system.DexClassLoader",
            "dalvik.system.PathClassLoader",
            "dalvik.system.InMemoryDexClassLoader",
        ),
        method_patterns=("loadClass",),
    ),
    StaticBehaviorRule(
        id="PRIV-API-REFLECTION",
        category="reflection",
        title="Reflection on Internal or Sensitive Classes",
        description=(
            "Static references to reflection APIs combined with internal framework class names "
            "detected."
        ),
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.MEDIUM,
        remediation_relevance=(
            "Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and "
            "policy compliance."
        ),
        api_patterns=("java.lang.reflect.Method", "java.lang.Class"),
        method_patterns=("getMethod", "getDeclaredMethod", "invoke", "forName"),
        string_patterns=("android.os.SystemProperties", "android.app.ActivityThread"),
    ),
)


class BehaviorAnalyzer:
    """Evaluates privacy-relevant static behavior rules against package inspection."""

    def __init__(self, catalog: tuple[StaticBehaviorRule, ...] = STATIC_BEHAVIOR_CATALOG) -> None:
        self._catalog = catalog

    def analyze(
        self,
        inspection: InspectionResult,
        index: EvidenceIndex,
    ) -> list[PrivacyFinding]:
        """Evaluate static behavior rules and produce structured privacy findings."""
        findings: list[PrivacyFinding] = []

        for rule in self._catalog:
            matched_locations: list[str] = []
            matched_values: list[str] = []
            evidence_items: list[Evidence] = []
            source_comp: str | None = None

            # 1. API patterns
            for api in rule.api_patterns:
                if api in index.apis:
                    matched_locations.append(f"api:{api}")
                    matched_values.append(api)
                    evidence_items.append(
                        Evidence(
                            description=f"Referenced API: {api}",
                            location=f"api:{api}",
                            snippet=f"api:{api}",
                        )
                    )

            # 2. Class patterns
            for cls in rule.class_patterns:
                hits = [c for c in index.classes if c == cls or c.startswith(cls + "$")]
                if hits:
                    sample = hits[0]
                    matched_locations.append(f"class:{sample}")
                    matched_values.append(sample)
                    source_comp = sample
                    evidence_items.append(
                        Evidence(
                            description=f"Referenced class: {sample}",
                            location=f"class:{sample}",
                            snippet=f"class:{sample}",
                        )
                    )

            # 3. Method patterns
            for meth in rule.method_patterns:
                for m in index.methods:
                    if m == meth or m.endswith(f".{meth}"):
                        matched_locations.append(f"method:{m}")
                        matched_values.append(m)
                        evidence_items.append(
                            Evidence(
                                description=f"Referenced method: {m}",
                                location=f"method:{m}",
                                snippet=f"method:{m}",
                            )
                        )
                        break

            # 4. String patterns
            for s in rule.string_patterns:
                if any(s in is_str for is_str in index.strings):
                    matched_locations.append(f"string:{s}")
                    matched_values.append(s)
                    evidence_items.append(
                        Evidence(
                            description=f"Constant string reference: {s}",
                            location=f"dex:string:{s}",
                            snippet=f"string:{s}",
                        )
                    )

            # 5. Manifest receiver actions
            if rule.receiver_actions and inspection.manifest:
                for r in inspection.manifest.receivers:
                    for filt in r.intent_filters:
                        for act in filt.actions:
                            if act in rule.receiver_actions:
                                loc = f"receiver:{r.name}:action:{act}"
                                matched_locations.append(loc)
                                matched_values.append(f"{r.name} ({act})")
                                source_comp = r.name
                                evidence_items.append(
                                    Evidence(
                                        description=f"Manifest broadcast receiver action: {act}",
                                        location=loc,
                                        snippet=f'<receiver android:name="{r.name}"> -> {act}',
                                    )
                                )

            # 6. Manifest service permissions
            if rule.service_permissions and inspection.manifest:
                for svc in inspection.manifest.services:
                    if svc.permission and svc.permission in rule.service_permissions:
                        loc = f"service:{svc.name}:permission:{svc.permission}"
                        matched_locations.append(loc)
                        matched_values.append(f"{svc.name} ({svc.permission})")
                        source_comp = svc.name
                        evidence_items.append(
                            Evidence(
                                description=f"Manifest service protected by {svc.permission}",
                                location=loc,
                                snippet=(
                                    f'<service android:name="{svc.name}" '
                                    f'android:permission="{svc.permission}">'
                                ),
                            )
                        )

            # Check if any evidence matched
            if not matched_locations:
                continue

            # Correlate with related declared permissions
            related_perms: list[str] = [
                p for p in rule.related_permissions if p in index.permissions
            ]

            # Determine confidence
            confidence = rule.confidence
            if len(matched_locations) >= 2 or related_perms:
                confidence = Confidence.CONFIRMED if confidence == Confidence.HIGH else confidence

            findings.append(
                PrivacyFinding(
                    id=rule.id,
                    category=rule.category,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=confidence,
                    evidence_state=EvidenceState.OBSERVED,
                    evidence_locations=sorted(set(matched_locations)),
                    evidence_values=sorted(set(matched_values)),
                    source_component=source_comp,
                    related_permissions=sorted(related_perms),
                    is_direct=True,
                    analysis_completeness=AnalysisCompleteness.COMPLETE,
                    remediation_relevance=rule.remediation_relevance,
                    evidence=evidence_items,
                    limitations=[
                        "Static observation of API or component reference does not guarantee "
                        "runtime execution or data exfiltration."
                    ],
                )
            )

        return sorted(findings, key=lambda f: f.id)
