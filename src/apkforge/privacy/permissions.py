"""Permission privacy analysis and permission-to-code correlation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.models import Evidence
from apkforge.privacy.models import (
    PermissionCategory,
    PermissionPrivacyResult,
    PermissionRelevance,
    PermissionUsage,
    PermissionUsageStatus,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.privacy.rules import EvidenceIndex

# Android permission to Privacy Category taxonomy
PERMISSION_TAXONOMY: dict[str, tuple[PermissionCategory, str]] = {
    # Location
    "android.permission.ACCESS_FINE_LOCATION": (PermissionCategory.LOCATION, "dangerous"),
    "android.permission.ACCESS_COARSE_LOCATION": (PermissionCategory.LOCATION, "dangerous"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (PermissionCategory.LOCATION, "dangerous"),
    "android.permission.ACCESS_MEDIA_LOCATION": (PermissionCategory.LOCATION, "dangerous"),
    # Contacts
    "android.permission.READ_CONTACTS": (PermissionCategory.CONTACTS, "dangerous"),
    "android.permission.WRITE_CONTACTS": (PermissionCategory.CONTACTS, "dangerous"),
    "android.permission.GET_ACCOUNTS": (PermissionCategory.CONTACTS, "dangerous"),
    # Phone
    "android.permission.READ_PHONE_STATE": (PermissionCategory.PHONE, "dangerous"),
    "android.permission.CALL_PHONE": (PermissionCategory.PHONE, "dangerous"),
    "android.permission.READ_CALL_LOG": (PermissionCategory.PHONE, "dangerous"),
    "android.permission.WRITE_CALL_LOG": (PermissionCategory.PHONE, "dangerous"),
    "android.permission.ANSWER_PHONE_CALLS": (PermissionCategory.PHONE, "dangerous"),
    "android.permission.READ_PHONE_NUMBERS": (PermissionCategory.PHONE, "dangerous"),
    # SMS
    "android.permission.SEND_SMS": (PermissionCategory.SMS, "dangerous"),
    "android.permission.RECEIVE_SMS": (PermissionCategory.SMS, "dangerous"),
    "android.permission.READ_SMS": (PermissionCategory.SMS, "dangerous"),
    "android.permission.RECEIVE_WAP_PUSH": (PermissionCategory.SMS, "dangerous"),
    "android.permission.RECEIVE_MMS": (PermissionCategory.SMS, "dangerous"),
    # Calendar
    "android.permission.READ_CALENDAR": (PermissionCategory.CALENDAR, "dangerous"),
    "android.permission.WRITE_CALENDAR": (PermissionCategory.CALENDAR, "dangerous"),
    # Audio & Camera
    "android.permission.RECORD_AUDIO": (PermissionCategory.MICROPHONE, "dangerous"),
    "android.permission.CAMERA": (PermissionCategory.CAMERA, "dangerous"),
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": (PermissionCategory.STORAGE_FILES, "dangerous"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (PermissionCategory.STORAGE_FILES, "dangerous"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        PermissionCategory.STORAGE_FILES,
        "signature|appop",
    ),
    "android.permission.READ_MEDIA_IMAGES": (PermissionCategory.STORAGE_FILES, "dangerous"),
    "android.permission.READ_MEDIA_VIDEO": (PermissionCategory.STORAGE_FILES, "dangerous"),
    "android.permission.READ_MEDIA_AUDIO": (PermissionCategory.STORAGE_FILES, "dangerous"),
    # Bluetooth & Nearby
    "android.permission.BLUETOOTH": (PermissionCategory.BLUETOOTH, "normal"),
    "android.permission.BLUETOOTH_ADMIN": (PermissionCategory.BLUETOOTH, "normal"),
    "android.permission.BLUETOOTH_CONNECT": (PermissionCategory.BLUETOOTH, "dangerous"),
    "android.permission.BLUETOOTH_SCAN": (PermissionCategory.BLUETOOTH, "dangerous"),
    "android.permission.BLUETOOTH_ADVERTISE": (PermissionCategory.BLUETOOTH, "dangerous"),
    "android.permission.NEARBY_WIFI_DEVICES": (PermissionCategory.NEARBY_DEVICES, "dangerous"),
    "android.permission.UWB_RANGING": (PermissionCategory.NEARBY_DEVICES, "dangerous"),
    # Network
    "android.permission.INTERNET": (PermissionCategory.NETWORK, "normal"),
    "android.permission.ACCESS_NETWORK_STATE": (PermissionCategory.NETWORK, "normal"),
    "android.permission.ACCESS_WIFI_STATE": (PermissionCategory.NETWORK, "normal"),
    "android.permission.CHANGE_WIFI_STATE": (PermissionCategory.NETWORK, "normal"),
    # Notifications
    "android.permission.POST_NOTIFICATIONS": (PermissionCategory.NOTIFICATIONS, "dangerous"),
    # Identifiers & System Special
    "android.permission.READ_PRIVILEGED_PHONE_STATE": (
        PermissionCategory.IDENTIFIERS,
        "signature|privileged",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        PermissionCategory.SYSTEM_SPECIAL,
        "signature|appop",
    ),
    "android.permission.WRITE_SETTINGS": (
        PermissionCategory.SYSTEM_SPECIAL,
        "signature|appop",
    ),
    "android.permission.PACKAGE_USAGE_STATS": (
        PermissionCategory.SYSTEM_SPECIAL,
        "signature|appop",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        PermissionCategory.SYSTEM_SPECIAL,
        "signature|appop",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        PermissionCategory.SYSTEM_SPECIAL,
        "normal",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        PermissionCategory.SYSTEM_SPECIAL,
        "signature",
    ),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (
        PermissionCategory.NOTIFICATIONS,
        "signature",
    ),
    "android.permission.FOREGROUND_SERVICE": (
        PermissionCategory.SYSTEM_SPECIAL,
        "normal",
    ),
}

# Permission to related framework classes and API signatures
PERMISSION_RELATED_APIS: dict[str, list[str]] = {
    "android.permission.ACCESS_FINE_LOCATION": [
        "android.location.LocationManager",
        "android.location.LocationListener",
        "com.google.android.gms.location.FusedLocationProviderClient",
        "com.google.android.gms.location.LocationRequest",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        "android.location.LocationManager",
        "android.location.LocationListener",
        "com.google.android.gms.location.FusedLocationProviderClient",
    ],
    "android.permission.READ_CONTACTS": [
        "android.provider.ContactsContract",
        "android.content.ContentResolver",
    ],
    "android.permission.WRITE_CONTACTS": [
        "android.provider.ContactsContract",
        "android.content.ContentResolver",
    ],
    "android.permission.RECORD_AUDIO": [
        "android.media.AudioRecord",
        "android.media.MediaRecorder",
        "android.speech.SpeechRecognizer",
    ],
    "android.permission.CAMERA": [
        "android.hardware.Camera",
        "android.hardware.camera2.CameraManager",
        "androidx.camera.core.Camera",
    ],
    "android.permission.READ_PHONE_STATE": [
        "android.telephony.TelephonyManager",
        "android.telephony.SubscriptionManager",
    ],
    "android.permission.SEND_SMS": [
        "android.telephony.SmsManager",
    ],
    "android.permission.READ_SMS": [
        "android.telephony.SmsManager",
        "android.provider.Telephony",
    ],
    "android.permission.READ_CALENDAR": [
        "android.provider.CalendarContract",
    ],
    "android.permission.BLUETOOTH": [
        "android.bluetooth.BluetoothAdapter",
        "android.bluetooth.BluetoothManager",
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        "android.bluetooth.BluetoothAdapter",
        "android.bluetooth.BluetoothDevice",
    ],
    "android.permission.POST_NOTIFICATIONS": [
        "android.app.NotificationManager",
        "androidx.core.app.NotificationManagerCompat",
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "java.io.File",
        "android.os.Environment",
        "android.provider.MediaStore",
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "java.io.File",
        "android.os.Environment",
        "android.provider.MediaStore",
    ],
    "android.permission.MANAGE_EXTERNAL_STORAGE": [
        "java.io.File",
        "android.os.Environment",
    ],
    "android.permission.READ_MEDIA_IMAGES": [
        "android.provider.MediaStore.Images",
    ],
    "android.permission.READ_MEDIA_VIDEO": [
        "android.provider.MediaStore.Video",
    ],
    "android.permission.READ_MEDIA_AUDIO": [
        "android.provider.MediaStore.Audio",
    ],
    "android.permission.RECEIVE_BOOT_COMPLETED": [
        "android.content.BroadcastReceiver",
        "android.intent.action.BOOT_COMPLETED",
    ],
    "android.permission.BIND_ACCESSIBILITY_SERVICE": [
        "android.accessibilityservice.AccessibilityService",
    ],
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": [
        "android.service.notification.NotificationListenerService",
    ],
}


class PermissionAnalyzer:
    """Analyzes declared permissions and correlates them with static code references."""

    def analyze(
        self,
        inspection: InspectionResult,
        index: EvidenceIndex,
    ) -> PermissionPrivacyResult:
        """Execute permission privacy categorization and code correlation."""
        # 1. Collect declared permissions from Phase 2 manifest inspection
        declared_set: set[str] = set()
        prot_level_map: dict[str, str] = {}
        if inspection.manifest and inspection.manifest.permissions:
            for p in inspection.manifest.permissions:
                if isinstance(p, str):
                    declared_set.add(p)
                elif hasattr(p, "name"):
                    declared_set.add(p.name)
                    if p.protection_level:
                        prot_level_map[p.name] = p.protection_level
        elif index.permissions:
            declared_set.update(index.permissions)

        declared = sorted(declared_set)

        categorized: dict[str, list[str]] = {}
        usage_details: list[PermissionUsage] = []
        high_risk_count = 0

        for perm in declared:
            tax_info = PERMISSION_TAXONOMY.get(perm)
            if tax_info:
                cat, prot = tax_info
            else:
                cat = PermissionCategory.OTHER
                prot = prot_level_map.get(perm, "unknown")

            cat_str = cat.value
            categorized.setdefault(cat_str, []).append(perm)

            if prot in ("dangerous", "signature|privileged", "signature|appop"):
                high_risk_count += 1

            # 2. Correlate with API references and code
            related_expected_apis = PERMISSION_RELATED_APIS.get(perm, [])
            matched_apis: list[str] = []
            correlated_classes: list[str] = []
            evidence_list: list[Evidence] = []

            # Check if expected APIs are in index
            for api in related_expected_apis:
                if api in index.apis:
                    matched_apis.append(api)
                    evidence_list.append(
                        Evidence(
                            description=f"Referenced API related to {perm}: {api}",
                            location=f"api:{api}",
                            snippet=f"Referenced API related to {perm}: {api}",
                        )
                    )

            # Check if any classes in app match the API namespace or reference it
            for c in sorted(index.classes):
                for api in matched_apis:
                    if api in c:
                        correlated_classes.append(c)

            # Correlate with manifest components when applicable
            if inspection.manifest:
                if perm == "android.permission.RECEIVE_BOOT_COMPLETED":
                    for r in inspection.manifest.receivers:
                        boot_match = False
                        for filt in r.intent_filters:
                            if any(
                                "BOOT_COMPLETED" in a or "MY_PACKAGE_REPLACED" in a
                                for a in filt.actions
                            ):
                                boot_match = True
                                break
                        if boot_match:
                            correlated_classes.append(r.name)
                            evidence_list.append(
                                Evidence(
                                    description=(
                                        f"Manifest receiver {r.name} "
                                        "configured for boot persistence"
                                    ),
                                    location=f"receiver:{r.name}",
                                    snippet=f"receiver:{r.name}",
                                )
                            )
                elif perm == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                    for s in inspection.manifest.services:
                        if (
                            s.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                            or "AccessibilityService" in s.name
                        ):
                            correlated_classes.append(s.name)
                            evidence_list.append(
                                Evidence(
                                    description=(
                                        f"Manifest accessibility service declaration: {s.name}"
                                    ),
                                    location=f"service:{s.name}",
                                    snippet=f"service:{s.name}",
                                )
                            )
                elif perm == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
                    for s in inspection.manifest.services:
                        if (
                            s.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
                            or "NotificationListener" in s.name
                        ):
                            correlated_classes.append(s.name)
                            evidence_list.append(
                                Evidence(
                                    description=(
                                        f"Manifest notification listener service: {s.name}"
                                    ),
                                    location=f"service:{s.name}",
                                    snippet=f"service:{s.name}",
                                )
                            )

            # Cap classes to 10
            correlated_classes = sorted(set(correlated_classes))[:10]

            # 3. Determine Usage Status
            if correlated_classes and (
                matched_apis
                or perm.startswith("android.permission.BIND_")
                or perm == "android.permission.RECEIVE_BOOT_COMPLETED"
            ):
                usage_status = PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION
            elif matched_apis:
                usage_status = PermissionUsageStatus.DECLARED_AND_REFERENCED
            elif related_expected_apis:
                usage_status = PermissionUsageStatus.DECLARED_ONLY
            else:
                usage_status = PermissionUsageStatus.UNKNOWN

            # 4. Determine Relevance posture
            if usage_status in (
                PermissionUsageStatus.DECLARED_WITH_STRONG_CODE_CORRELATION,
                PermissionUsageStatus.DECLARED_AND_REFERENCED,
            ):
                relevance = PermissionRelevance.LIKELY_REQUIRED
            elif usage_status == PermissionUsageStatus.DECLARED_ONLY:
                # Declared but no matching APIs observed
                if prot == "dangerous":
                    relevance = PermissionRelevance.POTENTIALLY_UNNECESSARY
                else:
                    relevance = PermissionRelevance.OPTIONAL
            else:
                relevance = PermissionRelevance.UNKNOWN

            limitations = [
                "Static analysis cannot establish that permission-protected capabilities "
                "are exercised at runtime."
            ]
            if usage_status == PermissionUsageStatus.DECLARED_ONLY:
                limitations.append(
                    f"Permission '{perm}' is declared in the manifest, but no matching API "
                    "or component references were observed statically; "
                    "actual runtime use remains uncertain."
                )

            usage_details.append(
                PermissionUsage(
                    permission=perm,
                    category=cat,
                    protection_level=prot,
                    usage_status=usage_status,
                    relevance=relevance,
                    description=f"{cat.value.capitalize()} capability permission ({prot})",
                    related_apis=sorted(matched_apis),
                    classes=correlated_classes,
                    methods=[],
                    evidence=evidence_list,
                    limitations=limitations,
                )
            )

        # Sort categorized permissions deterministically
        sorted_categorized = {k: sorted(v) for k, v in sorted(categorized.items())}

        return PermissionPrivacyResult(
            declared_permissions=declared,
            categorized_permissions=sorted_categorized,
            usage_details=sorted(usage_details, key=lambda u: u.permission),
            high_risk_permissions_count=high_risk_count,
        )
