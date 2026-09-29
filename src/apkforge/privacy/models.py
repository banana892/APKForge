"""Domain models for the APKForge Phase 4 Privacy & Tracker Engine."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus, Confidence, Evidence, Severity

__all__ = [
    "AdvertisingResult",
    "AnalyticsResult",
    "ClassifiedEndpoint",
    "DataCapabilityAssessment",
    "DataCapabilityType",
    "DataCollectionResult",
    "DetectedSDK",
    "EndpointCategory",
    "EndpointResult",
    "PermissionCategory",
    "PermissionPrivacyResult",
    "PermissionRelevance",
    "PermissionUsage",
    "PermissionUsageStatus",
    "PrivacyFinding",
    "PrivacyResult",
    "SDKCategory",
    "TelemetryResult",
    "TrackerResult",
]


# ===========================================================================
# Permission Privacy Models
# ===========================================================================


class PermissionCategory(StrEnum):
    """Privacy taxonomy categories for Android permissions."""

    LOCATION = "location"
    CONTACTS = "contacts"
    PHONE = "phone"
    SMS = "sms"
    CALENDAR = "calendar"
    MICROPHONE = "microphone"
    CAMERA = "camera"
    STORAGE_FILES = "storage_files"
    BLUETOOTH = "bluetooth"
    NEARBY_DEVICES = "nearby_devices"
    NETWORK = "network"
    NOTIFICATIONS = "notifications"
    IDENTIFIERS = "identifiers"
    SYSTEM_SPECIAL = "system_special"
    OTHER = "other"


class PermissionRelevance(StrEnum):
    """Categorization of permission necessity and risk posture."""

    REQUIRED = "required"
    LIKELY_REQUIRED = "likely_required"
    OPTIONAL = "optional"
    POTENTIALLY_UNNECESSARY = "potentially_unnecessary"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class PermissionUsageStatus(StrEnum):
    """Confidence classification of static permission-to-code correlation."""

    DECLARED_ONLY = "declared_only"
    DECLARED_AND_REFERENCED = "declared_and_referenced"
    DECLARED_WITH_STRONG_CODE_CORRELATION = "declared_with_strong_code_correlation"
    UNKNOWN = "unknown"


class PermissionUsage(BaseModel):
    """Structured correlation of a declared permission to code and APIs."""

    permission: str
    category: PermissionCategory = PermissionCategory.OTHER
    protection_level: str | None = None
    usage_status: PermissionUsageStatus = PermissionUsageStatus.UNKNOWN
    relevance: PermissionRelevance = PermissionRelevance.UNKNOWN
    description: str | None = None
    related_apis: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PermissionPrivacyResult(BaseModel):
    """Aggregate result of permission privacy analysis."""

    declared_permissions: list[str] = Field(default_factory=list)
    categorized_permissions: dict[str, list[str]] = Field(default_factory=dict)
    usage_details: list[PermissionUsage] = Field(default_factory=list)
    high_risk_permissions_count: int = 0


# ===========================================================================
# SDK & Tracker Models
# ===========================================================================


class SDKCategory(StrEnum):
    """Functional categories for third-party libraries and SDKs."""

    ADVERTISING = "advertising"
    ANALYTICS = "analytics"
    TRACKING = "tracking"
    TELEMETRY = "telemetry"
    ATTRIBUTION = "attribution"
    CRASH_REPORTING = "crash_reporting"
    SOCIAL = "social"
    PAYMENTS = "payments"
    OTHER = "other"


class DetectedSDK(BaseModel):
    """A detected third-party library or tracking technology."""

    id: str
    name: str
    vendor: str | None = None
    category: SDKCategory
    version: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    description: str | None = None
    matched_packages: list[str] = Field(default_factory=list)
    matched_classes: list[str] = Field(default_factory=list)
    matched_strings: list[str] = Field(default_factory=list)
    matched_endpoints: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class TrackerResult(BaseModel):
    """Detected tracking and attribution technologies."""

    detected_trackers: list[DetectedSDK] = Field(default_factory=list)
    total_trackers: int = 0


class AdvertisingResult(BaseModel):
    """Detected advertising frameworks and ad networks."""

    detected_advertising_sdks: list[DetectedSDK] = Field(default_factory=list)
    total_advertising_sdks: int = 0


class AnalyticsResult(BaseModel):
    """Detected user/product analytics and event logging systems."""

    detected_analytics_sdks: list[DetectedSDK] = Field(default_factory=list)
    total_analytics_sdks: int = 0


class TelemetryResult(BaseModel):
    """Detected diagnostic, crash reporting, and telemetry frameworks."""

    detected_telemetry_sdks: list[DetectedSDK] = Field(default_factory=list)
    total_telemetry_sdks: int = 0


# ===========================================================================
# Network Endpoint Models
# ===========================================================================


class EndpointCategory(StrEnum):
    """Functional classification for network endpoints."""

    FIRST_PARTY = "first_party"
    ADVERTISING = "advertising"
    ANALYTICS = "analytics"
    TRACKING = "tracking"
    TELEMETRY = "telemetry"
    CRASH_REPORTING = "crash_reporting"
    ATTRIBUTION = "attribution"
    CDN = "cdn"
    UPDATE = "update"
    UNKNOWN = "unknown"


class ClassifiedEndpoint(BaseModel):
    """A classified domain or URL extracted from the APK."""

    endpoint: str
    domain: str
    is_url: bool = False
    category: EndpointCategory = EndpointCategory.UNKNOWN
    purpose: str | None = None
    associated_sdk: str | None = None
    is_first_party: bool = False
    provenance: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class EndpointResult(BaseModel):
    """Analysis of network endpoints extracted from the application."""

    total_endpoints: int = 0
    first_party_domains: list[str] = Field(default_factory=list)
    third_party_domains: list[str] = Field(default_factory=list)
    classified_endpoints: list[ClassifiedEndpoint] = Field(default_factory=list)
    by_category: dict[str, list[str]] = Field(default_factory=dict)


# ===========================================================================
# Data Collection & Capability Models
# ===========================================================================


class DataCapabilityType(StrEnum):
    """Taxonomy of potential data collection types and device capabilities."""

    LOCATION = "location"
    CONTACTS = "contacts"
    PHONE = "phone"
    SMS = "sms"
    CALENDAR = "calendar"
    MICROPHONE = "microphone"
    CAMERA = "camera"
    FILES = "files"
    DEVICE_IDENTIFIERS = "device_identifiers"
    ADVERTISING_ID = "advertising_id"
    CLIPBOARD = "clipboard"
    ACCESSIBILITY = "accessibility"
    NETWORK_INFORMATION = "network_information"
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    ACCOUNT_INFORMATION = "account_information"
    APP_USAGE = "app_usage"
    DIAGNOSTIC_DATA = "diagnostic_data"
    CRASH_DATA = "crash_data"


class DataCapabilityAssessment(BaseModel):
    """Correlation of permissions, APIs, SDKs, and endpoints for a capability."""

    capability: DataCapabilityType
    description: str
    permissions: list[str] = Field(default_factory=list)
    apis: list[str] = Field(default_factory=list)
    associated_sdks: list[str] = Field(default_factory=list)
    associated_endpoints: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    assessment: str
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class DataCollectionResult(BaseModel):
    """Evaluation of data collection capabilities present in the APK."""

    capabilities: list[DataCapabilityAssessment] = Field(default_factory=list)
    device_identifiers_detected: list[str] = Field(default_factory=list)
    advertising_id_detected: bool = False
    clipboard_access_detected: bool = False
    accessibility_service_detected: bool = False
    background_data_capabilities: list[str] = Field(default_factory=list)


# ===========================================================================
# Findings & Top-level Privacy Result
# ===========================================================================


class PrivacyFinding(BaseModel):
    """An evidence-oriented privacy finding with technical justification."""

    id: str
    category: str
    title: str
    description: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class PrivacyResult(BaseModel):
    """Complete result of Phase 4 Privacy & Tracker analysis."""

    status: AnalysisStatus = AnalysisStatus.COMPLETE

    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None

    permissions: PermissionPrivacyResult = Field(default_factory=PermissionPrivacyResult)
    trackers: TrackerResult = Field(default_factory=TrackerResult)
    advertising: AdvertisingResult = Field(default_factory=AdvertisingResult)
    analytics: AnalyticsResult = Field(default_factory=AnalyticsResult)
    telemetry: TelemetryResult = Field(default_factory=TelemetryResult)
    endpoints: EndpointResult = Field(default_factory=EndpointResult)
    data_collection: DataCollectionResult = Field(default_factory=DataCollectionResult)

    detected_sdks: list[DetectedSDK] = Field(default_factory=list)

    findings: list[PrivacyFinding] = Field(default_factory=list)

    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def all_detected_sdks(self) -> list[DetectedSDK]:
        """All detected SDKs across detected_sdks, trackers, advertising, analytics, telemetry."""
        seen: set[str] = set()
        result: list[DetectedSDK] = []
        for sdk in (
            self.detected_sdks
            + self.trackers.detected_trackers
            + self.advertising.detected_advertising_sdks
            + self.analytics.detected_analytics_sdks
            + self.telemetry.detected_telemetry_sdks
        ):
            if sdk.name not in seen:
                seen.add(sdk.name)
                result.append(sdk)
        return result
