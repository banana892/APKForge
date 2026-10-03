"""Domain models for the APKForge Phase 4 & Phase F Privacy & Tracker Intelligence Layer."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus, Confidence, Evidence, Severity

__all__ = [
    "AdvertisingResult",
    "AnalysisCompleteness",
    "AnalyticsResult",
    "ClassifiedEndpoint",
    "ComponentReportSection",
    "DataCapabilityAssessment",
    "DataCapabilityType",
    "DataCollectionResult",
    "DetectedSDK",
    "EndpointCategory",
    "EndpointReportSection",
    "EndpointResult",
    "EvidenceState",
    "PermissionCategory",
    "PermissionPrivacyResult",
    "PermissionRelevance",
    "PermissionReportSection",
    "PermissionUsage",
    "PermissionUsageStatus",
    "PrivacyFinding",
    "PrivacyReport",
    "PrivacyResult",
    "SDKCategory",
    "SDKReportSection",
    "SensitiveAPIReportSection",
    "TelemetryResult",
    "TrackerResult",
    "UnknownPartialReportSection",
]


# ===========================================================================
# Evidence & Observation States
# ===========================================================================


class EvidenceState(StrEnum):
    """Explicit observation state for privacy evidence."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    PARTIAL = "PARTIAL"


class AnalysisCompleteness(StrEnum):
    """Evaluation completeness state."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


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
    evidence_locations: list[str] = Field(default_factory=list)
    actual_network_use_observed: bool = False
    network_use_status: str = "CANNOT_DETERMINE_STATICALLY"
    network_use_determination: str = (
        "Static presence does not prove runtime network activity or data "
        "transmission to this vendor."
    )
    false_positive_risk: str | None = None
    source_reference: str | None = None


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
    SOCIAL_LOGIN = "social_login"
    CONTENT_CDN = "content_cdn"
    CDN = "content_cdn"
    UPDATE_INFRASTRUCTURE = "update_infrastructure"
    UPDATE = "update_infrastructure"
    POTENTIALLY_SENSITIVE = "potentially_sensitive"
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
    raw_evidence: str | None = None
    transmission_verified: bool = False
    disclaimer: str = (
        "Presence of domain or URL in static binary does not prove data is "
        "transmitted to this endpoint."
    )


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
    evidence_state: EvidenceState = EvidenceState.OBSERVED
    evidence_locations: list[str] = Field(default_factory=list)
    evidence_values: list[str] = Field(default_factory=list)
    source_component: str | None = None
    related_permissions: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)
    related_sdks: list[str] = Field(default_factory=list)
    is_direct: bool = True
    analysis_completeness: AnalysisCompleteness = AnalysisCompleteness.COMPLETE
    remediation_relevance: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


# ===========================================================================
# Structured Report Sections & PrivacyReport
# ===========================================================================


class PermissionReportSection(BaseModel):
    """Structured report section for permissions."""

    declared_permissions: list[str] = Field(default_factory=list)
    categorized_permissions: dict[str, list[str]] = Field(default_factory=dict)
    usage_details: list[PermissionUsage] = Field(default_factory=list)
    uncertain_permissions: list[str] = Field(default_factory=list)
    high_risk_count: int = 0


class ComponentReportSection(BaseModel):
    """Structured report section for components and capabilities."""

    background_capabilities: list[str] = Field(default_factory=list)
    boot_receivers: list[str] = Field(default_factory=list)
    accessibility_services: list[str] = Field(default_factory=list)
    notification_listeners: list[str] = Field(default_factory=list)
    persistence_indicators: list[str] = Field(default_factory=list)


class SDKReportSection(BaseModel):
    """Structured report section for third-party SDKs."""

    detected_sdks: list[DetectedSDK] = Field(default_factory=list)
    trackers_count: int = 0
    advertising_count: int = 0
    analytics_count: int = 0
    telemetry_count: int = 0
    network_use_determination: str = (
        "Static presence of an SDK library does not prove actual data transmission at runtime."
    )


class EndpointReportSection(BaseModel):
    """Structured report section for endpoints."""

    total_endpoints: int = 0
    first_party_domains: list[str] = Field(default_factory=list)
    third_party_domains: list[str] = Field(default_factory=list)
    classified_endpoints: list[ClassifiedEndpoint] = Field(default_factory=list)
    by_category: dict[str, list[str]] = Field(default_factory=dict)
    network_traffic_disclaimer: str = (
        "Static domain/URL extraction does not constitute proof that network traffic is sent to "
        "these destinations."
    )


class SensitiveAPIReportSection(BaseModel):
    """Structured report section for sensitive API indicators."""

    device_identifiers: list[str] = Field(default_factory=list)
    advertising_id_detected: bool = False
    clipboard_access: bool = False
    accessibility_apis: list[str] = Field(default_factory=list)
    notification_apis: list[str] = Field(default_factory=list)
    dynamic_code_loading: list[str] = Field(default_factory=list)
    reflection_sensitive: list[str] = Field(default_factory=list)
    location_apis: list[str] = Field(default_factory=list)
    contacts_apis: list[str] = Field(default_factory=list)
    audio_capture_apis: list[str] = Field(default_factory=list)
    camera_apis: list[str] = Field(default_factory=list)
    webview_network_apis: list[str] = Field(default_factory=list)


class UnknownPartialReportSection(BaseModel):
    """Structured report section for unknown or partial analysis items."""

    partial_findings: list[PrivacyFinding] = Field(default_factory=list)
    unknown_findings: list[PrivacyFinding] = Field(default_factory=list)
    inconclusive_items: list[str] = Field(default_factory=list)


class PrivacyReport(BaseModel):
    """Structured, multi-section privacy intelligence report."""

    status: AnalysisStatus = AnalysisStatus.COMPLETE
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    permissions: PermissionReportSection = Field(default_factory=PermissionReportSection)
    components: ComponentReportSection = Field(default_factory=ComponentReportSection)
    sdks: SDKReportSection = Field(default_factory=SDKReportSection)
    endpoints: EndpointReportSection = Field(default_factory=EndpointReportSection)
    sensitive_apis: SensitiveAPIReportSection = Field(default_factory=SensitiveAPIReportSection)
    correlated_findings: list[PrivacyFinding] = Field(default_factory=list)
    unknown_partial: UnknownPartialReportSection = Field(
        default_factory=UnknownPartialReportSection
    )
    limitations: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        """Render a deterministic, readable Markdown privacy intelligence report."""
        pkg = self.package_name or "Unknown Package"
        ver = f"v{self.version_name}" if self.version_name else ""
        lines: list[str] = [
            f"# Privacy & Tracker Intelligence Report: {pkg} {ver}".strip(),
            "",
            f"**Status**: `{self.status.value.upper()}`",
            "",
            "---",
            "",
            "## Section A: Permissions",
            f"- Declared Permissions Count: {len(self.permissions.declared_permissions)}",
            f"- High-Risk / Dangerous Permissions: {self.permissions.high_risk_count}",
        ]
        if self.permissions.uncertain_permissions:
            lines.append(
                "- Declared Without Static Code Correlation: "
                f"{len(self.permissions.uncertain_permissions)}"
            )
            for p in self.permissions.uncertain_permissions[:10]:
                lines.append(f"  - `{p}` (declared only)")
        lines.append("")

        lines.extend(
            [
                "## Section B: Components & Capabilities",
                f"- Background Capabilities: {len(self.components.background_capabilities)}",
                f"- Boot / Persistence Receivers: {len(self.components.boot_receivers)}",
                f"- Accessibility Services: {len(self.components.accessibility_services)}",
                f"- Notification Listeners: {len(self.components.notification_listeners)}",
                "",
                "## Section C: SDK & Library Indicators",
                f"- Total Third-Party SDK Indicators: {len(self.sdks.detected_sdks)}",
                f"  - Trackers: {self.sdks.trackers_count}",
                f"  - Advertising: {self.sdks.advertising_count}",
                f"  - Analytics: {self.sdks.analytics_count}",
                f"  - Telemetry / Crash: {self.sdks.telemetry_count}",
                f"- Network Traffic Determination: *{self.sdks.network_use_determination}*",
            ]
        )
        for sdk in self.sdks.detected_sdks:
            lines.append(
                f"  - **{sdk.name}** (`{sdk.id}`, category: `{sdk.category.value}`, "
                f"confidence: `{sdk.confidence.value}`)"
            )
            if sdk.matched_packages:
                lines.append(f"    - Packages: {', '.join(sdk.matched_packages)}")
            if sdk.matched_classes:
                lines.append(f"    - Classes: {', '.join(sdk.matched_classes[:3])}")
            if sdk.matched_endpoints:
                lines.append(f"    - Endpoints: {', '.join(sdk.matched_endpoints)}")
        lines.append("")

        lines.extend(
            [
                "## Section D: Domains & Endpoints",
                f"- Total Extracted Endpoints: {self.endpoints.total_endpoints}",
                f"- First-Party Domains: {len(self.endpoints.first_party_domains)}",
                f"- Third-Party Domains: {len(self.endpoints.third_party_domains)}",
                f"- Disclaimer: *{self.endpoints.network_traffic_disclaimer}*",
            ]
        )
        for cat, doms in sorted(self.endpoints.by_category.items()):
            lines.append(f"- Category `{cat}` ({len(doms)}): {', '.join(sorted(doms)[:5])}")
        lines.append("")

        dev_ids = ", ".join(self.sensitive_apis.device_identifiers) or "None"
        adid = "Detected" if self.sensitive_apis.advertising_id_detected else "None"
        clip = "Detected" if self.sensitive_apis.clipboard_access else "None"
        dyn = ", ".join(self.sensitive_apis.dynamic_code_loading) or "None"
        refl = ", ".join(self.sensitive_apis.reflection_sensitive) or "None"
        locs_api = ", ".join(self.sensitive_apis.location_apis) or "None"
        contacts_api = ", ".join(self.sensitive_apis.contacts_apis) or "None"
        audio_api = ", ".join(self.sensitive_apis.audio_capture_apis) or "None"
        cam_api = ", ".join(self.sensitive_apis.camera_apis) or "None"

        lines.extend(
            [
                "## Section E: Sensitive API Indicators",
                f"- Device Identifiers: {dev_ids}",
                f"- Advertising ID Client: {adid}",
                f"- Clipboard Access: {clip}",
                f"- Dynamic Code Loading: {dyn}",
                f"- Sensitive Reflection: {refl}",
                f"- Location APIs: {locs_api}",
                f"- Contacts APIs: {contacts_api}",
                f"- Audio Capture APIs: {audio_api}",
                f"- Camera APIs: {cam_api}",
                "",
                "## Section F: Correlated Findings",
                f"- Total Findings: {len(self.correlated_findings)}",
            ]
        )
        for f in self.correlated_findings:
            locs = (
                ", ".join(f.evidence_locations[:2]) if f.evidence_locations else "unknown location"
            )
            lines.append(
                f"- `[{f.id}]` ({f.severity.value.upper()}) **{f.title}** "
                f"[{f.evidence_state.value}] (Confidence: {f.confidence.value})"
            )
            lines.append(f"  - Description: {f.description}")
            lines.append(f"  - Evidence: {locs}")
            if f.remediation_relevance:
                lines.append(f"  - Remediation Relevance: {f.remediation_relevance}")
        lines.append("")

        lines.extend(
            [
                "## Section G: Unknown / Partial Analysis",
                f"- Partial Findings Count: {len(self.unknown_partial.partial_findings)}",
                f"- Unknown Findings Count: {len(self.unknown_partial.unknown_findings)}",
                f"- Inconclusive Items Count: {len(self.unknown_partial.inconclusive_items)}",
            ]
        )
        for item in self.unknown_partial.inconclusive_items:
            lines.append(f"  - {item}")
        lines.append("")

        lines.extend(
            [
                "## Section H: Evidence Limitations",
            ]
        )
        for lim in self.limitations:
            lines.append(f"- {lim}")
        lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Render pure JSON string."""
        return self.model_dump_json(indent=2)


class PrivacyResult(BaseModel):
    """Complete result of Phase 4 & Phase F Privacy & Tracker analysis."""

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

    def to_report(self) -> PrivacyReport:
        """Convert PrivacyResult into a structured PrivacyReport."""
        # Section A: Permissions
        uncertain = [
            u.permission
            for u in self.permissions.usage_details
            if u.usage_status == PermissionUsageStatus.DECLARED_ONLY
        ]
        perm_section = PermissionReportSection(
            declared_permissions=self.permissions.declared_permissions,
            categorized_permissions=self.permissions.categorized_permissions,
            usage_details=self.permissions.usage_details,
            uncertain_permissions=uncertain,
            high_risk_count=self.permissions.high_risk_permissions_count,
        )

        # Section B: Components
        boot_recs: list[str] = []
        acc_services: list[str] = []
        notif_listeners: list[str] = []
        for f in self.findings:
            if "BOOT" in f.id or "PERSISTENCE" in f.id:
                boot_recs.extend(f.evidence_values)
            if "ACCESSIBILITY" in f.id:
                acc_services.extend(f.evidence_values)
            if "NOTIFICATION" in f.id:
                notif_listeners.extend(f.evidence_values)

        comp_section = ComponentReportSection(
            background_capabilities=self.data_collection.background_data_capabilities,
            boot_receivers=sorted(set(boot_recs)),
            accessibility_services=sorted(set(acc_services)),
            notification_listeners=sorted(set(notif_listeners)),
            persistence_indicators=sorted(set(boot_recs)),
        )

        # Section C: SDKs
        sdk_section = SDKReportSection(
            detected_sdks=self.all_detected_sdks,
            trackers_count=self.trackers.total_trackers,
            advertising_count=self.advertising.total_advertising_sdks,
            analytics_count=self.analytics.total_analytics_sdks,
            telemetry_count=self.telemetry.total_telemetry_sdks,
        )

        # Section D: Endpoints
        endpoint_section = EndpointReportSection(
            total_endpoints=self.endpoints.total_endpoints,
            first_party_domains=self.endpoints.first_party_domains,
            third_party_domains=self.endpoints.third_party_domains,
            classified_endpoints=self.endpoints.classified_endpoints,
            by_category=self.endpoints.by_category,
        )

        # Section E: Sensitive APIs
        dynamic_loading: list[str] = []
        reflection: list[str] = []
        location_apis: list[str] = []
        contacts_apis: list[str] = []
        audio_apis: list[str] = []
        camera_apis: list[str] = []
        webview_apis: list[str] = []
        for f in self.findings:
            if "DYNAMIC-CODE" in f.id:
                dynamic_loading.extend(f.evidence_values)
            elif "REFLECTION" in f.id:
                reflection.extend(f.evidence_values)
            elif "LOCATION" in f.id:
                location_apis.extend(f.evidence_values)
            elif "CONTACTS" in f.id:
                contacts_apis.extend(f.evidence_values)
            elif "AUDIO" in f.id or "MICROPHONE" in f.id:
                audio_apis.extend(f.evidence_values)
            elif "CAMERA" in f.id:
                camera_apis.extend(f.evidence_values)
            elif "WEBVIEW" in f.id:
                webview_apis.extend(f.evidence_values)

        sensitive_section = SensitiveAPIReportSection(
            device_identifiers=self.data_collection.device_identifiers_detected,
            advertising_id_detected=self.data_collection.advertising_id_detected,
            clipboard_access=self.data_collection.clipboard_access_detected,
            accessibility_apis=sorted(set(acc_services)),
            notification_apis=sorted(set(notif_listeners)),
            dynamic_code_loading=sorted(set(dynamic_loading)),
            reflection_sensitive=sorted(set(reflection)),
            location_apis=sorted(set(location_apis)),
            contacts_apis=sorted(set(contacts_apis)),
            audio_capture_apis=sorted(set(audio_apis)),
            camera_apis=sorted(set(camera_apis)),
            webview_network_apis=sorted(set(webview_apis)),
        )

        # Section G: Unknown / Partial
        partial_findings = [
            f
            for f in self.findings
            if f.evidence_state in (EvidenceState.PARTIAL, EvidenceState.UNKNOWN)
            or f.analysis_completeness == AnalysisCompleteness.PARTIAL
        ]
        unknown_findings = [
            f
            for f in self.findings
            if f.evidence_state == EvidenceState.UNKNOWN
            or f.analysis_completeness == AnalysisCompleteness.UNKNOWN
        ]
        inconclusive = [f"Permission declared without API references: {p}" for p in uncertain]
        if self.endpoints.by_category.get("unknown"):
            inconclusive.append(
                f"{len(self.endpoints.by_category['unknown'])} endpoints "
                "cannot be reliably classified statically"
            )

        unknown_section = UnknownPartialReportSection(
            partial_findings=partial_findings,
            unknown_findings=unknown_findings,
            inconclusive_items=inconclusive,
        )

        return PrivacyReport(
            status=self.status,
            package_name=self.package_name,
            version_name=self.version_name,
            version_code=self.version_code,
            permissions=perm_section,
            components=comp_section,
            sdks=sdk_section,
            endpoints=endpoint_section,
            sensitive_apis=sensitive_section,
            correlated_findings=self.findings,
            unknown_partial=unknown_section,
            limitations=self.limitations,
        )
