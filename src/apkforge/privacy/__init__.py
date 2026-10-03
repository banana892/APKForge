"""APKForge Phase F: Privacy, Tracker & Ads Intelligence Layer.

Analyzes static technical evidence from intake and inspection
to detect declared data-related capabilities, third-party advertising, analytics,
tracking, telemetry SDKs, and network endpoints with provenance.
"""

from __future__ import annotations

from apkforge.privacy.advertising import AdvertisingDetector
from apkforge.privacy.analytics import AnalyticsDetector
from apkforge.privacy.behavior import BehaviorAnalyzer, StaticBehaviorRule
from apkforge.privacy.cross_check import PhaseBComparisonResult, compare_privacy_with_security
from apkforge.privacy.data_collection import DataCollectionAnalyzer
from apkforge.privacy.endpoints import EndpointAnalyzer
from apkforge.privacy.engine import PrivacyEngine
from apkforge.privacy.models import (
    AdvertisingResult,
    AnalysisCompleteness,
    AnalyticsResult,
    ClassifiedEndpoint,
    ComponentReportSection,
    DataCapabilityAssessment,
    DataCapabilityType,
    DataCollectionResult,
    DetectedSDK,
    EndpointCategory,
    EndpointReportSection,
    EndpointResult,
    EvidenceState,
    PermissionCategory,
    PermissionPrivacyResult,
    PermissionRelevance,
    PermissionReportSection,
    PermissionUsage,
    PermissionUsageStatus,
    PrivacyFinding,
    PrivacyReport,
    PrivacyResult,
    SDKCategory,
    SDKReportSection,
    SensitiveAPIReportSection,
    TelemetryResult,
    TrackerResult,
    UnknownPartialReportSection,
)
from apkforge.privacy.permissions import PermissionAnalyzer
from apkforge.privacy.rules import EvidenceIndex, PrivacyRule, RuleEngine
from apkforge.privacy.service import PrivacyAnalysisService
from apkforge.privacy.telemetry import TelemetryDetector
from apkforge.privacy.trackers import TrackerDetector

__all__ = [
    "AdvertisingDetector",
    "AdvertisingResult",
    "AnalysisCompleteness",
    "AnalyticsDetector",
    "AnalyticsResult",
    "BehaviorAnalyzer",
    "ClassifiedEndpoint",
    "ComponentReportSection",
    "DataCapabilityAssessment",
    "DataCapabilityType",
    "DataCollectionAnalyzer",
    "DataCollectionResult",
    "DetectedSDK",
    "EndpointAnalyzer",
    "EndpointCategory",
    "EndpointReportSection",
    "EndpointResult",
    "EvidenceIndex",
    "EvidenceState",
    "PermissionAnalyzer",
    "PermissionCategory",
    "PermissionPrivacyResult",
    "PermissionRelevance",
    "PermissionReportSection",
    "PermissionUsage",
    "PermissionUsageStatus",
    "PhaseBComparisonResult",
    "PrivacyAnalysisService",
    "PrivacyEngine",
    "PrivacyFinding",
    "PrivacyReport",
    "PrivacyResult",
    "PrivacyRule",
    "RuleEngine",
    "SDKCategory",
    "SDKReportSection",
    "SensitiveAPIReportSection",
    "StaticBehaviorRule",
    "TelemetryDetector",
    "TelemetryResult",
    "TrackerDetector",
    "TrackerResult",
    "UnknownPartialReportSection",
    "compare_privacy_with_security",
]
