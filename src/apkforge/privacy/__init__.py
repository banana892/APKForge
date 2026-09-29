"""APKForge Phase 4: Privacy & Tracker Engine.

Analyzes static technical evidence from Phase 1 intake and Phase 2 inspection
to detect declared data-related capabilities, third-party advertising, analytics,
tracking, telemetry SDKs, and network endpoints with provenance.
"""

from __future__ import annotations

from apkforge.privacy.advertising import AdvertisingDetector
from apkforge.privacy.analytics import AnalyticsDetector
from apkforge.privacy.data_collection import DataCollectionAnalyzer
from apkforge.privacy.endpoints import EndpointAnalyzer
from apkforge.privacy.engine import PrivacyEngine
from apkforge.privacy.models import (
    AdvertisingResult,
    AnalyticsResult,
    ClassifiedEndpoint,
    DataCapabilityAssessment,
    DataCapabilityType,
    DataCollectionResult,
    DetectedSDK,
    EndpointCategory,
    EndpointResult,
    PermissionCategory,
    PermissionPrivacyResult,
    PermissionRelevance,
    PermissionUsage,
    PermissionUsageStatus,
    PrivacyFinding,
    PrivacyResult,
    SDKCategory,
    TelemetryResult,
    TrackerResult,
)
from apkforge.privacy.permissions import PermissionAnalyzer
from apkforge.privacy.rules import EvidenceIndex, PrivacyRule, RuleEngine
from apkforge.privacy.telemetry import TelemetryDetector
from apkforge.privacy.trackers import TrackerDetector

__all__ = [
    "AdvertisingDetector",
    "AdvertisingResult",
    "AnalyticsDetector",
    "AnalyticsResult",
    "ClassifiedEndpoint",
    "DataCapabilityAssessment",
    "DataCapabilityType",
    "DataCollectionAnalyzer",
    "DataCollectionResult",
    "DetectedSDK",
    "EndpointAnalyzer",
    "EndpointCategory",
    "EndpointResult",
    "EvidenceIndex",
    "PermissionAnalyzer",
    "PermissionCategory",
    "PermissionPrivacyResult",
    "PermissionRelevance",
    "PermissionUsage",
    "PermissionUsageStatus",
    "PrivacyEngine",
    "PrivacyFinding",
    "PrivacyResult",
    "PrivacyRule",
    "RuleEngine",
    "SDKCategory",
    "TelemetryDetector",
    "TelemetryResult",
    "TrackerDetector",
    "TrackerResult",
]
