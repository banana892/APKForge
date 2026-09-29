"""Telemetry, diagnostics, and crash reporting framework detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.privacy.models import DetectedSDK, SDKCategory, TelemetryResult

if TYPE_CHECKING:
    from apkforge.privacy.rules import EvidenceIndex, RuleEngine


class TelemetryDetector:
    """Detects crash reporters, diagnostics loggers, and application telemetry frameworks."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine

    def detect(self, index: EvidenceIndex) -> TelemetryResult:
        """Scan index against telemetry and crash reporting rules."""
        detected: list[DetectedSDK] = []

        for rule in self._engine.rules:
            if rule.category not in (SDKCategory.TELEMETRY, SDKCategory.CRASH_REPORTING):
                continue

            matched, confidence, evidence_items, matches_dict = self._engine.match_rule(rule, index)
            if matched:
                sdk = DetectedSDK(
                    id=rule.id,
                    name=rule.name,
                    vendor=rule.vendor,
                    category=rule.category,
                    version=None,
                    confidence=confidence,
                    description=rule.description,
                    matched_packages=matches_dict["packages"],
                    matched_classes=matches_dict["classes"],
                    matched_strings=matches_dict["strings"],
                    matched_endpoints=matches_dict["endpoints"],
                    evidence=evidence_items,
                )
                detected.append(sdk)

        sorted_telemetry = sorted(detected, key=lambda s: s.id)
        return TelemetryResult(
            detected_telemetry_sdks=sorted_telemetry,
            total_telemetry_sdks=len(sorted_telemetry),
        )
