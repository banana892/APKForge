"""Analytics and behavioral tracking SDK detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.privacy.models import AnalyticsResult, DetectedSDK, SDKCategory

if TYPE_CHECKING:
    from apkforge.privacy.rules import EvidenceIndex, RuleEngine


class AnalyticsDetector:
    """Detects analytics platforms, event loggers, and customer data platforms."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine

    def detect(self, index: EvidenceIndex) -> AnalyticsResult:
        """Scan index against analytics rules."""
        detected: list[DetectedSDK] = []

        for rule in self._engine.rules:
            if rule.category != SDKCategory.ANALYTICS:
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

        sorted_analytics = sorted(detected, key=lambda s: s.id)
        return AnalyticsResult(
            detected_analytics_sdks=sorted_analytics,
            total_analytics_sdks=len(sorted_analytics),
        )
