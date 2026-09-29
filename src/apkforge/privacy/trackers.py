"""Tracker and attribution technology detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.privacy.models import DetectedSDK, SDKCategory, TrackerResult

if TYPE_CHECKING:
    from apkforge.privacy.rules import EvidenceIndex, RuleEngine


class TrackerDetector:
    """Detects tracking, user profiling, and attribution technologies."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine

    def detect(self, index: EvidenceIndex) -> TrackerResult:
        """Scan index against tracker and attribution rules."""
        detected: list[DetectedSDK] = []

        for rule in self._engine.rules:
            if rule.category not in (SDKCategory.TRACKING, SDKCategory.ATTRIBUTION):
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

        sorted_trackers = sorted(detected, key=lambda s: s.id)
        return TrackerResult(
            detected_trackers=sorted_trackers,
            total_trackers=len(sorted_trackers),
        )
