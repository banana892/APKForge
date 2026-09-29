"""Advertising SDK and ad network detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.privacy.models import AdvertisingResult, DetectedSDK, SDKCategory

if TYPE_CHECKING:
    from apkforge.privacy.rules import EvidenceIndex, RuleEngine


class AdvertisingDetector:
    """Detects mobile advertising networks, mediation platforms, and ad SDKs."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine

    def detect(self, index: EvidenceIndex) -> AdvertisingResult:
        """Scan index against advertising rules."""
        detected: list[DetectedSDK] = []

        for rule in self._engine.rules:
            if rule.category != SDKCategory.ADVERTISING:
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

        sorted_ads = sorted(detected, key=lambda s: s.id)
        return AdvertisingResult(
            detected_advertising_sdks=sorted_ads,
            total_advertising_sdks=len(sorted_ads),
        )
