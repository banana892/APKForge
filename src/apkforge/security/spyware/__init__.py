"""Spyware and surveillance analysis modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.security.spyware.collection import CollectionAnalyzer
from apkforge.security.spyware.surveillance import SurveillanceAnalyzer

if TYPE_CHECKING:
    from apkforge.security.models import SecurityFinding
    from apkforge.security.rules import SecurityEvidenceIndex

__all__ = [
    "CollectionAnalyzer",
    "SpywareAnalyzer",
    "SurveillanceAnalyzer",
]


class SpywareAnalyzer:
    """Coordinator running specialized surveillance and data harvesting analyzers."""

    def __init__(self) -> None:
        self._surveillance_analyzer = SurveillanceAnalyzer()
        self._collection_analyzer = CollectionAnalyzer()

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Run all spyware and data collection analyzers."""
        findings: list[SecurityFinding] = []
        findings.extend(self._surveillance_analyzer.analyze(index))
        findings.extend(self._collection_analyzer.analyze(index))
        return sorted(findings, key=lambda f: f.id)
