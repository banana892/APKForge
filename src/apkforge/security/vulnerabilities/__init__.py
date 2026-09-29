"""Vulnerability analysis modules: manifest misconfigurations, component exposure, and crypto."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.security.vulnerabilities.components import ComponentVulnerabilityAnalyzer
from apkforge.security.vulnerabilities.crypto import CryptoVulnerabilityAnalyzer
from apkforge.security.vulnerabilities.manifest import ManifestVulnerabilityAnalyzer

if TYPE_CHECKING:
    from apkforge.security.models import SecurityFinding
    from apkforge.security.rules import SecurityEvidenceIndex

__all__ = [
    "ComponentVulnerabilityAnalyzer",
    "CryptoVulnerabilityAnalyzer",
    "ManifestVulnerabilityAnalyzer",
    "VulnerabilityAnalyzer",
]


class VulnerabilityAnalyzer:
    """Coordinator running specialized vulnerability and misconfiguration analyzers."""

    def __init__(self) -> None:
        self._manifest_analyzer = ManifestVulnerabilityAnalyzer()
        self._component_analyzer = ComponentVulnerabilityAnalyzer()
        self._crypto_analyzer = CryptoVulnerabilityAnalyzer()

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Run all vulnerability analyzers."""
        findings: list[SecurityFinding] = []
        findings.extend(self._manifest_analyzer.analyze(index))
        findings.extend(self._component_analyzer.analyze(index))
        findings.extend(self._crypto_analyzer.analyze(index))
        return sorted(findings, key=lambda f: f.id)
