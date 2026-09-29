"""APKForge Phase 5: Security Analysis Engine.

Performs evidence-based static security analysis, detecting malware indicators,
spyware indicators, security misconfigurations, vulnerabilities, and diff-aware regressions.
"""

from __future__ import annotations

from apkforge.security.diff_analyzer import DiffSecurityAnalyzer
from apkforge.security.engine import SecurityEngine
from apkforge.security.malware import MalwareAnalyzer
from apkforge.security.models import (
    FullAnalysisResult,
    SecurityCategory,
    SecurityFinding,
    SecurityResult,
    SecurityStatus,
    SecuritySummary,
)
from apkforge.security.rules import (
    SecurityCondition,
    SecurityEvidenceIndex,
    SecurityRule,
    SecurityRuleEngine,
)
from apkforge.security.spyware import SpywareAnalyzer
from apkforge.security.vulnerabilities import VulnerabilityAnalyzer

__all__ = [
    "DiffSecurityAnalyzer",
    "FullAnalysisResult",
    "MalwareAnalyzer",
    "SecurityCategory",
    "SecurityCondition",
    "SecurityEngine",
    "SecurityEvidenceIndex",
    "SecurityFinding",
    "SecurityResult",
    "SecurityRule",
    "SecurityRuleEngine",
    "SecurityStatus",
    "SecuritySummary",
    "SpywareAnalyzer",
    "VulnerabilityAnalyzer",
]
