"""Data models for Phase 5: Security Analysis Engine.

All models are strictly evidence-based, deterministic, and serializable to JSON.
Findings distinguish evidence, severity, confidence, assessment, and limitations.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus, Confidence, Evidence, Severity

__all__ = [
    "AnalysisStatus",
    "Confidence",
    "Evidence",
    "FullAnalysisResult",
    "SecurityCategory",
    "SecurityFinding",
    "SecurityResult",
    "SecurityStatus",
    "SecuritySummary",
    "Severity",
]


class SecurityCategory(StrEnum):
    """Classification categories for security-relevant findings."""

    MALWARE_INDICATOR = "malware_indicator"
    SPYWARE_INDICATOR = "spyware_indicator"
    VULNERABILITY = "vulnerability"
    SURVEILLANCE = "surveillance"
    PERSISTENCE = "persistence"
    CODE_EXECUTION = "code_execution"
    DYNAMIC_CODE = "dynamic_code"
    PAYLOAD = "payload"
    NETWORK = "network"
    CRYPTO = "crypto"
    CONFIGURATION = "configuration"
    EXPORTED_COMPONENT = "exported_component"
    CREDENTIAL_ACCESS = "credential_access"
    DIFF_MODIFICATION = "diff_modification"
    OTHER = "other"


class SecurityStatus(StrEnum):
    """Top-level neutral security status.

    Security contract: Never emit absolute 'safe', 'clean', or 'malware' verdicts.
    Status describes whether static findings exist and whether analysis completed.
    """

    FINDINGS_PRESENT = "findings_present"
    NO_SIGNIFICANT_STATIC_FINDINGS = "no_significant_static_findings"
    ANALYSIS_INCOMPLETE = "analysis_incomplete"


class SecurityFinding(BaseModel):
    """An evidence-oriented security finding.

    In accordance with APKForge security design:
    - Never makes unsupported claims (e.g. 'this app is malware')
    - Clearly documents observations, severity, confidence, assessment, and limitations
    """

    id: str = Field(description="Unique finding identifier (e.g. SEC-MAL-PAYLOAD-001).")
    category: str = Field(description="Category of the finding.")
    title: str = Field(description="Concise human-readable title.")
    description: str = Field(description="Detailed technical description of the observation.")
    severity: Severity = Field(
        description="Potential security impact of the finding (INFO to CRITICAL)."
    )
    confidence: Confidence = Field(
        description="Confidence that the observed evidence supports the finding."
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Structured, traceable evidence items supporting the finding.",
    )
    assessment: str = Field(
        default="",
        description="Technical assessment explaining the security significance of the evidence.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit analysis boundaries (e.g. static analysis does not verify runtime execution)."
        ),
    )
    references: list[str] = Field(
        default_factory=list,
        description="External standards, CWE, CVE, or technical documentation references.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Filtering and search tags.",
    )


class SecuritySummary(BaseModel):
    """Quantitative aggregation of security findings."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    malware_indicator_count: int = 0
    spyware_indicator_count: int = 0
    vulnerability_count: int = 0
    diff_security_change_count: int = 0

    overall_security_status: SecurityStatus = SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS


class SecurityResult(BaseModel):
    """Complete structured result produced by the Security Analysis Engine."""

    status: AnalysisStatus = AnalysisStatus.COMPLETE
    security_status: SecurityStatus = SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS

    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None

    summary: SecuritySummary = Field(default_factory=SecuritySummary)

    findings: list[SecurityFinding] = Field(default_factory=list)
    malware_indicators: list[SecurityFinding] = Field(default_factory=list)
    spyware_indicators: list[SecurityFinding] = Field(default_factory=list)
    vulnerability_indicators: list[SecurityFinding] = Field(default_factory=list)
    diff_findings: list[SecurityFinding] = Field(default_factory=list)

    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class FullAnalysisResult(BaseModel):
    """Unified result model orchestrating Inspection, Privacy, and Security engines."""

    status: AnalysisStatus = AnalysisStatus.COMPLETE
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None

    inspection_status: AnalysisStatus = AnalysisStatus.COMPLETE
    privacy_status: AnalysisStatus = AnalysisStatus.COMPLETE
    security_status: SecurityStatus = SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS

    inspection_summary: dict[str, Any] = Field(default_factory=dict)
    privacy_summary: dict[str, Any] = Field(default_factory=dict)
    security_summary: SecuritySummary = Field(default_factory=SecuritySummary)

    security_findings: list[SecurityFinding] = Field(default_factory=list)

    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
