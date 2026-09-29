"""APKForge core data models.

All inter-module communication uses these Pydantic models.  Future analysis,
modification, and reporting engines must accept and return instances of these
models (or subclasses) so that the pipeline remains composable.

Model families
--------------
:class:`APKInput`
    Represents an APK file supplied by the user.

:class:`Finding`, :class:`Evidence`, :class:`Severity`, :class:`Confidence`
    Structured representation of a security/privacy finding.  A finding must
    never be a boolean ``malware=True`` flag.

:class:`AnalysisResult`
    Outcome of a single analysis module execution.

:class:`DiffResult`
    Differences between two APKs.

:class:`ModificationPlan`, :class:`ModificationStep`
    A validated, reversible description of changes to apply to an APK.

:class:`VerificationResult`
    Post-build verification outcome.

:class:`Report`
    Top-level report aggregating all results.

Security invariant
------------------
The :class:`AnalysisStatus` enum has three values::

    COMPLETE  — all analysers ran and produced results.
    PARTIAL   — at least one analyser ran but some did not complete.
    FAILED    — the analysis could not run at all.

A result must never be interpreted as "clean" if its status is PARTIAL or
FAILED.  Callers must propagate the status to the report.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

__all__ = [
    "APKInput",
    "APKMetadata",
    "AnalysisResult",
    "AnalysisStatus",
    "Confidence",
    "DiffChangeType",
    "DiffEntry",
    "DiffResult",
    "Evidence",
    "Finding",
    "ModificationPlan",
    "ModificationStep",
    "ModificationStepStatus",
    "Report",
    "Severity",
    "VerificationResult",
]


# ===========================================================================
# Enums
# ===========================================================================


class AnalysisStatus(StrEnum):
    """Outcome of an analysis operation.

    Security contract: PARTIAL and FAILED must never be treated as "clean".
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class Severity(StrEnum):
    """Severity of a security or privacy finding.

    Mirrors the CVSS qualitative severity scale for familiarity.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    """Confidence level of a finding.

    Static analysis is inherently probabilistic.  Every finding should carry
    an explicit confidence so that consumers can threshold appropriately.
    """

    CONFIRMED = "confirmed"  # Strong evidence, low false-positive probability
    HIGH = "high"  # Multiple independent indicators
    MEDIUM = "medium"  # Single indicator, no contradicting evidence
    LOW = "low"  # Heuristic / pattern match only
    SPECULATIVE = "speculative"  # Theoretical; requires dynamic confirmation


class DiffChangeType(StrEnum):
    """Type of change between two APK versions."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    UNCHANGED = "unchanged"


class ModificationStepStatus(StrEnum):
    """Execution status of a single modification step."""

    PENDING = "pending"
    APPLIED = "applied"
    SKIPPED = "skipped"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ===========================================================================
# Input models
# ===========================================================================


class APKInput(BaseModel):
    """Represents an APK file supplied by the user.

    Attributes:
        path: Absolute or relative path to the APK file.  Must exist and be a
            regular file at the time of creation.
        sha256: Optional pre-computed SHA-256 hex digest.  If not supplied, it
            will be computed on first access.
        label: Optional human-readable label for this APK (e.g. "original",
            "patched").

    Security note:
        The file referenced by *path* is treated as **untrusted**.  Its
        contents must never be executed, and its ZIP entries must be extracted
        only within a controlled workspace with enforced size limits.
    """

    path: Path
    sha256: str | None = Field(
        default=None,
        description="SHA-256 hex digest of the APK file.",
    )
    label: str | None = Field(
        default=None,
        max_length=128,
        description="Human-readable label for this APK.",
    )

    model_config = {"frozen": True}

    @field_validator("path", mode="before")
    @classmethod
    def resolve_path(cls, v: object) -> Path:
        """Resolve the path to an absolute path."""
        if isinstance(v, str):
            return Path(v).resolve()
        if isinstance(v, Path):
            return v.resolve()
        msg = f"Expected str or Path, got {type(v)}"
        raise TypeError(msg)

    @field_validator("sha256", mode="before")
    @classmethod
    def normalise_sha256(cls, v: object) -> str | None:
        """Normalise and validate SHA-256 hex digest."""
        if v is None:
            return None
        if not isinstance(v, str):
            msg = "sha256 must be a string"
            raise TypeError(msg)
        normalised = v.strip().lower()
        if len(normalised) != 64:
            msg = f"SHA-256 digest must be 64 hex characters, got {len(normalised)}"
            raise ValueError(msg)
        if not all(c in "0123456789abcdef" for c in normalised):
            msg = "SHA-256 digest contains non-hex characters"
            raise ValueError(msg)
        return normalised

    def compute_sha256(self) -> str:
        """Compute the SHA-256 digest of the APK file.

        Returns:
            str: Lowercase hex digest.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        h = hashlib.sha256()
        chunk_size = 64 * 1024
        with self.path.open("rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()


# ===========================================================================
# Finding models
# ===========================================================================


class Evidence(BaseModel):
    """A piece of evidence supporting a finding.

    Attributes:
        description: Human-readable description of the evidence.
        location: Location within the APK (e.g. file path, byte offset,
            class/method name).
        snippet: A short, safe, displayable excerpt from the evidence.
            Must not contain full binary payloads.
        references: Optional list of external references (CVE IDs, CWE IDs,
            research papers, etc.).
    """

    description: str = Field(description="What was observed.")
    location: str | None = Field(
        default=None,
        description="Where it was observed (file, class, method, offset).",
    )
    snippet: str | None = Field(
        default=None,
        max_length=4096,
        description="Short display-safe excerpt. No raw binary data.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="CVE IDs, CWE IDs, URLs, or other references.",
    )


class Finding(BaseModel):
    """A security or privacy finding with structured evidence.

    Design rationale
    ----------------
    A finding must never be reduced to a boolean flag.  Instead it carries:

    - **severity** — How serious the finding is *if confirmed*.
    - **confidence** — How certain we are that this is a real finding.
    - **evidence** — The raw observations supporting the finding.
    - **assessment** — A human-readable interpretation of the evidence.
    - **limitations** — What this analysis *cannot* determine (important for
      legal / compliance use cases).

    Attributes:
        finding_id: Stable, machine-readable identifier for this finding type.
        title: Short human-readable title.
        description: Detailed description of the finding.
        severity: Severity classification.
        confidence: Confidence level of the finding.
        evidence: Supporting evidence items.
        assessment: Analyst-style narrative summary.
        limitations: Description of what this analysis could not determine.
        tags: Free-form tags for filtering (e.g. ``["network", "permission"]``).
    """

    finding_id: str = Field(
        description="Stable machine-readable finding identifier.",
        pattern=r"^[A-Z][A-Z0-9_-]{2,63}$",
    )
    title: str = Field(description="Short human-readable title.")
    description: str = Field(description="Detailed description of the finding.")
    severity: Severity
    confidence: Confidence
    evidence: list[Evidence] = Field(default_factory=list)
    assessment: str = Field(
        default="",
        description="Analyst-style narrative combining evidence into a conclusion.",
    )
    limitations: str = Field(
        default="",
        description="What this static analysis cannot determine.",
    )
    tags: list[str] = Field(default_factory=list)


# ===========================================================================
# Analysis result models
# ===========================================================================


class AnalysisResult(BaseModel):
    """Result of a single analysis module execution.

    Attributes:
        module_name: Identifier of the analysis module that produced this result.
        status: COMPLETE, PARTIAL, or FAILED.  Never map PARTIAL/FAILED to "clean".
        findings: Findings produced by the module.
        errors: Error messages if the analysis failed or was partial.
        warnings: Non-fatal warnings encountered during analysis.
        duration_seconds: Wall-clock time taken by the analysis.
        metadata: Arbitrary module-specific metadata (e.g. tool versions).
    """

    module_name: str = Field(description="Name of the analysis module.")
    status: AnalysisStatus
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    duration_seconds: float | None = Field(
        default=None,
        ge=0,
        description="Wall-clock duration of the analysis.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific metadata.",
    )

    @model_validator(mode="after")
    def failed_status_requires_errors(self) -> AnalysisResult:
        """Encourage callers to record *why* an analysis failed."""
        if self.status == AnalysisStatus.FAILED and not self.errors:
            self.errors = ["Analysis failed; no error details were recorded."]
        return self


# ===========================================================================
# Diff models
# ===========================================================================


class DiffEntry(BaseModel):
    """A single difference between two APK versions.

    Attributes:
        path: Path of the artefact within the APK (e.g. ``classes.dex``).
        change_type: The type of change.
        old_hash: SHA-256 of the entry in the original APK.
        new_hash: SHA-256 of the entry in the modified APK.
        description: Human-readable description of the difference.
    """

    path: str
    change_type: DiffChangeType
    old_hash: str | None = None
    new_hash: str | None = None
    description: str = ""


class DiffResult(BaseModel):
    """Result of a comparison between two APKs.

    Attributes:
        original: The original APK input.
        modified: The modified APK input.
        status: Overall status of the diff operation.
        entries: Individual differences.
        errors: Errors encountered during diffing.
        summary: High-level summary of the differences.
    """

    original: APKInput
    modified: APKInput
    status: AnalysisStatus
    entries: list[DiffEntry] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    summary: str = ""


# ===========================================================================
# Modification models
# ===========================================================================


class ModificationStep(BaseModel):
    """A single, reversible step in a modification plan.

    Attributes:
        step_id: Stable identifier for this step type.
        description: Human-readable description of the change.
        target_path: APK-relative path of the resource being modified.
        parameters: Step-specific parameters.
        status: Current execution status.
    """

    step_id: str
    description: str
    target_path: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: ModificationStepStatus = ModificationStepStatus.PENDING


class ModificationPlan(BaseModel):
    """A complete, validated plan for modifying an APK.

    A plan is validated before any modification is applied.  The original APK
    is never modified in-place; all changes happen in an isolated workspace.

    Attributes:
        plan_id: Unique identifier for this plan instance.
        source_apk: The immutable source APK.
        steps: Ordered list of modification steps.
        created_at: Timestamp when the plan was created.
        notes: Human-readable notes about this plan.
    """

    plan_id: str
    source_apk: APKInput
    steps: list[ModificationStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    notes: str = ""

    @property
    def is_empty(self) -> bool:
        """Return True if the plan has no steps."""
        return len(self.steps) == 0


# ===========================================================================
# Verification models
# ===========================================================================


class VerificationResult(BaseModel):
    """Result of post-build APK verification.

    Attributes:
        status: COMPLETE, PARTIAL, or FAILED.
        checks_passed: Names of verification checks that passed.
        checks_failed: Names of verification checks that failed.
        errors: Errors encountered during verification.
        signed: Whether the APK passed signature verification.
    """

    status: AnalysisStatus
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    signed: bool | None = Field(
        default=None,
        description="Signature status (None = not checked).",
    )


# ===========================================================================
# APK metadata
# ===========================================================================


class APKMetadata(BaseModel):
    """Basic APK metadata extracted during inspection.

    This is a stub for Phase 0.  Later phases will populate all fields via
    manifest parsing.

    Attributes:
        package_name: Android package name (e.g. ``com.example.app``).
        version_name: Human-readable version string.
        version_code: Integer version code.
        min_sdk: Minimum Android SDK version.
        target_sdk: Target Android SDK version.
        sha256: SHA-256 of the APK file.
    """

    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    sha256: str | None = None


# ===========================================================================
# Report
# ===========================================================================


class Report(BaseModel):
    """Top-level report aggregating all APKForge analysis results.

    This model is the contract between the analysis engine and the reporting
    layer.  All reporters (text, JSON, HTML) must accept a :class:`Report`.

    Attributes:
        report_id: Unique identifier for this report.
        generated_at: Timestamp when the report was generated.
        apk: The APK that was analysed.
        metadata: Basic APK metadata (may be partial).
        overall_status: Worst-case status across all analysis results.
        analysis_results: Results from individual analysis modules.
        diff_results: Results from diff operations (if any).
        verification: Verification result (if built/rebuilt).
        limitations: Global analysis limitations that apply to this report.
        notes: Analyst notes.
    """

    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    apk: APKInput
    metadata: APKMetadata = Field(default_factory=APKMetadata)
    overall_status: AnalysisStatus = AnalysisStatus.FAILED
    analysis_results: list[AnalysisResult] = Field(default_factory=list)
    diff_results: list[DiffResult] = Field(default_factory=list)
    verification: VerificationResult | None = None
    limitations: list[str] = Field(default_factory=list)
    notes: str = ""

    @model_validator(mode="after")
    def compute_overall_status(self) -> Report:
        """Derive the overall status from individual analysis results.

        The overall status degrades monotonically:
        COMPLETE → PARTIAL (if any result is PARTIAL)
        COMPLETE → FAILED (if any result is FAILED)
        """
        if not self.analysis_results:
            return self
        statuses = {r.status for r in self.analysis_results}
        if AnalysisStatus.FAILED in statuses:
            self.overall_status = AnalysisStatus.FAILED
        elif AnalysisStatus.PARTIAL in statuses:
            self.overall_status = AnalysisStatus.PARTIAL
        else:
            self.overall_status = AnalysisStatus.COMPLETE
        return self

    @property
    def all_findings(self) -> list[Finding]:
        """Return all findings across all analysis results, sorted by severity."""
        _order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        findings = [f for r in self.analysis_results for f in r.findings]
        return sorted(findings, key=lambda f: _order.get(f.severity, 99))
