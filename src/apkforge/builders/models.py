"""Result and option models for BuildService.

Toolchain configuration lives in :mod:`apkforge.builders.toolchain` and signing
configuration in :mod:`apkforge.builders.signing`; this module holds the data
that flows *out* of a build.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "DEFAULT_STAGE_TIMEOUT_SECONDS",
    "BuildFailureCategory",
    "BuildOptions",
    "BuildResult",
    "BuildStage",
    "BuildVerificationResult",
    "CertificateInfo",
    "SigningMode",
    "StageResult",
    "StageStatus",
]

DEFAULT_STAGE_TIMEOUT_SECONDS = 900


class BuildStage(StrEnum):
    """Pipeline stages, in execution order."""

    PREPARE = "prepare"
    DECODE = "decode"
    BUILD = "build"
    ALIGN = "align"
    SIGN = "sign"
    VERIFY = "verify"


class StageStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - a status, not a password
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class BuildFailureCategory(StrEnum):
    """Structured failure categories.

    Stage-generic categories (``DECODE_FAILURE``, ``BUILD_FAILURE``, ...) are used
    when the tool output matched no specific pattern; in that case
    ``StageResult.classified`` is ``False`` so unknown errors stay identifiable.

    ``TOOL_UNAVAILABLE`` means a required tool is not configured or not present;
    ``TOOLCHAIN_FAILURE`` means it is present but broken, unsupported or not
    executable. ``OUTPUT_MISSING`` means a tool reported success but its expected
    output does not exist (or is empty). ``UNEXPECTED_FAILURE`` is an internal
    exception, reported with its type and message instead of being raised.
    """

    SUCCESS = "SUCCESS"
    INPUT_FAILURE = "INPUT_FAILURE"
    CONFIGURATION_FAILURE = "CONFIGURATION_FAILURE"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    TOOLCHAIN_FAILURE = "TOOLCHAIN_FAILURE"
    WORKSPACE_FAILURE = "WORKSPACE_FAILURE"
    FRAMEWORK_FAILURE = "FRAMEWORK_FAILURE"
    DECODE_FAILURE = "DECODE_FAILURE"
    RESOURCE_FAILURE = "RESOURCE_FAILURE"
    BUILD_FAILURE = "BUILD_FAILURE"
    ALIGNMENT_FAILURE = "ALIGNMENT_FAILURE"
    SIGNING_FAILURE = "SIGNING_FAILURE"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    OUTPUT_MISSING = "OUTPUT_MISSING"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    UNEXPECTED_FAILURE = "UNEXPECTED_FAILURE"


class SigningMode(StrEnum):
    """How an APK produced by BuildService is signed."""

    UNSIGNED = "unsigned"
    DEVELOPMENT = "development"  # the APKForge development/test key
    USER_PROVIDED = "user_provided"  # an explicitly configured keystore


@dataclass
class StageResult:
    """What happened in one pipeline stage."""

    stage: BuildStage
    status: StageStatus = StageStatus.SKIPPED
    duration_seconds: float = 0.0
    commands: list[list[str]] = field(default_factory=list)  # secret-masked argv
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    start_time: str = ""
    end_time: str = ""
    log_file: Path | None = None
    failure_category: BuildFailureCategory | None = None
    failure_cause: str = ""
    evidence: str | None = None  # the tool-output line that justified the category
    classified: bool = True
    notes: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)  # "[STAGE] ..." progress lines
    output_path: Path | None = None  # the artifact this stage produced (on PASS)
    failed_command: list[str] | None = None  # secret-masked argv of the failing command
    certificate_sha256: str | None = None  # sign: digest of the configured certificate
    verification: BuildVerificationResult | None = None  # verify only

    @property
    def passed(self) -> bool:
        return self.status == StageStatus.PASS

    def to_dict(self, *, tail: int = 2000) -> dict[str, Any]:
        return {
            "stage": str(self.stage),
            "status": str(self.status),
            "duration_seconds": round(self.duration_seconds, 3),
            "commands": self.commands,
            "exit_code": self.exit_code,
            "stdout_tail": self.stdout[-tail:],
            "stderr_tail": self.stderr[-tail:],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "log_file": str(self.log_file) if self.log_file else None,
            "failure_category": str(self.failure_category) if self.failure_category else None,
            "failure_cause": self.failure_cause,
            "evidence": self.evidence,
            "classified": self.classified,
            "notes": self.notes,
            "events": self.events,
            "output_path": str(self.output_path) if self.output_path else None,
            "failed_command": self.failed_command,
            "certificate_sha256": self.certificate_sha256,
            "verification": self.verification.to_dict() if self.verification else None,
        }


@dataclass
class CertificateInfo:
    """Signer details parsed from ``apksigner verify --print-certs``."""

    subject_dn: str | None = None
    sha256_digest: str | None = None
    signer_count: int | None = None
    v1_scheme: bool = False
    v2_scheme: bool = False
    v3_scheme: bool = False
    v31_scheme: bool = False
    v4_scheme: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BuildVerificationResult:
    """Independent checks on the final signed APK.

    ``expected_signer_matched`` is ``None`` when no expected certificate was
    given (standalone :meth:`BuildService.verify`); the pipeline always gives one.
    """

    valid: bool = False
    zipalign_verified: bool = False
    signature_verified: bool = False
    expected_signer_matched: bool | None = None
    zip_integrity_verified: bool = False
    manifest_present: bool = False
    certificate: CertificateInfo | None = None
    expected_certificate_sha256: str | None = None
    apksigner_warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    apksigner_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["certificate"] = self.certificate.to_dict() if self.certificate else None
        return d


@dataclass
class BuildOptions:
    """Per-build options. Everything not set here comes from the service."""

    output_apk: Path | None = None
    overwrite_output: bool = False
    work_dir: Path | None = None
    keep_workspace_on_success: bool = False
    keep_workspace_on_failure: bool = True
    stage_timeout_seconds: int = DEFAULT_STAGE_TIMEOUT_SECONDS


@dataclass
class BuildResult:
    """Structured outcome of :meth:`BuildService.build_pipeline`."""

    success: bool
    build_id: str
    input_apk: Path
    input_sha256: str | None = None
    input_unchanged: bool | None = None
    output_apk: Path | None = None
    stages: list[StageResult] = field(default_factory=list)
    failure_stage: BuildStage | None = None
    failure_category: BuildFailureCategory = BuildFailureCategory.SUCCESS
    failure_cause: str = ""
    failure_evidence: str | None = None
    failure_command: list[str] | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    signing_mode: SigningMode = SigningMode.UNSIGNED
    certificate: CertificateInfo | None = None
    verification: BuildVerificationResult | None = None
    workspace: Path | None = None
    log_file: Path | None = None
    duration_seconds: float = 0.0
    toolchain: dict[str, Any] = field(default_factory=dict)

    def stage(self, stage: BuildStage) -> StageResult | None:
        return next((s for s in self.stages if s.stage == stage), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "build_id": self.build_id,
            "input_apk": str(self.input_apk),
            "input_sha256": self.input_sha256,
            "input_unchanged": self.input_unchanged,
            "output_apk": str(self.output_apk) if self.output_apk else None,
            "stages": [s.to_dict() for s in self.stages],
            "failure_stage": str(self.failure_stage) if self.failure_stage else None,
            "failure_category": str(self.failure_category),
            "failure_cause": self.failure_cause,
            "failure_evidence": self.failure_evidence,
            "failure_command": self.failure_command,
            "warnings": self.warnings,
            "errors": self.errors,
            "logs": self.logs,
            "signing_mode": str(self.signing_mode),
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "verification": self.verification.to_dict() if self.verification else None,
            "workspace": str(self.workspace) if self.workspace else None,
            "log_file": str(self.log_file) if self.log_file else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "toolchain": self.toolchain,
        }
