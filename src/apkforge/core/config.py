"""APKForge configuration system.

All configuration is expressed as Pydantic models with validated fields and
secure defaults.  Configuration can be loaded from:

1. Built-in defaults (always applied first).
2. A TOML file at a user-supplied path (Phase 1+).
3. Environment variables with the ``APKFORGE_`` prefix (Phase 1+).

Security defaults
-----------------
- APKs are never executed.
- Extraction limits are enforced from the start.
- Temporary files are isolated per-session.
- No networking unless explicitly configured.
"""

from __future__ import annotations

import os
import tempfile
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

__all__ = [
    "APKForgeConfig",
    "AnalysisSettings",
    "ExtractionLimits",
    "LogLevel",
    "PluginSettings",
    "ReportFormat",
    "ReportSettings",
    "WorkspaceSettings",
    "load_default_config",
]


class LogLevel(StrEnum):
    """Supported logging verbosity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ReportFormat(StrEnum):
    """Supported report output formats (Phase 1+)."""

    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


def _env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return default


class ExtractionLimits(BaseModel):
    """Hard limits applied during APK extraction.

    These limits exist to mitigate zip-bomb and decompression attacks.  They
    must be respected by every future extraction implementation.

    Attributes:
        max_total_size_bytes: Maximum total uncompressed bytes extracted.
            Default: 1024 MiB (1 GiB) or APKFORGE_EXTRACTION_MAX_TOTAL_BYTES.
        max_single_file_bytes: Maximum uncompressed size for a single entry.
            Default: 256 MiB or APKFORGE_EXTRACTION_MAX_SINGLE_FILE_BYTES.
            Accommodates legitimate modern native libraries (such as libxul.so
            at ~157 MB) while preserving strict bounds against decompression bombs.
        max_file_count: Maximum number of files extracted from a single APK.
            Default: 10,000 or APKFORGE_EXTRACTION_MAX_FILE_COUNT.
        max_recursion_depth: Maximum nesting depth when extracting nested archives.
    """

    max_total_size_bytes: int = Field(
        default_factory=lambda: _env_int("APKFORGE_EXTRACTION_MAX_TOTAL_BYTES", 1024 * 1024 * 1024),
        ge=1,
        description="Maximum total extracted size in bytes.",
    )
    max_single_file_bytes: int = Field(
        default_factory=lambda: _env_int("APKFORGE_EXTRACTION_MAX_SINGLE_FILE_BYTES", 256 * 1024 * 1024),
        ge=1,
        description="Maximum size for a single extracted file in bytes.",
    )
    max_file_count: int = Field(
        default_factory=lambda: _env_int("APKFORGE_EXTRACTION_MAX_FILE_COUNT", 10_000),
        ge=1,
        description="Maximum number of files to extract.",
    )
    max_recursion_depth: int = Field(
        default=4,
        ge=0,
        le=16,
        description="Maximum nesting depth when extracting embedded archives.",
    )

    @model_validator(mode="after")
    def single_must_not_exceed_total(self) -> ExtractionLimits:
        if self.max_single_file_bytes > self.max_total_size_bytes:
            msg = (
                "max_single_file_bytes must be ≤ max_total_size_bytes; "
                f"got {self.max_single_file_bytes} > {self.max_total_size_bytes}"
            )
            raise ValueError(msg)
        return self



class AnalysisSettings(BaseModel):
    """Settings that govern analysis behaviour.

    Attributes:
        enabled_modules: Names of analysis modules to activate.  An empty list
            means *all* registered modules run (default).  Provide an explicit
            list to restrict.
        timeout_seconds: Per-analysis wall-clock timeout (0 = no limit).
        treat_warnings_as_errors: When True, any warning-level finding causes
            the overall status to be at least PARTIAL.
    """

    enabled_modules: list[str] = Field(
        default_factory=list,
        description="Restrict analysis to these modules.  Empty = all.",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=0,
        description="Analysis timeout in seconds (0 = unlimited).",
    )
    treat_warnings_as_errors: bool = Field(
        default=False,
        description="Escalate warnings to errors for stricter analysis.",
    )


class ReportSettings(BaseModel):
    """Settings for the reporting subsystem.

    Attributes:
        default_format: Format used when ``--format`` is not supplied on the CLI.
        output_directory: Directory where report files are written.  ``None``
            means output to stdout/console only.
        include_evidence: Include raw evidence snippets in findings.
        include_limitations: Include analysis limitation descriptions in the report.
    """

    default_format: ReportFormat = ReportFormat.TEXT
    output_directory: Path | None = Field(
        default=None,
        description="Directory for report output files.  None = stdout.",
    )
    include_evidence: bool = Field(
        default=True,
        description="Include raw evidence in finding reports.",
    )
    include_limitations: bool = Field(
        default=True,
        description="Include analysis limitation descriptions.",
    )


class PluginSettings(BaseModel):
    """Settings for the plugin subsystem.

    Attributes:
        plugin_directories: Extra filesystem paths where APKForge will look for
            plugin packages in addition to built-in plugins.
        disabled_plugins: Names of plugins that must not be loaded even if
            they are discovered.
    """

    plugin_directories: list[Path] = Field(
        default_factory=list,
        description="Extra directories to scan for plugins.",
    )
    disabled_plugins: list[str] = Field(
        default_factory=list,
        description="Plugins explicitly disabled by name.",
    )


class WorkspaceSettings(BaseModel):
    """Settings for the workspace (temporary working directory) subsystem.

    Attributes:
        base_directory: Parent directory for per-session workspace directories.
            Defaults to the OS temporary directory.
        keep_on_success: Keep workspace files after a successful operation.
        keep_on_failure: Keep workspace files after a failed operation (useful
            for debugging).
    """

    base_directory: Path = Field(
        default_factory=lambda: Path(tempfile.gettempdir()) / "apkforge",
        description="Parent directory for session workspaces.",
    )
    keep_on_success: bool = Field(
        default=False,
        description="Retain workspace files after successful operations.",
    )
    keep_on_failure: bool = Field(
        default=True,
        description="Retain workspace files after failed operations for debugging.",
    )

    @field_validator("base_directory", mode="before")
    @classmethod
    def expand_user(cls, v: object) -> Path:
        """Expand ``~`` in user-supplied paths."""
        if isinstance(v, str):
            return Path(os.path.expanduser(v))
        if isinstance(v, Path):
            return Path(os.path.expanduser(str(v)))
        return Path(str(v))


# ---------------------------------------------------------------------------
# Root configuration model
# ---------------------------------------------------------------------------


class APKForgeConfig(BaseModel):
    """Root APKForge configuration.

    All sub-models have secure defaults so that APKForge is safe out of the
    box without any user-supplied configuration file.

    Attributes:
        log_level: Verbosity level for the root logger.
        extraction: Limits applied during APK extraction.
        analysis: General analysis settings.
        reporting: Report generation settings.
        plugins: Plugin discovery settings.
        workspace: Workspace (working-copy) settings.
    """

    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Root logger verbosity.",
    )
    extraction: ExtractionLimits = Field(default_factory=ExtractionLimits)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    reporting: ReportSettings = Field(default_factory=ReportSettings)
    plugins: PluginSettings = Field(default_factory=PluginSettings)
    workspace: WorkspaceSettings = Field(default_factory=WorkspaceSettings)

    model_config = {"frozen": False, "extra": "forbid"}


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def load_default_config() -> APKForgeConfig:
    """Return a configuration object with all defaults applied.

    This is the canonical way to obtain a config instance when no
    user-supplied configuration file is present.

    Returns:
        APKForgeConfig: A fully-populated, validated configuration.
    """
    return APKForgeConfig()
