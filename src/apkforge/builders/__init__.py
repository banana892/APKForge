"""APKForge builders package.

:class:`BuildService` is the single abstraction the rest of APKForge uses to
rebuild an APK. Its stages (``prepare_workspace``, ``decode``, ``build``,
``align``, ``sign``, ``verify``) are individually callable and composed by
``build_pipeline``. No other module should invoke Apktool, zipalign or
apksigner directly; CLI and GUI share this one service.

Security principles:
- APKForge never executes the APK being built.
- Build output is verified (alignment, signature, expected signer) before it is
  reported as successful.
"""

from __future__ import annotations

from apkforge.builders.classify import FailureDiagnosis, classify_stage_failure
from apkforge.builders.models import (
    BuildFailureCategory,
    BuildOptions,
    BuildResult,
    BuildStage,
    BuildVerificationResult,
    CertificateInfo,
    SigningMode,
    StageResult,
    StageStatus,
)
from apkforge.builders.runner import CommandResult, CommandRunner
from apkforge.builders.service import BuildService
from apkforge.builders.signing import SigningConfig, ensure_dev_keystore
from apkforge.builders.toolchain import (
    ToolchainCheckResult,
    ToolchainConfig,
    ToolDiagnostic,
    validate_toolchain,
)
from apkforge.builders.workspace import BuildWorkspace

__all__ = [
    "BuildFailureCategory",
    "BuildOptions",
    "BuildResult",
    "BuildService",
    "BuildStage",
    "BuildVerificationResult",
    "BuildWorkspace",
    "CertificateInfo",
    "CommandResult",
    "CommandRunner",
    "FailureDiagnosis",
    "SigningConfig",
    "SigningMode",
    "StageResult",
    "StageStatus",
    "ToolDiagnostic",
    "ToolchainCheckResult",
    "ToolchainConfig",
    "classify_stage_failure",
    "ensure_dev_keystore",
    "validate_toolchain",
]
