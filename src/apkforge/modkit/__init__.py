"""Phase H.7 - Third-Party ModKit Integration Framework.

A *ModKit* is an external APK modification engine (a separately installed CLI tool
or, later, a library) that APKForge drives through a controlled adapter contract.
APKForge owns the lifecycle: input staging and SHA-256 tracking, the isolated
workspace, process execution, timeout/failure handling, independent output
validation, provenance, and the hand-off to the existing diff, privacy/security
and H.4 verification infrastructure. The ModKit only transforms.

No third-party ModKit is bundled; H.7 ships only the generic framework and the
deterministic reference ``test-modkit``. H.9 adds sequential chains
(:mod:`apkforge.modkit.chain`). See ``docs/modkits.md``.
"""

from __future__ import annotations

from apkforge.modkit.analysis import (
    FindingDelta,
    ModKitAnalysisReport,
    ModKitPostAnalysis,
    compare_findings,
)
from apkforge.modkit.chain import (
    ChainSpec,
    ChainStep,
    ModKitChainResult,
    ModKitChainRunner,
    load_chain_spec,
)
from apkforge.modkit.config import (
    ConfigIssue,
    ModKitConfig,
    ModKitConfigSet,
    load_modkit_config,
    parse_modkit_config,
)
from apkforge.modkit.contract import ExecutionContext, ExternalProcessAdapter, ModKitAdapter
from apkforge.modkit.executor import ModKitExecutor
from apkforge.modkit.manager import ModKitManager, contract_problems, default_manager
from apkforge.modkit.models import (
    ArtifactRecord,
    AvailabilityReport,
    AvailabilityStatus,
    CommandRecord,
    ExecutionOutcome,
    ExecutionRequest,
    FailureCategory,
    InstallationModel,
    ModKitCapability,
    ModKitExecutionResult,
    ModKitIdentity,
    ModKitInfo,
    ModKitResultStatus,
    OperationSpec,
    OutputDeclaration,
    ParameterSpec,
    ProvenanceRecord,
    Requirement,
    RequirementCheck,
    RequirementKind,
    TrustLevel,
)
from apkforge.modkit.process import CommandSpec, ModKitProcessRunner
from apkforge.modkit.workspace import ModKitWorkspace

__all__ = [
    "ArtifactRecord",
    "AvailabilityReport",
    "AvailabilityStatus",
    "ChainSpec",
    "ChainStep",
    "CommandRecord",
    "CommandSpec",
    "ConfigIssue",
    "ExecutionContext",
    "ExecutionOutcome",
    "ExecutionRequest",
    "ExternalProcessAdapter",
    "FailureCategory",
    "FindingDelta",
    "InstallationModel",
    "ModKitAdapter",
    "ModKitAnalysisReport",
    "ModKitCapability",
    "ModKitChainResult",
    "ModKitChainRunner",
    "ModKitConfig",
    "ModKitConfigSet",
    "ModKitExecutionResult",
    "ModKitExecutor",
    "ModKitIdentity",
    "ModKitInfo",
    "ModKitManager",
    "ModKitPostAnalysis",
    "ModKitProcessRunner",
    "ModKitResultStatus",
    "ModKitWorkspace",
    "OperationSpec",
    "OutputDeclaration",
    "ParameterSpec",
    "ProvenanceRecord",
    "Requirement",
    "RequirementCheck",
    "RequirementKind",
    "TrustLevel",
    "compare_findings",
    "contract_problems",
    "default_manager",
    "load_chain_spec",
    "load_modkit_config",
    "parse_modkit_config",
]
