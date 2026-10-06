"""Phase H.7 ModKit models (schema 1).

Everything a ModKit adapter reports and everything the framework records about an
execution is an immutable, typed model. Enums are ``StrEnum`` so the JSON form is
stable; new members and new optional fields may be added (additive evolution), the
meaning of existing ones never changes.

Vocabulary
----------
``modkit_id``         stable identifier of the ModKit (``test-modkit``, later ``morphe``)
``display_name``      human-readable name
``installed_version`` version the installed tool reports about itself (``None``: unknown)
``adapter_version``   version of the APKForge adapter code that drives the tool

These are deliberately different fields: the same adapter can drive several tool
versions, and a tool upgrade does not change the adapter.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import Path  # noqa: TC003 - pydantic field type
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "MODKIT_ID_PATTERN",
    "SCHEMA_VERSION",
    "ArtifactRecord",
    "AvailabilityReport",
    "AvailabilityStatus",
    "CommandRecord",
    "ExecutionOutcome",
    "ExecutionRequest",
    "FailureCategory",
    "InstallationModel",
    "ModKitCapability",
    "ModKitExecutionResult",
    "ModKitIdentity",
    "ModKitInfo",
    "ModKitResultStatus",
    "OperationSpec",
    "OutputDeclaration",
    "ParameterSpec",
    "ProvenanceRecord",
    "Requirement",
    "RequirementCheck",
    "RequirementKind",
    "TrustLevel",
    "ValidationCheck",
]

SCHEMA_VERSION = 1

#: A ModKit id is a lowercase slug: it is used in file names and CLI arguments.
MODKIT_ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ModKitCapability(StrEnum):
    """What an adapter has *verified* it can do (never what the tool might do)."""

    DEX_TRANSFORMATION = "DEX_TRANSFORMATION"
    RESOURCE_TRANSFORMATION = "RESOURCE_TRANSFORMATION"
    MANIFEST_TRANSFORMATION = "MANIFEST_TRANSFORMATION"
    APK_TRANSFORMATION = "APK_TRANSFORMATION"
    PATCH_SELECTION = "PATCH_SELECTION"
    MULTI_PATCH = "MULTI_PATCH"


class AvailabilityStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_INSTALLED = "NOT_INSTALLED"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    EXECUTION_UNAVAILABLE = "EXECUTION_UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class InstallationModel(StrEnum):
    """Who put the ModKit on this machine. H.7 implements USER_MANAGED only for
    third-party tools; APKForge never downloads or installs one."""

    USER_MANAGED = "USER_MANAGED"
    APKFORGE_MANAGED = "APKFORGE_MANAGED"  # reserved: not implemented
    BUNDLED = "BUNDLED"  # APKForge's own (test) code only; no third-party tool is bundled


class TrustLevel(StrEnum):
    """APKForge validates every output but never vouches for a ModKit's semantics."""

    EXTERNAL_UNVERIFIED = "EXTERNAL_UNVERIFIED"
    TEST_ONLY = "TEST_ONLY"


class RequirementKind(StrEnum):
    EXECUTABLE = "EXECUTABLE"
    RUNTIME = "RUNTIME"
    MIN_VERSION = "MIN_VERSION"
    MAX_VERSION = "MAX_VERSION"
    ANDROID_SDK = "ANDROID_SDK"
    BUILD_TOOLS = "BUILD_TOOLS"
    ENVIRONMENT = "ENVIRONMENT"
    FILESYSTEM = "FILESYSTEM"
    OTHER = "OTHER"


class ModKitResultStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NO_OP = "NO_OP"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    INVALID_INPUT = "INVALID_INPUT"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    TIMEOUT = "TIMEOUT"
    OUTPUT_INVALID = "OUTPUT_INVALID"
    OUTPUT_MISSING = "OUTPUT_MISSING"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    DEPENDENCY_ERROR = "DEPENDENCY_ERROR"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class FailureCategory(StrEnum):
    """Finer-grained cause of a non-successful result."""

    NOT_AVAILABLE = "NOT_AVAILABLE"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_REQUEST = "INVALID_REQUEST"
    WORKSPACE_FAILURE = "WORKSPACE_FAILURE"
    STAGING_MISMATCH = "STAGING_MISMATCH"
    MISSING_EXECUTABLE = "MISSING_EXECUTABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TIMEOUT = "TIMEOUT"
    NON_ZERO_EXIT = "NON_ZERO_EXIT"
    PROCESS_CRASH = "PROCESS_CRASH"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    ADAPTER_ERROR = "ADAPTER_ERROR"
    INPUT_MUTATED = "INPUT_MUTATED"
    ORIGINAL_MUTATED = "ORIGINAL_MUTATED"
    OUTPUT_MISSING = "OUTPUT_MISSING"
    OUTPUT_AMBIGUOUS = "OUTPUT_AMBIGUOUS"
    OUTPUT_OUTSIDE_WORKSPACE = "OUTPUT_OUTSIDE_WORKSPACE"
    OUTPUT_NOT_REGULAR_FILE = "OUTPUT_NOT_REGULAR_FILE"
    OUTPUT_MALFORMED = "OUTPUT_MALFORMED"
    OUTPUT_UNCHANGED = "OUTPUT_UNCHANGED"
    UNEXPECTED_ARTIFACT = "UNEXPECTED_ARTIFACT"
    UNSAFE_FILENAME = "UNSAFE_FILENAME"
    PUBLISH_FAILED = "PUBLISH_FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Identity, requirements, availability
# ---------------------------------------------------------------------------


class ModKitIdentity(_Frozen):
    modkit_id: str
    display_name: str
    adapter_version: str
    description: str = ""
    installed_version: str | None = None
    installation: InstallationModel = InstallationModel.USER_MANAGED
    trust: TrustLevel = TrustLevel.EXTERNAL_UNVERIFIED
    license_note: str = ""

    @field_validator("modkit_id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not MODKIT_ID_PATTERN.fullmatch(v) or len(v) > 64:
            raise ValueError(f"invalid modkit_id {v!r}: lowercase slug [a-z0-9-], max 64 chars")
        return v


class Requirement(_Frozen):
    """A prerequisite the adapter declares (checked by :class:`RequirementCheck`)."""

    kind: RequirementKind
    name: str
    description: str = ""
    #: Version bound or other constraint text (``>=1.0.0``), when applicable.
    constraint: str | None = None
    optional: bool = False


class RequirementCheck(_Frozen):
    requirement: Requirement
    satisfied: bool | None  # None: could not be determined
    detail: str = ""
    observed: str | None = None


class AvailabilityReport(_Frozen):
    status: AvailabilityStatus
    reason: str = ""
    installed_version: str | None = None
    executable: str | None = None
    checks: tuple[RequirementCheck, ...] = ()

    @property
    def available(self) -> bool:
        return self.status is AvailabilityStatus.AVAILABLE


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


class ParameterSpec(_Frozen):
    name: str
    description: str = ""
    required: bool = False
    #: Sensitive values are masked in every command record and log.
    sensitive: bool = False
    #: Full-match regex every value must satisfy (default: no control characters).
    pattern: str = r"[^\x00-\x1f\x7f]{0,4096}"
    choices: tuple[str, ...] = ()


class OperationSpec(_Frozen):
    """A requestable operation. ``capabilities`` are what the operation exercises."""

    id: str
    description: str = ""
    capabilities: tuple[ModKitCapability, ...] = ()
    parameters: tuple[ParameterSpec, ...] = ()
    input_types: tuple[str, ...] = ("apk",)
    output_types: tuple[str, ...] = ("apk",)
    #: The operation may legitimately leave the APK unchanged (NO_OP).
    may_be_noop: bool = False


class ModKitInfo(_Frozen):
    """Discovery record: what ``apkforge modkits`` / ``modkit info`` shows."""

    identity: ModKitIdentity
    availability: AvailabilityReport
    capabilities: tuple[ModKitCapability, ...] = ()
    requirements: tuple[Requirement, ...] = ()
    operations: tuple[OperationSpec, ...] = ()
    configured: bool = False
    enabled: bool = True
    config_source: str | None = None
    config_errors: tuple[str, ...] = ()
    #: An entry exists in the configuration but no adapter is registered for it.
    adapter_registered: bool = True

    def to_json_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = self.model_dump(mode="json")
        return data


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


class ExecutionRequest(_Frozen):
    """What a caller asks a ModKit to do. Never contains a shell string: the adapter
    builds the argument vector from these typed fields."""

    input_apk: Path
    #: Directory the validated output is published to (created if missing).
    output_dir: Path
    operation: str
    parameters: dict[str, str] = Field(default_factory=dict)
    #: Capabilities the caller selects; must be a subset of the operation's.
    capabilities: tuple[ModKitCapability, ...] = ()
    timeout_seconds: int | None = Field(default=None, ge=1, le=86_400)
    #: A transformation is expected: an unchanged output is OUTPUT_INVALID unless
    #: the adapter declares a no-op. ``False`` accepts an unchanged output as NO_OP.
    expect_change: bool = True
    #: Base directory for the isolated execution workspace.
    workspace_base: Path | None = None
    keep_workspace: bool = False
    #: File name of the published APK (a single safe component); default
    #: ``<input stem>.<modkit_id>.apk``. ModKit-supplied names are never used.
    output_name: str | None = None


class CommandRecord(_Frozen):
    """A reproducible, secret-masked description of an external invocation."""

    executable: str
    argv: tuple[str, ...]
    cwd: str
    #: Non-secret environment handed to the child (sensitive values masked).
    environment: dict[str, str] = Field(default_factory=dict)
    #: Names of environment variables the child received whose values are masked.
    masked_environment: tuple[str, ...] = ()
    masked_arguments: int = 0


class ExecutionOutcome(_Frozen):
    """What the adapter's ``execute`` observed. Independent of how it ran (process
    or in-process library), so no subprocess type leaks into the contract."""

    exit_code: int | None = None
    timed_out: bool = False
    #: Signal number when the process was killed by a signal (crash).
    signal: int | None = None
    error: FailureCategory | None = None
    error_detail: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    command: CommandRecord | None = None
    stdout_log: str | None = None
    stderr_log: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""


class OutputDeclaration(_Frozen):
    """What the adapter claims it produced, as names *relative to output/*.

    The framework never trusts this: it scans ``output/`` itself and rejects
    anything undeclared, unsafe, ambiguous, or escaping the boundary.
    """

    primary: tuple[str, ...] = ()
    auxiliary: tuple[str, ...] = ()
    declared_no_op: bool = False
    notes: tuple[str, ...] = ()


class ArtifactRecord(_Frozen):
    role: str  # original | staged_input | candidate | published
    path: str
    sha256: str
    size: int


class ValidationCheck(_Frozen):
    id: str
    passed: bool
    detail: str = ""


class ProvenanceRecord(_Frozen):
    schema_version: int = SCHEMA_VERSION
    execution_id: str
    modkit_id: str
    modkit_version: str | None
    adapter_version: str
    apkforge_version: str
    requested_operation: str
    capabilities: tuple[ModKitCapability, ...] = ()
    parameters: dict[str, str] = Field(default_factory=dict)  # masked
    input_sha256: str
    input_size: int
    input_path: str
    output_sha256: str | None = None
    output_size: int | None = None
    start_time: str
    end_time: str
    exit_code: int | None = None
    toolchain: dict[str, str] = Field(default_factory=dict)
    workspace_id: str
    workspace_path: str
    command: CommandRecord | None = None


class ModKitExecutionResult(_Frozen):
    schema_version: int = SCHEMA_VERSION
    status: ModKitResultStatus
    failure: FailureCategory | None = None
    reason: str = ""
    execution_id: str
    identity: ModKitIdentity
    operation: str
    original: ArtifactRecord | None = None
    staged_input: ArtifactRecord | None = None
    candidate: ArtifactRecord | None = None
    published: ArtifactRecord | None = None
    outcome: ExecutionOutcome | None = None
    declaration: OutputDeclaration | None = None
    validation: tuple[ValidationCheck, ...] = ()
    provenance: ProvenanceRecord | None = None
    original_unchanged: bool | None = None
    workspace_path: str | None = None
    workspace_retained: bool = False
    messages: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status in (ModKitResultStatus.SUCCESS, ModKitResultStatus.NO_OP)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent, sort_keys=False)
