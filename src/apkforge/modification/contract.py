"""Phase D modifier contract: what a modifier declares, plans, applies and verifies.

A modifier answers three questions and nothing else:

- *What should change?*  :meth:`APKModifier.inspect` and :meth:`APKModifier.plan`
  read the decoded project and return a :class:`ModifierPlan`. Planning never writes.
- *How is that change applied?*  :meth:`APKModifier.apply` edits files inside the
  decoded project of a BuildService workspace, and only the files the plan declared.
- *How can that change be verified?*  :meth:`APKModifier.verify` (optional) checks
  the rebuilt, signed APK and its re-analysis after the build.

Everything else belongs to someone else: decode, build, align, sign and APK
verification to :class:`~apkforge.builders.service.BuildService`; ordering,
conflicts, source-level checks, rollback, the expected-vs-actual diff and the
aggregate result to :class:`~apkforge.modification.pipeline.ModificationPipeline`.

A modifier never runs a subprocess, never touches the original APK and never reads
outside :attr:`ProjectContext.decoded_dir` (paths go through :meth:`ProjectContext.path`).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, Field

from apkforge.core.exceptions import ModificationError
from apkforge.diff.expectations import ExpectedChange  # noqa: TC001 - pydantic field
from apkforge.modification.edits import SourceEdit  # noqa: TC001 - pydantic field
from apkforge.modification.models import ModificationRisk

if TYPE_CHECKING:
    from apkforge.diff.expectations import ExpectationVerdict
    from apkforge.diff.models import DiffResult

__all__ = [
    "APKModifier",
    "ApplyOutcome",
    "FileAction",
    "ModifierInfo",
    "ModifierPlan",
    "PlanReadiness",
    "PlanTarget",
    "PlannedFileChange",
    "Precondition",
    "ProjectContext",
    "TargetAccess",
    "VerificationEvidence",
    "VerificationOutcome",
    "validate_relative_path",
]

MANIFEST = "AndroidManifest.xml"


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class ModifierInfo(BaseModel):
    """Static description of a modifier (shown by ``apkforge modifiers``)."""

    id: str
    name: str
    description: str
    version: str = "1"
    risk: ModificationRisk = ModificationRisk.MEDIUM
    supported_conditions: list[str] = Field(
        default_factory=list, description="APK conditions under which the modifier applies."
    )
    prerequisites: list[str] = Field(default_factory=list)
    parameters: dict[str, str] = Field(
        default_factory=dict, description="Accepted parameter name -> description."
    )
    verification_available: bool = False
    test_only: bool = Field(
        default=False, description="Exists to exercise the framework; no real-world purpose."
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


class Precondition(BaseModel):
    """One checked precondition. An unsatisfied precondition makes the plan not ready."""

    name: str
    satisfied: bool
    expected: str
    actual: str
    reason: str = ""


class PlanReadiness(StrEnum):
    READY = "ready"
    PRECONDITION_FAILED = "precondition_failed"


class TargetAccess(StrEnum):
    """How a plan uses a target. Two plans conflict on a shared target unless both READ."""

    ADD = "add"
    MODIFY = "modify"
    REMOVE = "remove"
    READ = "read"  # the plan depends on the target staying as it is


class PlanTarget(BaseModel):
    """Something a plan changes or depends on, e.g. ``permission`` / ``component``."""

    kind: str
    identifier: str
    access: TargetAccess
    description: str = ""

    @property
    def writes(self) -> bool:
        return self.access != TargetAccess.READ


class FileAction(StrEnum):
    ADD = "add"
    MODIFY = "modify"
    REMOVE = "remove"


class PlannedFileChange(BaseModel):
    """A file of the decoded project the modifier will add, modify or remove."""

    path: str  # POSIX path relative to the decoded project
    action: FileAction


class ModifierPlan(BaseModel):
    """What a modifier will do to one APK, declared before anything is changed.

    The plan is the source of truth for every later check: the framework compares
    the files actually changed with :attr:`file_changes`, the manifest edits with
    :attr:`manifest_edits`, and the rebuilt APK's re-analysis with
    :attr:`expected_changes`.
    """

    modifier_id: str
    modifier_version: str = "1"
    description: str = ""
    target_apk: str
    target_sha256: str
    package: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    readiness: PlanReadiness = PlanReadiness.READY
    refusal_code: str | None = Field(
        default=None, description="Modifier-specific reason code when not ready."
    )
    preconditions: list[Precondition] = Field(default_factory=list)
    targets: list[PlanTarget] = Field(default_factory=list)
    changes: list[str] = Field(default_factory=list, description="Intended changes, in words.")
    file_changes: list[PlannedFileChange] = Field(default_factory=list)
    manifest_edits: list[SourceEdit] = Field(default_factory=list)
    expected_changes: list[ExpectedChange] = Field(default_factory=list)
    verification: list[str] = Field(
        default_factory=list, description="What verify() checks after the rebuild."
    )
    consequences: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(
        default_factory=dict, description="Modifier-specific payload (e.g. its native plan)."
    )

    @property
    def ready(self) -> bool:
        return self.readiness == PlanReadiness.READY

    def require(
        self, name: str, satisfied: bool, *, expected: str, actual: str, reason: str = ""
    ) -> bool:
        """Record a precondition; an unsatisfied one makes the plan not ready."""
        self.preconditions.append(
            Precondition(
                name=name, satisfied=satisfied, expected=expected, actual=actual, reason=reason
            )
        )
        if not satisfied:
            self.readiness = PlanReadiness.PRECONDITION_FAILED
            self.problems.append(reason or f"{name}: expected {expected}, found {actual}")
        return satisfied

    def comparable(self) -> dict[str, Any]:
        """The parts that must not change between planning and applying."""
        return self.model_dump(
            mode="json",
            include={
                "readiness",
                "targets",
                "file_changes",
                "manifest_edits",
                "expected_changes",
            },
        )


# ---------------------------------------------------------------------------
# Execution context and outcomes
# ---------------------------------------------------------------------------


def validate_relative_path(path: str) -> str:
    """Return *path* if it is a plain relative POSIX path; raise ModificationError otherwise."""
    p = PurePosixPath(path)
    if (
        not path
        or "\\" in path
        or "\x00" in path
        or p.is_absolute()
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise ModificationError(f"Unsafe project path {path!r}", context="modifier-plan")
    return path


class ProjectContext:
    """Read/write view of one decoded project, handed to every modifier call.

    ``decoded_dir`` is inside a BuildService workspace; the original APK is identified
    only by path and SHA-256 and is never opened by a modifier.
    """

    def __init__(
        self,
        decoded_dir: Path,
        *,
        original_apk: Path,
        original_sha256: str,
        baseline: dict[str, Any] | None = None,
    ) -> None:
        self.decoded_dir = decoded_dir.resolve()
        self.original_apk = original_apk
        self.original_sha256 = original_sha256
        self.baseline = baseline or {}

    def path(self, relative: str) -> Path:
        """Absolute path of *relative* inside the decoded project; rejects escapes."""
        candidate = (self.decoded_dir / validate_relative_path(relative)).resolve()
        if not candidate.is_relative_to(self.decoded_dir):
            raise ModificationError(
                f"Path {relative!r} escapes the decoded project", context="modifier-path"
            )
        return candidate

    @property
    def manifest_path(self) -> Path:
        return self.path(MANIFEST)

    def manifest_text(self) -> str:
        return self.manifest_path.read_text(encoding="utf-8")

    def package(self) -> str | None:
        root = ET.fromstring(self.manifest_text())  # noqa: S314 - Apktool output
        return root.get("package")


class ApplyOutcome(BaseModel):
    """What ``apply`` reports. The framework independently checks the files it touched."""

    applied: bool
    message: str = ""
    errors: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class VerificationEvidence:
    """What a modifier's ``verify`` may look at after the rebuild."""

    def __init__(
        self,
        project: ProjectContext,
        output_apk: Path,
        diff: DiffResult,
        verdict: ExpectationVerdict,
    ) -> None:
        self.project = project
        self.output_apk = output_apk
        self.diff = diff
        self.verdict = verdict


class VerificationOutcome(BaseModel):
    """Result of a modifier's own verification of the rebuilt APK."""

    passed: bool
    checks: list[Precondition] = Field(
        default_factory=list, description="Individual checks (expected vs actual)."
    )
    message: str = ""

    @classmethod
    def from_checks(cls, checks: list[Precondition]) -> VerificationOutcome:
        failed = [c for c in checks if not c.satisfied]
        msg = "; ".join(f"{c.name}: expected {c.expected}, found {c.actual}" for c in failed)
        return cls(passed=bool(checks) and not failed, checks=checks, message=msg or "passed")


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


class APKModifier(ABC):
    """Base class for Phase D modifiers. See the module docstring for the contract.

    Lifecycle (driven by the pipeline): ``inspect`` -> ``plan`` (with preconditions)
    -> ``apply`` -> [framework source check] -> [BuildService] -> [diff] -> ``verify``.
    """

    #: Stable identifier, unique within a catalog (e.g. ``c5.disable_boot_receiver``).
    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1"
    risk: ClassVar[ModificationRisk] = ModificationRisk.MEDIUM
    supported_conditions: ClassVar[list[str]] = []
    prerequisites: ClassVar[list[str]] = []
    parameters: ClassVar[dict[str, str]] = {}
    test_only: ClassVar[bool] = False

    def info(self) -> ModifierInfo:
        return ModifierInfo(
            id=self.id,
            name=self.name,
            description=self.description,
            version=self.version,
            risk=self.risk,
            supported_conditions=list(self.supported_conditions),
            prerequisites=list(self.prerequisites),
            parameters=dict(self.parameters),
            verification_available=self.has_verification(),
            test_only=self.test_only,
        )

    @classmethod
    def has_verification(cls) -> bool:
        return cls.verify is not APKModifier.verify

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        """Read-only findings the plan is based on (recorded in the result)."""
        return {}

    @abstractmethod
    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        """Declare the change, or a not-ready plan with failed preconditions. Never writes."""

    @abstractmethod
    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        """Make exactly the planned edits inside ``project.decoded_dir``."""

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        """Check that the intended modification is present in the rebuilt APK.

        Not implemented by default: the framework then reports the modifier as
        *not verified*, never as verified.
        """
        raise NotImplementedError

    def new_plan(self, project: ProjectContext, parameters: dict[str, str]) -> ModifierPlan:
        """A ready, empty plan bound to this modifier and APK (helper for ``plan``)."""
        return ModifierPlan(
            modifier_id=self.id,
            modifier_version=self.version,
            description=self.description,
            target_apk=str(project.original_apk),
            target_sha256=project.original_sha256,
            package=project.package(),
            parameters=dict(parameters),
        )
