"""The public ModKit adapter contract (Phase H.7).

A ModKit is a *transformation provider*; APKForge owns the lifecycle. The
framework (:class:`~apkforge.modkit.executor.ModKitExecutor`) calls an adapter in
this order and never lets it touch anything outside its isolated workspace::

    availability()            is the tool installed, configured, runnable, supported?
    validate_input(request)   adapter-specific request checks (parameters, input type)
    prepare(ctx)              optional: write files into working/ (e.g. an option file)
    execute(ctx)              run the transformation; reads input/, writes output/
    collect_output(ctx)       *claim* which files in output/ are the result
    cleanup(ctx)              optional: release adapter resources (always called)

Two adapter styles are supported by the same contract:

- :class:`ExternalProcessAdapter` - a separately installed CLI tool. The adapter
  only builds an argument vector (:meth:`ExternalProcessAdapter.build_command`); the
  framework runs it with :class:`~apkforge.modkit.process.ModKitProcessRunner`.
- A library/API adapter subclasses :class:`ModKitAdapter` directly and implements
  :meth:`ModKitAdapter.execute` in-process, returning an
  :class:`~apkforge.modkit.models.ExecutionOutcome` with ``command=None``.

Contract rules
--------------
- ``capabilities()`` lists only what the adapter has verified; every operation's
  capabilities must be a subset of it (the manager rejects an adapter otherwise).
- ``collect_output`` names files *relative to output/*. The framework validates
  every claim independently (see :mod:`apkforge.modkit.validation`).
- Adapters must not retry, must not write outside the workspace, and must not
  read the original APK (they get ``ctx.staged_input``).
- Nothing in this contract is specific to any particular ModKit.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from apkforge.modkit.models import (
    AvailabilityReport,
    AvailabilityStatus,
    ExecutionOutcome,
    InstallationModel,
    ModKitCapability,
    ModKitIdentity,
    OperationSpec,
    OutputDeclaration,
    Requirement,
    RequirementCheck,
    RequirementKind,
    TrustLevel,
)
from apkforge.modkit.process import INHERITED_ENVIRONMENT, CommandSpec, ModKitProcessRunner

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.modkit.config import ModKitConfig
    from apkforge.modkit.models import ExecutionRequest
    from apkforge.modkit.workspace import ModKitWorkspace

__all__ = [
    "ExecutionContext",
    "ExternalProcessAdapter",
    "ModKitAdapter",
    "compare_versions",
    "parse_version_tuple",
]

_VERSION = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version_tuple(text: str) -> tuple[int, int, int] | None:
    m = _VERSION.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def compare_versions(a: str, b: str) -> int | None:
    """-1/0/1 comparing the numeric ``major.minor.patch`` parts; None if unparsable."""
    ta, tb = parse_version_tuple(a), parse_version_tuple(b)
    if ta is None or tb is None:
        return None
    return (ta > tb) - (ta < tb)


@dataclass(frozen=True)
class ExecutionContext:
    """Everything an adapter may use during one execution."""

    execution_id: str
    request: ExecutionRequest
    operation: OperationSpec
    workspace: ModKitWorkspace
    staged_input: Path
    timeout_seconds: float
    config: ModKitConfig | None = None

    @property
    def output_dir(self) -> Path:
        return self.workspace.output_dir

    @property
    def working_dir(self) -> Path:
        return self.workspace.working_dir


class ModKitAdapter(ABC):
    """Base class of every ModKit adapter."""

    modkit_id: ClassVar[str]
    display_name: ClassVar[str]
    adapter_version: ClassVar[str]
    description: ClassVar[str] = ""
    installation: ClassVar[InstallationModel] = InstallationModel.USER_MANAGED
    trust: ClassVar[TrustLevel] = TrustLevel.EXTERNAL_UNVERIFIED
    license_note: ClassVar[str] = (
        "Third-party ModKit: governed by its own license. APKForge does not bundle or "
        "redistribute it and grants no redistribution rights."
    )

    def __init__(self, config: ModKitConfig | None = None) -> None:
        self.config = config
        self._availability: AvailabilityReport | None = None

    # -- identity -----------------------------------------------------------------

    @property
    def id(self) -> str:
        return self.modkit_id

    @property
    def name(self) -> str:
        return self.display_name

    @property
    def version(self) -> str | None:
        """Installed tool version (None when unknown/not installed)."""
        return self.availability().installed_version

    def identity(self) -> ModKitIdentity:
        return ModKitIdentity(
            modkit_id=self.modkit_id,
            display_name=self.display_name,
            adapter_version=self.adapter_version,
            description=self.description,
            installed_version=self.version,
            installation=self.installation,
            trust=self.trust,
            license_note=self.license_note,
        )

    # -- declarations -------------------------------------------------------------

    @abstractmethod
    def capabilities(self) -> tuple[ModKitCapability, ...]:
        """Verified capabilities of this adapter (never speculative)."""

    @abstractmethod
    def operations(self) -> tuple[OperationSpec, ...]:
        """Operations a request may name."""

    @abstractmethod
    def requirements(self) -> tuple[Requirement, ...]:
        """Prerequisites (executables, runtimes, version bounds, ...)."""

    def toolchain(self) -> dict[str, str]:
        """Versions of the dependencies used, for provenance (non-secret)."""
        return {}

    # -- availability -------------------------------------------------------------

    def availability(self) -> AvailabilityReport:
        """Cached :meth:`check_availability`."""
        if self._availability is None:
            self._availability = self.check_availability()
        return self._availability

    def refresh(self) -> AvailabilityReport:
        self._availability = None
        return self.availability()

    @abstractmethod
    def check_availability(self) -> AvailabilityReport:
        """Determine availability now. Must not modify anything."""

    # -- lifecycle ----------------------------------------------------------------

    def validate_input(self, request: ExecutionRequest, operation: OperationSpec) -> list[str]:
        """Adapter-specific problems with *request* (the framework already checked
        the generic ones: input file, operation, parameters, capabilities)."""
        return []

    def prepare(self, ctx: ExecutionContext) -> None:  # noqa: B027 - optional hook
        """Optional preparation inside ``ctx.working_dir``."""

    @abstractmethod
    def execute(self, ctx: ExecutionContext) -> ExecutionOutcome:
        """Run the transformation (exactly once; never retry)."""

    @abstractmethod
    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        """Name the produced files relative to ``ctx.output_dir``."""

    def cleanup(self, ctx: ExecutionContext) -> None:  # noqa: B027 - optional hook
        """Release adapter resources. Called even when execution failed."""


class ExternalProcessAdapter(ModKitAdapter):
    """Adapter for a separately installed command-line ModKit.

    Subclasses implement :meth:`version_argv`, :meth:`parse_version` and
    :meth:`build_command`; availability, version detection and execution are
    provided here.
    """

    #: Inclusive minimum / exclusive maximum supported tool version (None: unbounded).
    min_version: ClassVar[str | None] = None
    max_version: ClassVar[str | None] = None
    #: Additional (non-secret) parent environment variables the tool needs.
    inherit_environment: ClassVar[tuple[str, ...]] = ()
    version_timeout: ClassVar[float] = 30.0

    def __init__(
        self,
        config: ModKitConfig | None = None,
        *,
        runner: ModKitProcessRunner | None = None,
    ) -> None:
        super().__init__(config)
        self.runner = runner or ModKitProcessRunner()

    # -- subclass hooks -----------------------------------------------------------

    def default_executable(self) -> Path | None:
        """Executable used when the configuration names none (default: none)."""
        return None

    def launcher(self, executable: Path) -> list[str]:
        """Argument-vector prefix that runs *executable* (e.g. ``[java, -jar, exe]``)."""
        return [str(executable)]

    def dependency_checks(self) -> list[RequirementCheck]:
        """Checks for runtimes/dependencies other than the executable itself."""
        return []

    @abstractmethod
    def version_argv(self, executable: Path) -> list[str]:
        """Argument vector that makes the tool print its version."""

    @abstractmethod
    def parse_version(self, text: str) -> str | None:
        """Extract the version from the version command's output."""

    @abstractmethod
    def build_command(self, ctx: ExecutionContext) -> CommandSpec:
        """Argument vector for one execution (no shell, absolute executable)."""

    # -- provided -----------------------------------------------------------------

    def executable(self) -> Path | None:
        if self.config is not None and self.config.executable_path is not None:
            return self.config.executable_path
        return self.default_executable()

    def executable_requirement(self) -> Requirement:
        return Requirement(
            kind=RequirementKind.EXECUTABLE,
            name=f"{self.modkit_id} executable",
            description="configured executable_path (user-managed installation)",
        )

    def requirements(self) -> tuple[Requirement, ...]:
        reqs = [self.executable_requirement()]
        if self.min_version:
            reqs.append(
                Requirement(
                    kind=RequirementKind.MIN_VERSION,
                    name=f"{self.modkit_id} version",
                    constraint=f">={self.min_version}",
                )
            )
        if self.max_version:
            reqs.append(
                Requirement(
                    kind=RequirementKind.MAX_VERSION,
                    name=f"{self.modkit_id} version",
                    constraint=f"<{self.max_version}",
                )
            )
        return tuple(reqs)

    def probe_version(self, executable: Path) -> tuple[str | None, str]:
        """Run the version command; returns (version, detail). Never raises."""
        argv = self.version_argv(executable)
        env = {k: os.environ[k] for k in (*INHERITED_ENVIRONMENT, *self.inherit_environment)
               if k in os.environ}  # fmt: skip
        if self.config is not None:
            env.update(self.config.environment)
        with tempfile.TemporaryDirectory(prefix="apkforge-modkit-version-") as tmp:
            env["HOME"] = env["TMPDIR"] = tmp
            try:
                with tempfile.TemporaryFile(dir=tmp) as out:
                    proc = subprocess.run(  # noqa: S603 - argv array, no shell
                        argv,
                        cwd=tmp,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=out,
                        stderr=subprocess.STDOUT,
                        timeout=self.version_timeout,
                        check=False,
                        start_new_session=True,
                    )
                    out.seek(0)
                    text = out.read(65536).decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                return None, f"version command timed out after {self.version_timeout:g} s"
            except OSError as exc:
                return None, f"version command failed to start: {type(exc).__name__}: {exc}"
        if proc.returncode != 0:
            return None, f"version command exited with {proc.returncode}"
        version = self.parse_version(text)
        if version is None:
            return None, "version command output did not contain a version"
        return version, ""

    def check_availability(self) -> AvailabilityReport:
        S = AvailabilityStatus
        if self.config is not None and not self.config.enabled:
            return AvailabilityReport(status=S.EXECUTION_UNAVAILABLE, reason="disabled in config")
        exe = self.executable()
        if exe is None:
            return AvailabilityReport(
                status=S.NOT_INSTALLED, reason="no executable_path configured"
            )
        exe_req = self.executable_requirement()
        checks: list[RequirementCheck] = []
        if not exe.exists():
            checks.append(RequirementCheck(requirement=exe_req, satisfied=False, observed=str(exe)))
            return AvailabilityReport(
                status=S.NOT_INSTALLED,
                reason=f"executable {exe} does not exist",
                executable=str(exe),
                checks=tuple(checks),
            )
        if not exe.is_file() or not os.access(exe, os.R_OK):
            checks.append(RequirementCheck(requirement=exe_req, satisfied=False, observed=str(exe)))
            return AvailabilityReport(
                status=S.EXECUTION_UNAVAILABLE,
                reason=f"{exe} is not a readable regular file",
                executable=str(exe),
                checks=tuple(checks),
            )
        if self.launcher(exe)[0] == str(exe) and not os.access(exe, os.X_OK):
            checks.append(RequirementCheck(requirement=exe_req, satisfied=False, observed=str(exe)))
            return AvailabilityReport(
                status=S.EXECUTION_UNAVAILABLE,
                reason=f"{exe} is not executable",
                executable=str(exe),
                checks=tuple(checks),
            )
        checks.append(RequirementCheck(requirement=exe_req, satisfied=True, observed=str(exe)))
        deps = self.dependency_checks()
        checks.extend(deps)
        missing = [c for c in deps if c.satisfied is False and not c.requirement.optional]
        if missing:
            return AvailabilityReport(
                status=S.DEPENDENCY_MISSING,
                reason="; ".join(f"{c.requirement.name}: {c.detail or 'missing'}" for c in missing),
                executable=str(exe),
                checks=tuple(checks),
            )
        version, detail = self.probe_version(exe)
        if version is None:
            return AvailabilityReport(
                status=S.EXECUTION_UNAVAILABLE,
                reason=f"cannot determine the installed version: {detail}",
                executable=str(exe),
                checks=tuple(checks),
            )
        status, reason = S.AVAILABLE, ""
        for req in self.requirements():
            if req.kind not in (RequirementKind.MIN_VERSION, RequirementKind.MAX_VERSION):
                continue
            bound = (self.min_version if req.kind is RequirementKind.MIN_VERSION
                     else self.max_version)  # fmt: skip
            assert bound is not None
            cmp = compare_versions(version, bound)
            ok = (
                None
                if cmp is None
                else (cmp >= 0 if req.kind is RequirementKind.MIN_VERSION else cmp < 0)
            )
            checks.append(RequirementCheck(requirement=req, satisfied=ok, observed=version))
            if ok is not True and status is S.AVAILABLE:
                status = S.VERSION_UNSUPPORTED
                reason = f"installed version {version} does not satisfy {req.constraint}"
        return AvailabilityReport(
            status=status,
            reason=reason,
            installed_version=version,
            executable=str(exe),
            checks=tuple(checks),
        )

    def execute(self, ctx: ExecutionContext) -> ExecutionOutcome:
        spec = self.build_command(ctx)
        return self.runner.run(
            spec,
            ctx.workspace,
            timeout_seconds=ctx.timeout_seconds,
            config_environment=self.config.environment if self.config else None,
        )
