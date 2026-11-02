"""Adapter for Morphe Desktop (H.8.1: discovery and compatibility only).

Morphe Desktop (https://github.com/MorpheApp/morphe-desktop) ships as a JAR run with
``java -jar morphe-desktop.jar ...``; APKForge never bundles or downloads it, the user
configures ``executable_path`` to point at their own copy (see ``docs/modkits.md``).
This adapter only answers "is it installed, is Java available, what version is it, is
that version supported" — it declares no capabilities or operations, so the framework
never invokes :meth:`build_command`. Patch discovery and execution are added in later
H.8 stages.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from apkforge.modkit.contract import ExternalProcessAdapter
from apkforge.modkit.models import (
    ModKitCapability,
    OperationSpec,
    OutputDeclaration,
    Requirement,
    RequirementCheck,
    RequirementKind,
    TrustLevel,
)

if TYPE_CHECKING:
    from apkforge.modkit.contract import ExecutionContext
    from apkforge.modkit.process import CommandSpec

__all__ = ["MIN_JAVA_MAJOR", "MORPHE_MODKIT_ID", "MorpheAdapter"]

MORPHE_MODKIT_ID = "morphe"
#: Morphe Desktop's documented minimum Java runtime.
MIN_JAVA_MAJOR = 21
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?")
_JAVA_VERSION_RE = re.compile(r'version\s+"?(\d+)(?:\.(\d+))?')

_JAVA_REQUIREMENT = Requirement(
    kind=RequirementKind.RUNTIME,
    name="java runtime",
    description=(
        f"Java {MIN_JAVA_MAJOR}+ (Morphe Desktop CLI requirement); override with "
        "modkits.morphe.options.java_executable, otherwise 'java' is looked up on PATH"
    ),
)


class MorpheAdapter(ExternalProcessAdapter):
    """Drives the Morphe Desktop CLI JAR as an external process."""

    modkit_id: ClassVar[str] = MORPHE_MODKIT_ID
    display_name: ClassVar[str] = "Morphe Desktop"
    adapter_version: ClassVar[str] = "0.1.0"
    description: ClassVar[str] = (
        "Third-party APK patching engine (Morphe Patcher), driven via the Morphe Desktop "
        "CLI JAR. APKForge independently validates and verifies every output; Morphe is "
        "never allowed to declare its own output safe."
    )
    trust: ClassVar[TrustLevel] = TrustLevel.EXTERNAL_UNVERIFIED
    license_note: ClassVar[str] = (
        "Morphe Patcher/Desktop is GPL-3.0 licensed with additional branding restrictions. "
        "APKForge does not bundle or redistribute it and grants no redistribution rights; "
        "review Morphe's license before distributing Morphe binaries or patch bundles."
    )
    #: Pinned to 1.20.x; 1.20.0 is the only version verified so far (CLI, list-patches
    #: against the real MorpheApp/morphe-patches bundle, and a live patch run). Widen
    #: only after testing the new version the same way.
    min_version: ClassVar[str | None] = "1.20.0"
    max_version: ClassVar[str | None] = "1.21.0"

    def capabilities(self) -> tuple[ModKitCapability, ...]:
        # H.8.1 verifies availability only; patch execution capabilities are added
        # once H.8.2/H.8.3 implement and verify them.
        return ()

    def operations(self) -> tuple[OperationSpec, ...]:
        return ()

    def requirements(self) -> tuple[Requirement, ...]:
        base = list(super().requirements())
        base.insert(1, _JAVA_REQUIREMENT)
        return tuple(base)

    def toolchain(self) -> dict[str, str]:
        java = self.java_executable()
        if java is None:
            return {}
        major, _detail = self._probe_java_major(java)
        return {"java": str(major)} if major is not None else {}

    # -- Java runtime discovery ----------------------------------------------------

    def java_executable(self) -> Path | None:
        configured = self.config.options.get("java_executable") if self.config else None
        if configured:
            p = Path(configured)
            return p if p.is_absolute() else None
        found = shutil.which("java")
        return Path(found) if found else None

    def _probe_java_major(self, java: Path) -> tuple[int | None, str]:
        try:
            proc = subprocess.run(  # noqa: S603 - absolute path, no shell
                [str(java), "-version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=self.version_timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, f"{type(exc).__name__}: {exc}"
        text = proc.stdout.decode("utf-8", errors="replace")
        m = _JAVA_VERSION_RE.search(text)
        if not m:
            return None, "java -version output did not contain a version"
        major = int(m.group(1))
        if major == 1 and m.group(2):  # legacy "1.8.0_xxx" numbering
            major = int(m.group(2))
        return major, ""

    def dependency_checks(self) -> list[RequirementCheck]:
        java = self.java_executable()
        if java is None:
            return [
                RequirementCheck(
                    requirement=_JAVA_REQUIREMENT,
                    satisfied=False,
                    detail="no Java runtime found ('java' not on PATH and java_executable "
                    "not configured)",
                )
            ]
        major, detail = self._probe_java_major(java)
        if major is None:
            return [
                RequirementCheck(
                    requirement=_JAVA_REQUIREMENT,
                    satisfied=False,
                    observed=str(java),
                    detail=detail,
                )
            ]
        ok = major >= MIN_JAVA_MAJOR
        return [
            RequirementCheck(
                requirement=_JAVA_REQUIREMENT,
                satisfied=ok,
                observed=f"{java} (Java {major})",
                detail="" if ok else f"Java {MIN_JAVA_MAJOR}+ required, found Java {major}",
            )
        ]

    # -- ExternalProcessAdapter contract --------------------------------------------

    def launcher(self, executable: Path) -> list[str]:
        java = self.java_executable()
        return [str(java) if java is not None else "java", "-jar", str(executable)]

    def version_argv(self, executable: Path) -> list[str]:
        return [*self.launcher(executable), "--version"]

    def parse_version(self, text: str) -> str | None:
        m = _VERSION_RE.search(text)
        return m.group(0) if m else None

    def build_command(self, ctx: ExecutionContext) -> CommandSpec:
        raise NotImplementedError("Morphe patch execution is implemented in H.8.3")

    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        return OutputDeclaration()
