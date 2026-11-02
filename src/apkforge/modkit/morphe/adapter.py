"""Adapter for Morphe Desktop (H.8.1: discovery/compatibility; H.8.2: patch bundle
discovery; H.8.3: patch selection and execution).

Morphe Desktop (https://github.com/MorpheApp/morphe-desktop) ships as a JAR run with
``java -jar morphe-desktop.jar ...``; APKForge never bundles or downloads it, the user
configures ``executable_path`` to point at their own copy (see ``docs/modkits.md``).
H.8.1 answers "is it installed, is Java available, what version is it, is that version
supported". H.8.2 adds :meth:`MorpheAdapter.list_patches`, a read-only query of a patch
bundle's contents (``list-patches``) run directly, outside the operation contract. H.8.3
adds the ``patch`` operation: :meth:`capabilities`/:meth:`operations` are no longer
empty, so the framework now drives ``build_command``/``execute``/``collect_output``
through the normal :class:`~apkforge.modkit.executor.ModKitExecutor` lifecycle, the same
as any other adapter.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from apkforge.modkit.contract import ExternalProcessAdapter
from apkforge.modkit.models import (
    ModKitCapability,
    OperationSpec,
    OutputDeclaration,
    ParameterSpec,
    Requirement,
    RequirementCheck,
    RequirementKind,
    TrustLevel,
)
from apkforge.modkit.morphe.patches import PatchBundleListing, parse_patch_listing
from apkforge.modkit.process import INHERITED_ENVIRONMENT, CommandSpec

if TYPE_CHECKING:
    from apkforge.modkit.contract import ExecutionContext

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

#: H.8.3's only operation.
PATCH_OPERATION_ID = "patch"
#: Morphe's own result-file claim is read for diagnostics only (never trusted; see
#: collect_output), so it is capped the same way test-modkit's is.
_RESULT_LIMIT = 64 * 1024
_OUTPUT_NAME = "patched.apk"


def _split_names(value: str) -> list[str]:
    return [n.strip() for n in value.split(",") if n.strip()]


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
        # Verified live: a "Clone app" run actually changed the manifest package
        # name (apkforge/modkit/morphe docs; the H.8.3 live test). Morphe patches
        # can touch dex/resources too, but only this much has been exercised.
        return (
            ModKitCapability.APK_TRANSFORMATION,
            ModKitCapability.PATCH_SELECTION,
            ModKitCapability.MULTI_PATCH,
        )

    def operations(self) -> tuple[OperationSpec, ...]:
        return (
            OperationSpec(
                id=PATCH_OPERATION_ID,
                description="Apply selected patches from a Morphe patch bundle.",
                capabilities=(
                    ModKitCapability.APK_TRANSFORMATION,
                    ModKitCapability.PATCH_SELECTION,
                    ModKitCapability.MULTI_PATCH,
                ),
                parameters=(
                    ParameterSpec(
                        name="patches",
                        description="Local .mpp path or a GitHub/GitLab repo URL.",
                        required=True,
                    ),
                    ParameterSpec(
                        name="enable", description="Comma-separated patch names to enable."
                    ),
                    ParameterSpec(
                        name="disable", description="Comma-separated patch names to disable."
                    ),
                    ParameterSpec(
                        name="exclusive",
                        description="Disable every patch except --enable.",
                        choices=("true", "false"),
                    ),
                    ParameterSpec(
                        name="force",
                        description="Skip the app-version compatibility check.",
                        choices=("true", "false"),
                    ),
                    ParameterSpec(
                        name="prerelease",
                        description="Fetch the latest dev pre-release bundle.",
                        choices=("true", "false"),
                    ),
                ),
                may_be_noop=True,
            ),
        )

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

    def data_dir(self, ctx: ExecutionContext) -> Path:
        """Where Morphe caches downloaded patch bundles for this run.

        Defaults inside the workspace (safe: adapters must not write outside it;
        a fresh bundle download every run is the price). ``modkits.morphe.options.
        data_dir`` (absolute path) opts into a persistent cache across runs instead.
        """
        configured = self.config.options.get("data_dir") if self.config else None
        if configured:
            p = Path(configured)
            if p.is_absolute():
                return p
        return ctx.working_dir / "morphe-data"

    def build_command(self, ctx: ExecutionContext) -> CommandSpec:
        exe = self.executable()
        assert exe is not None
        p = ctx.request.parameters
        argv = [
            *self.launcher(exe),
            PATCH_OPERATION_ID,
            str(ctx.staged_input),
            "--patches", p["patches"],
        ]  # fmt: skip
        for name in _split_names(p.get("enable", "")):
            argv += ["--enable", name]
        for name in _split_names(p.get("disable", "")):
            argv += ["--disable", name]
        if p.get("exclusive") == "true":
            argv.append("--exclusive")
        if p.get("force") == "true":
            argv.append("--force")
        if p.get("prerelease") == "true":
            argv.append("--prerelease")
        argv += [
            # Signing is APKForge's own concern downstream (BuildService); Morphe's
            # self-signed output is never trusted or treated as final.
            "--unsigned",
            "-o", str(ctx.output_dir / _OUTPUT_NAME),
            "-r", str(ctx.working_dir / "result.json"),
        ]  # fmt: skip
        return CommandSpec(
            argv=tuple(argv), environment={"MORPHE_DATA_DIR": str(self.data_dir(ctx))}
        )

    def _result_notes(self, ctx: ExecutionContext) -> tuple[str, ...]:
        """Morphe's own claim about what it did, for diagnostics only (never
        trusted: pass/fail here always comes from the independently validated
        output file, exactly like test-modkit's result.json)."""
        path = ctx.working_dir / "result.json"
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > _RESULT_LIMIT:
                return ()
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ()
        if not isinstance(data, dict):
            return ()
        notes: list[str] = []
        applied = data.get("appliedPatches")
        if isinstance(applied, list):
            notes.append(f"morphe applied: {', '.join(map(str, applied)) or '(none)'}")
        failed = data.get("failedPatches")
        if isinstance(failed, list) and failed:
            notes.append(f"morphe failed: {', '.join(map(str, failed))}")
        return tuple(notes)

    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        candidate = ctx.output_dir / _OUTPUT_NAME
        if not candidate.is_file() or candidate.is_symlink():
            return OutputDeclaration(notes=("morphe did not produce the expected output file",))
        return OutputDeclaration(primary=(_OUTPUT_NAME,), notes=self._result_notes(ctx))

    # -- H.8.2: patch bundle discovery ----------------------------------------------

    #: ``--patches`` on a repo URL makes Morphe download the release asset itself
    #: (the real v2.0.0 MorpheApp/morphe-patches bundle is ~15 MB); version probing's
    #: 30 s default is too short for that.
    patches_timeout: ClassVar[float] = 180.0

    def list_patches(
        self,
        patches: str,
        *,
        package: str | None = None,
        prerelease: bool = False,
        timeout: float | None = None,
    ) -> tuple[PatchBundleListing | None, str]:
        """Query the patches in *patches* (a local ``.mpp`` path or a GitHub/GitLab
        repo URL such as ``https://github.com/MorpheApp/morphe-patches``, which
        Morphe itself resolves and caches). Returns ``(listing, error_detail)``;
        never raises. Read-only: outside the operation contract, so it runs even
        though :meth:`capabilities`/:meth:`operations` are still empty.
        """
        exe = self.executable()
        if exe is None or not exe.exists():
            return None, "morphe executable is not configured or does not exist"
        argv = [
            *self.launcher(exe),
            "list-patches",
            "--patches",
            patches,
            "--with-packages",
            "--with-versions",
        ]
        if package:
            argv += ["--filter-package-name", package]
        if prerelease:
            argv.append("--prerelease")
        env = {k: os.environ[k] for k in (*INHERITED_ENVIRONMENT, *self.inherit_environment)
               if k in os.environ}  # fmt: skip
        if self.config is not None:
            env.update(self.config.environment)
        wait = timeout or self.patches_timeout
        with tempfile.TemporaryDirectory(prefix="apkforge-modkit-morphe-patches-") as tmp:
            env["HOME"] = env["TMPDIR"] = tmp
            try:
                proc = subprocess.run(  # noqa: S603 - argv array, no shell
                    argv,
                    cwd=tmp,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=wait,
                    check=False,
                    start_new_session=True,
                )
            except subprocess.TimeoutExpired:
                return None, f"list-patches timed out after {wait:g} s"
            except OSError as exc:
                return None, f"list-patches failed to start: {type(exc).__name__}: {exc}"
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            return None, detail or f"list-patches exited with {proc.returncode}"
        text = proc.stdout.decode("utf-8", errors="replace")
        return parse_patch_listing(patches, text), ""
