"""Adapter for the reference ``test-modkit`` tool (see :mod:`.tool`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from apkforge.modkit.contract import ExternalProcessAdapter
from apkforge.modkit.models import (
    InstallationModel,
    ModKitCapability,
    ModKitIdentity,
    OperationSpec,
    OutputDeclaration,
    ParameterSpec,
    Requirement,
    RequirementCheck,
    RequirementKind,
    TrustLevel,
)
from apkforge.modkit.process import CommandSpec
from apkforge.modkit.testing import tool

if TYPE_CHECKING:
    from apkforge.modkit.contract import ExecutionContext

__all__ = ["TEST_MODKIT_ID", "TOOL_PATH", "TestModKitAdapter"]

TEST_MODKIT_ID = "test-modkit"
TOOL_PATH = Path(tool.__file__).resolve()
_RESULT_LIMIT = 64 * 1024

_RUNTIME = Requirement(
    kind=RequirementKind.RUNTIME,
    name="python runtime",
    description="the reference tool is a Python script run by the current interpreter",
)
_DEPENDENCY = Requirement(
    kind=RequirementKind.FILESYSTEM,
    name="dependency_path",
    description="optional file the configuration says must exist (dependency simulation)",
)


class TestModKitAdapter(ExternalProcessAdapter):
    """Drives :mod:`apkforge.modkit.testing.tool` as an external process."""

    __test__ = False  # not a pytest test class

    modkit_id: ClassVar[str] = TEST_MODKIT_ID
    display_name: ClassVar[str] = "Test ModKit"
    adapter_version: ClassVar[str] = "1.0.0"
    description: ClassVar[str] = (
        "Deterministic reference ModKit for framework tests. Never for production use."
    )
    trust: ClassVar[TrustLevel] = TrustLevel.TEST_ONLY
    license_note: ClassVar[str] = "APKForge's own synthetic test fixture (APKForge license)."
    min_version: ClassVar[str | None] = "1.0.0"
    max_version: ClassVar[str | None] = "2.0.0"

    def identity(self) -> ModKitIdentity:
        configured = self.config is not None and self.config.executable_path is not None
        return (
            super()
            .identity()
            .model_copy(
                update={
                    "installation": (
                        InstallationModel.USER_MANAGED if configured else InstallationModel.BUNDLED
                    )
                }
            )
        )

    def capabilities(self) -> tuple[ModKitCapability, ...]:
        return (ModKitCapability.APK_TRANSFORMATION,)

    def operations(self) -> tuple[OperationSpec, ...]:
        return (
            OperationSpec(
                id="transform",
                description="Add a deterministic marker asset (or simulate a failure mode).",
                capabilities=(ModKitCapability.APK_TRANSFORMATION,),
                parameters=(
                    ParameterSpec(
                        name="scenario",
                        description="success or a simulated failure mode",
                        choices=tool.SCENARIOS,
                    ),
                    ParameterSpec(
                        name="marker",
                        description="text written to the marker asset",
                        pattern=r"[A-Za-z0-9 ._-]{1,64}",
                    ),
                    ParameterSpec(
                        name="api_token",
                        description="dummy secret (exercises masking)",
                        sensitive=True,
                    ),
                ),
                may_be_noop=True,
            ),
        )

    def requirements(self) -> tuple[Requirement, ...]:
        base = list(super().requirements())
        base.insert(1, _RUNTIME)
        if self.config is not None and "dependency_path" in self.config.options:
            base.append(_DEPENDENCY)
        return tuple(base)

    def default_executable(self) -> Path | None:
        return TOOL_PATH

    def launcher(self, executable: Path) -> list[str]:
        return [sys.executable, str(executable)]

    def dependency_checks(self) -> list[RequirementCheck]:
        runtime = Path(sys.executable)
        checks = [
            RequirementCheck(
                requirement=_RUNTIME,
                satisfied=runtime.is_file(),
                observed=f"{runtime} ({sys.version.split()[0]})",
            )
        ]
        dep = self.config.options.get("dependency_path") if self.config else None
        if dep is not None:
            exists = Path(dep).is_absolute() and Path(dep).exists()
            checks.append(
                RequirementCheck(
                    requirement=_DEPENDENCY,
                    satisfied=exists,
                    observed=dep,
                    detail="" if exists else f"{dep} does not exist",
                )
            )
        return checks

    def toolchain(self) -> dict[str, str]:
        return {"test-modkit-runtime": sys.version.split()[0]}

    def version_argv(self, executable: Path) -> list[str]:
        return [*self.launcher(executable), "--version"]

    def parse_version(self, text: str) -> str | None:
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) == 2 and parts[0] == "test-modkit":
                return parts[1]
        return None

    def build_command(self, ctx: ExecutionContext) -> CommandSpec:
        exe = self.executable()
        assert exe is not None
        p = ctx.request.parameters
        argv = [
            *self.launcher(exe),
            "run",
            "--input", str(ctx.staged_input),
            "--output-dir", str(ctx.output_dir),
            "--result", str(ctx.working_dir / "result.json"),
            "--scenario", p.get("scenario", "success"),
            "--marker", p.get("marker", "test-modkit"),
        ]  # fmt: skip
        secrets: tuple[str, ...] = ()
        if "api_token" in p:
            argv += ["--token", p["api_token"]]
            secrets = (p["api_token"],)
        return CommandSpec(argv=tuple(argv), sensitive_values=secrets)

    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        """Read the tool's (untrusted) result claim; malformed claims yield no outputs."""
        path = ctx.working_dir / "result.json"
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > _RESULT_LIMIT:
                return OutputDeclaration(notes=("no usable result.json",))
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return OutputDeclaration(notes=("unreadable result.json",))
        outputs = data.get("outputs") if isinstance(data, dict) else None
        if not isinstance(outputs, list) or not all(isinstance(o, str) for o in outputs):
            return OutputDeclaration(notes=("malformed result.json",))
        return OutputDeclaration(primary=tuple(outputs), declared_no_op=data.get("no_op") is True)
