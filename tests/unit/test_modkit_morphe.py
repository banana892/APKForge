"""Phase H.8.1/H.8.2/H.8.3 - Morphe Desktop adapter: discovery, compatibility, patch
bundle listing, and patch selection/execution.

No real Morphe Desktop JAR or JRE is used: a tiny fake ``java`` script stands in for
``java -version``, ``java -jar <jar> --version``, ``... list-patches`` and
``... patch``, exactly like the reference ``test-modkit`` stands in for a real
third-party tool elsewhere in this test suite.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from apkforge.modkit import AvailabilityStatus as A
from apkforge.modkit import (
    ExecutionRequest,
    ModKitConfig,
    ModKitExecutor,
    ModKitResultStatus,
    contract_problems,
)
from apkforge.modkit import ModKitCapability as A_CAP
from apkforge.modkit.morphe import MIN_JAVA_MAJOR, MORPHE_MODKIT_ID, MorpheAdapter
from tests.fixtures.factory import create_synthetic_apk

# The quirky "INFO: Index: 0" merge and the Compatible-packages block are the real
# shape; see test_modkit_morphe_patches.py for the parser itself.
_FAKE_PATCH_LIST = """\
INFO: Index: 0
Name: Clone app
Description: Universal patch.
Enabled: false

Index: 1
Name: Hide ads
Description: Package-specific patch.
Enabled: true
Compatible packages:
\tPackage name: com.example.app
\tCompatible versions:
\t\t1.0.0
"""

_FAKE_JAVA = """\
#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ["-version"]:
    print('openjdk version "{java_version}.0.1" 2024-01-01', file=sys.stderr)
elif len(args) >= 3 and args[0] == "-jar" and args[2] == "--version":
    print("Morphe Desktop {morphe_version}")
elif len(args) >= 3 and args[0] == "-jar" and args[2] == "list-patches":
    bundle = args[args.index("--patches") + 1]
    if "missing" in bundle:
        print(f"{{bundle}} can not be found", file=sys.stderr)
        sys.exit(2)
    print({fake_patch_list!r}, end="")
elif len(args) >= 3 and args[0] == "-jar" and args[2] == "patch":
    import json
    import zipfile

    rest = args[3:]
    apk_path, patches = rest[0], rest[rest.index("--patches") + 1]
    out_path, result_path = rest[rest.index("-o") + 1], rest[rest.index("-r") + 1]
    enabled = [rest[i + 1] for i, a in enumerate(rest) if a == "--enable"]
    if "missing" in patches:
        print(f"{{patches}} can not be found", file=sys.stderr)
        sys.exit(2)
    if "--unsigned" not in rest:
        print("expected --unsigned", file=sys.stderr)
        sys.exit(2)
    with open(apk_path, "rb") as src, open(out_path, "wb") as dst:
        dst.write(src.read())
    with zipfile.ZipFile(out_path, "a") as zf:
        zf.writestr("assets/morphe-marker.txt", "patched")
    with open(result_path, "w") as f:
        json.dump({{"success": True, "appliedPatches": enabled, "failedPatches": []}}, f)
else:
    print(f"unexpected args: {{args}}", file=sys.stderr)
    sys.exit(2)
"""


def _fake_java(tmp_path: Path, *, java_version: int = 21, morphe_version: str = "1.20.0") -> Path:
    p = tmp_path / "fake-java"
    p.write_text(
        _FAKE_JAVA.format(
            java_version=java_version,
            morphe_version=morphe_version,
            fake_patch_list=_FAKE_PATCH_LIST,
        )
    )
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def _jar(tmp_path: Path) -> Path:
    p = tmp_path / "morphe-desktop.jar"
    p.write_bytes(b"")
    return p


def _config(tmp_path: Path, jar: Path, **extra: object) -> ModKitConfig:
    return ModKitConfig(modkit_id=MORPHE_MODKIT_ID, executable_path=jar, **extra)  # type: ignore[arg-type]


def test_identity_and_contract() -> None:
    a = MorpheAdapter()
    assert a.identity().modkit_id == MORPHE_MODKIT_ID
    assert "GPL" in a.license_note
    assert contract_problems(a, MORPHE_MODKIT_ID) == []


def test_capabilities_and_operations_declared_in_h8_3() -> None:
    a = MorpheAdapter()
    assert set(a.capabilities()) == {
        A_CAP.APK_TRANSFORMATION,
        A_CAP.PATCH_SELECTION,
        A_CAP.MULTI_PATCH,
    }
    ops = a.operations()
    assert [o.id for o in ops] == ["patch"]
    assert {p.name for p in ops[0].parameters} >= {"patches", "enable", "disable"}
    assert contract_problems(a, MORPHE_MODKIT_ID) == []


def test_requirements_cover_executable_java_and_version_bounds() -> None:
    kinds = {r.kind for r in MorpheAdapter().requirements()}
    assert {"EXECUTABLE", "RUNTIME", "MIN_VERSION", "MAX_VERSION"} <= {str(k) for k in kinds}


def test_not_installed_without_executable() -> None:
    assert MorpheAdapter().availability().status is A.NOT_INSTALLED


def test_dependency_missing_without_java(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))  # no 'java' resolvable
    cfg = _config(tmp_path, _jar(tmp_path))
    av = MorpheAdapter(cfg).availability()
    assert av.status is A.DEPENDENCY_MISSING and "java" in av.reason.lower()


def test_java_too_old_is_dependency_missing(tmp_path: Path) -> None:
    java = _fake_java(tmp_path, java_version=17)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    av = MorpheAdapter(cfg).availability()
    assert av.status is A.DEPENDENCY_MISSING
    assert f"Java {MIN_JAVA_MAJOR}+ required" in av.reason


@pytest.mark.parametrize(
    ("morphe_version", "status"),
    [
        ("1.20.0", A.AVAILABLE),
        ("1.20.9", A.AVAILABLE),
        ("1.19.0", A.VERSION_UNSUPPORTED),
        ("1.21.0", A.VERSION_UNSUPPORTED),
        ("1.21.0-dev.5", A.VERSION_UNSUPPORTED),
    ],
)
def test_version_bounds(tmp_path: Path, morphe_version: str, status: A) -> None:
    java = _fake_java(tmp_path, morphe_version=morphe_version)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    av = MorpheAdapter(cfg).availability()
    assert av.status is status and av.installed_version == morphe_version


def test_java_executable_option_overrides_path(tmp_path: Path) -> None:
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    assert MorpheAdapter(cfg).java_executable() == java
    assert MorpheAdapter(cfg).availability().status is A.AVAILABLE


def test_launcher_runs_java_dash_jar(tmp_path: Path) -> None:
    jar = _jar(tmp_path)
    a = MorpheAdapter(_config(tmp_path, jar, options={"java_executable": "/usr/bin/fake-java"}))
    assert a.launcher(jar) == ["/usr/bin/fake-java", "-jar", str(jar)]


def test_relative_java_executable_option_is_ignored(tmp_path: Path) -> None:
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": "java"})
    assert MorpheAdapter(cfg).java_executable() is None


# -- H.8.2: patch bundle discovery -----------------------------------------------


def test_list_patches_parses_fake_cli_output(tmp_path: Path) -> None:
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    listing, err = MorpheAdapter(cfg).list_patches(str(tmp_path / "bundle.mpp"))
    assert err == ""
    assert listing is not None
    assert [p.name for p in listing.patches] == ["Clone app", "Hide ads"]
    assert listing.patches[0].compatible == ()
    assert listing.patches[1].compatible[0].package == "com.example.app"


def test_list_patches_without_executable_configured() -> None:
    listing, err = MorpheAdapter().list_patches("bundle.mpp")
    assert listing is None and "not configured" in err


def test_list_patches_surfaces_tool_error(tmp_path: Path) -> None:
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    listing, err = MorpheAdapter(cfg).list_patches("missing.mpp")
    assert listing is None
    assert "can not be found" in err


def test_list_patches_runs_outside_the_operation_contract(tmp_path: Path) -> None:
    # H.8.2 discovery is a plain method call, not an ExecutionRequest/ModKitExecutor
    # run: no workspace, no build_command/execute/collect_output involved.
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    listing, err = MorpheAdapter(cfg).list_patches(str(tmp_path / "bundle.mpp"))
    assert err == "" and listing is not None and listing.patches


# -- H.8.3: patch selection and execution ----------------------------------------


def _patch_request(apk: Path, tmp_path: Path, **overrides: object) -> ExecutionRequest:
    parameters = {"patches": str(tmp_path / "bundle.mpp"), "enable": "Clone app"}
    parameters.update(overrides.pop("parameters", {}))  # type: ignore[arg-type]
    return ExecutionRequest(
        input_apk=apk,
        output_dir=tmp_path / "out",
        operation="patch",
        parameters=parameters,
        workspace_base=tmp_path / "ws",
        **overrides,  # type: ignore[arg-type]
    )


def test_patch_operation_succeeds_end_to_end(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    result = ModKitExecutor().run(MorpheAdapter(cfg), _patch_request(apk, tmp_path))
    assert result.status is ModKitResultStatus.SUCCESS, result.reason
    assert result.published is not None
    assert result.declaration is not None
    assert any("Clone app" in n for n in result.declaration.notes)


def test_patch_operation_passes_enable_disable_exclusive_force(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    request = _patch_request(
        apk, tmp_path,
        parameters={
            "enable": "Clone app, Hide ads",
            "disable": "Spoof signature",
            "exclusive": "true",
            "force": "true",
        },
    )  # fmt: skip
    result = ModKitExecutor().run(MorpheAdapter(cfg), request)
    assert result.status is ModKitResultStatus.SUCCESS, result.reason
    assert result.provenance is not None and result.provenance.command is not None
    argv = result.provenance.command.argv
    assert argv.count("--enable") == 2
    assert "Clone app" in argv and "Hide ads" in argv
    assert "--disable" in argv and "Spoof signature" in argv
    assert "--exclusive" in argv and "--force" in argv
    assert "--unsigned" in argv


def test_patch_operation_always_unsigned_and_isolates_data_dir(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    result = ModKitExecutor().run(MorpheAdapter(cfg), _patch_request(apk, tmp_path))
    assert result.provenance is not None and result.provenance.command is not None
    command = result.provenance.command
    assert "--unsigned" in command.argv
    # MORPHE_DATA_DIR defaults inside the workspace (never outside it) unless the
    # user opts into a persistent cache via modkits.morphe.options.data_dir.
    data_dir = command.environment["MORPHE_DATA_DIR"]
    assert data_dir.startswith(str(Path(result.workspace_path or "")))


def test_patch_operation_honors_configured_data_dir(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    persistent = tmp_path / "persistent-morphe-cache"
    cfg = _config(
        tmp_path, _jar(tmp_path),
        options={"java_executable": str(java), "data_dir": str(persistent)},
    )  # fmt: skip
    result = ModKitExecutor().run(MorpheAdapter(cfg), _patch_request(apk, tmp_path))
    assert result.status is ModKitResultStatus.SUCCESS, result.reason
    assert result.provenance is not None and result.provenance.command is not None
    assert result.provenance.command.environment["MORPHE_DATA_DIR"] == str(persistent)


def test_patch_operation_surfaces_tool_error(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    request = _patch_request(apk, tmp_path, parameters={"patches": "missing.mpp"})
    result = ModKitExecutor().run(MorpheAdapter(cfg), request)
    assert result.status is ModKitResultStatus.EXECUTION_FAILED
    assert result.outcome is not None
    assert "can not be found" in result.outcome.stderr_tail


def test_patch_operation_requires_patches_parameter(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "in" / "app.apk")
    java = _fake_java(tmp_path)
    cfg = _config(tmp_path, _jar(tmp_path), options={"java_executable": str(java)})
    request = ExecutionRequest(
        input_apk=apk, output_dir=tmp_path / "out", operation="patch",
        parameters={}, workspace_base=tmp_path / "ws",
    )  # fmt: skip
    result = ModKitExecutor().run(MorpheAdapter(cfg), request)
    assert result.status is ModKitResultStatus.INVALID_INPUT
    assert "patches" in result.reason
