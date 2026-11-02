"""Phase H.8.1 - Morphe Desktop adapter: discovery and compatibility only.

No real Morphe Desktop JAR or JRE is used: a tiny fake ``java`` script stands in for
both ``java -version`` and ``java -jar <jar> --version``, exactly like the reference
``test-modkit`` stands in for a real third-party tool elsewhere in this test suite.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from apkforge.modkit import AvailabilityStatus as A
from apkforge.modkit import ModKitConfig, contract_problems
from apkforge.modkit.morphe import MIN_JAVA_MAJOR, MORPHE_MODKIT_ID, MorpheAdapter

_FAKE_JAVA = """\
#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ["-version"]:
    print('openjdk version "{java_version}.0.1" 2024-01-01', file=sys.stderr)
elif len(args) >= 3 and args[0] == "-jar" and args[2] == "--version":
    print("Morphe Desktop {morphe_version}")
else:
    print(f"unexpected args: {{args}}", file=sys.stderr)
    sys.exit(2)
"""


def _fake_java(tmp_path: Path, *, java_version: int = 21, morphe_version: str = "1.20.0") -> Path:
    p = tmp_path / "fake-java"
    p.write_text(_FAKE_JAVA.format(java_version=java_version, morphe_version=morphe_version))
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


def test_capabilities_and_operations_are_empty_in_h8_1() -> None:
    # No operation is verified yet: the framework can never reach build_command.
    a = MorpheAdapter()
    assert a.capabilities() == () and a.operations() == ()


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


def test_build_command_and_collect_output_are_not_implemented_yet() -> None:
    a = MorpheAdapter()
    with pytest.raises(NotImplementedError):
        a.build_command(None)  # type: ignore[arg-type]
    assert a.collect_output(None).primary == ()  # type: ignore[arg-type]
