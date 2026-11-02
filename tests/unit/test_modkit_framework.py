"""Phase H.7 - generic ModKit framework (contract, config, discovery, execution, security).

Everything runs against the deterministic reference ``test-modkit`` (a real external
process) or small in-test adapters; no third-party ModKit is involved.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.config import WorkspaceSettings
from apkforge.core.exceptions import WorkspaceError
from apkforge.modkit import (
    AvailabilityReport,
    AvailabilityStatus,
    CommandSpec,
    ExecutionContext,
    ExecutionOutcome,
    ExecutionRequest,
    ExternalProcessAdapter,
    FailureCategory,
    ModKitAdapter,
    ModKitCapability,
    ModKitConfig,
    ModKitConfigSet,
    ModKitExecutor,
    ModKitIdentity,
    ModKitManager,
    ModKitProcessRunner,
    ModKitResultStatus,
    ModKitWorkspace,
    OperationSpec,
    OutputDeclaration,
    Requirement,
    TrustLevel,
    contract_problems,
    default_manager,
    load_modkit_config,
    parse_modkit_config,
)
from apkforge.modkit.analysis import compare_findings
from apkforge.modkit.config import CONFIG_ENV_VAR
from apkforge.modkit.manager import TEST_MODKIT_ENV_VAR
from apkforge.modkit.masking import MASK, SecretMasker, is_sensitive_name
from apkforge.modkit.morphe import MORPHE_MODKIT_ID
from apkforge.modkit.process import INHERITED_ENVIRONMENT
from apkforge.modkit.testing import MARKER_ENTRY, SCENARIOS, TEST_MODKIT_ID, TestModKitAdapter
from apkforge.modkit.validation import is_safe_name, validate_apk_archive
from tests.fixtures import create_synthetic_apk

R = ModKitResultStatus
F = FailureCategory
A = AvailabilityStatus
SECRET = "tok-9f8e7d6c5b4a-SECRET"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.delenv(TEST_MODKIT_ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk")


def _manager(config: ModKitConfigSet | None = None, **adapter_kw: Any) -> ModKitManager:
    m = ModKitManager(config, executor=ModKitExecutor())
    m.register(TEST_MODKIT_ID, lambda cfg: TestModKitAdapter(cfg, **adapter_kw))
    return m


def _config(tmp_path: Path, **entry: Any) -> ModKitConfigSet:
    return parse_modkit_config({"modkits": {TEST_MODKIT_ID: entry}}, source=str(tmp_path / "c"))


def _request(
    apk: Path, tmp_path: Path, scenario: str | None = "success", **kw: Any
) -> ExecutionRequest:
    params = {**({"scenario": scenario} if scenario else {}), **kw.pop("parameters", {})}
    return ExecutionRequest(
        input_apk=apk,
        output_dir=kw.pop("output_dir", tmp_path / "out" / (scenario or "library")),
        operation=kw.pop("operation", "transform"),
        parameters=params,
        workspace_base=kw.pop("workspace_base", tmp_path / "ws"),
        **kw,
    )


def _run(apk: Path, tmp_path: Path, scenario: str = "success", manager: ModKitManager | None = None,
         **kw: Any) -> Any:  # fmt: skip
    before = _sha(apk)
    res = (manager or _manager()).execute(TEST_MODKIT_ID, _request(apk, tmp_path, scenario, **kw))
    assert _sha(apk) == before, "the original APK must never change"
    if res.status is not R.SUCCESS:
        assert res.published is None
        out = tmp_path / "out" / scenario
        assert not out.exists() or not any(out.iterdir()), "nothing published on failure"
    return res


def _fake_tool(tmp_path: Path, body: str, name: str = "fake_tool.py") -> Path:
    p = tmp_path / "tools" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ---------------------------------------------------------------------------
# Models / contract
# ---------------------------------------------------------------------------


class TestModels:
    def test_identity_distinguishes_ids_and_versions(self) -> None:
        a = TestModKitAdapter()
        ident = a.identity()
        assert ident.modkit_id == "test-modkit"
        assert ident.display_name == "Test ModKit"
        assert ident.installed_version == "1.0.0"  # what the tool reports
        assert ident.adapter_version == "1.0.0"  # the APKForge adapter code
        assert ident.trust is TrustLevel.TEST_ONLY

    @pytest.mark.parametrize("bad", ["Morphe", "a b", "../x", "-x", "", "x" * 65])
    def test_identity_rejects_bad_ids(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            ModKitIdentity(modkit_id=bad, display_name="x", adapter_version="1")

    def test_request_is_immutable_and_bounded(self, apk: Path, tmp_path: Path) -> None:
        req = _request(apk, tmp_path)
        with pytest.raises(ValidationError):
            req.operation = "other"  # type: ignore[misc]
        with pytest.raises(ValidationError):
            _request(apk, tmp_path, timeout_seconds=0)

    def test_capabilities_are_verified_subset(self) -> None:
        a = TestModKitAdapter()
        assert a.capabilities() == (ModKitCapability.APK_TRANSFORMATION,)
        for op in a.operations():
            assert set(op.capabilities) <= set(a.capabilities())
        assert contract_problems(a, TEST_MODKIT_ID) == []

    def test_adapter_claiming_unverified_capability_is_rejected(self) -> None:
        class Overclaiming(TestModKitAdapter):
            def operations(self) -> tuple[OperationSpec, ...]:
                return (OperationSpec(id="x", capabilities=(ModKitCapability.MULTI_PATCH,)),)

        m = ModKitManager()
        m.register(TEST_MODKIT_ID, Overclaiming)
        assert m.get(TEST_MODKIT_ID) is None
        info = m.info(TEST_MODKIT_ID)
        assert info is not None and info.availability.status is A.EXECUTION_UNAVAILABLE
        assert "unverified capabilities" in info.availability.reason

    def test_adapter_inheriting_secret_env_is_rejected(self) -> None:
        class Leaky(TestModKitAdapter):
            inherit_environment: ClassVar[tuple[str, ...]] = ("GITHUB_TOKEN",)

        assert any("secret" in p for p in contract_problems(Leaky()))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfig:
    def test_valid_entry(self, tmp_path: Path) -> None:
        cs = _config(tmp_path, executable_path=str(tmp_path / "t"), environment={"LOG": "1"},
                     timeout_seconds=5, enabled=False)  # fmt: skip
        cfg = cs.get(TEST_MODKIT_ID)
        assert cfg is not None and not cs.issues
        assert cfg.executable_path == tmp_path / "t" and cfg.timeout_seconds == 5
        assert cfg.enabled is False and cfg.environment == {"LOG": "1"}

    @pytest.mark.parametrize(
        ("entry", "fragment"),
        [
            ({"executable_path": "relative/tool"}, "absolute"),
            ({"environment": {"API_TOKEN": "x"}}, "secret"),
            ({"environment": {"MY_PASSWORD": "x"}}, "secret"),
            ({"environment": {"PATH": "/evil"}}, "controlled by APKForge"),
            ({"environment": {"LD_PRELOAD": "/evil.so"}}, "controlled by APKForge"),
            ({"environment": {"BAD NAME": "x"}}, "invalid environment"),
            ({"environment": {"X": "a\nb"}}, "control characters"),
            ({"options": {"secret_key": "x"}}, "secret"),
            ({"timeout_seconds": 0}, "greater than or equal"),
            ({"unknown_field": 1}, "Extra inputs"),
            ({"executable_path": 5}, "path string"),
        ],
    )
    def test_invalid_entries_are_structured_issues(
        self, tmp_path: Path, entry: dict[str, Any], fragment: str
    ) -> None:
        cs = _config(tmp_path, **entry)
        assert cs.get(TEST_MODKIT_ID) is None
        issues = cs.issues_for(TEST_MODKIT_ID)
        assert issues and any(fragment in str(i) for i in issues), issues
        assert TEST_MODKIT_ID in cs.ids()

    def test_bad_id_and_shape(self) -> None:
        cs = parse_modkit_config({"modkits": {"Bad_ID": {}, "ok-kit": "nope"}, "other": 1})
        msgs = [str(i) for i in cs.issues]
        assert any("unknown top-level" in m for m in msgs)
        assert any("Bad_ID" in m for m in msgs) and any("must be a table" in m for m in msgs)

    def test_file_loading(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        assert load_modkit_config() == ModKitConfigSet()  # nothing configured is valid
        missing = load_modkit_config(tmp_path / "nope.toml")
        assert missing.issues and "does not exist" in str(missing.issues[0])
        broken = tmp_path / "broken.toml"
        broken.write_text("[modkits\n")
        assert "cannot parse" in str(load_modkit_config(broken).issues[0])
        good = tmp_path / "good.toml"
        good.write_text('[modkits.example-kit]\nexecutable_path = "/opt/example/kit"\n')
        link = tmp_path / "link.toml"
        link.symlink_to(good)
        assert "not a regular file" in str(load_modkit_config(link).issues[0])
        monkeypatch.setenv(CONFIG_ENV_VAR, str(good))
        loaded = load_modkit_config()
        assert loaded.source == str(good) and loaded.ids() == ["example-kit"]
        monkeypatch.delenv(CONFIG_ENV_VAR)
        xdg = tmp_path / "xdg" / "apkforge"
        xdg.mkdir(parents=True)
        (xdg / "modkits.toml").write_text(good.read_text())
        assert load_modkit_config().ids() == ["example-kit"]


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


class TestAvailability:
    def test_reference_modkit_available(self) -> None:
        av = TestModKitAdapter().availability()
        assert av.status is A.AVAILABLE and av.installed_version == "1.0.0"
        assert all(c.satisfied for c in av.checks)

    def test_not_installed(self, tmp_path: Path) -> None:
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=tmp_path / "missing.py")
        av = TestModKitAdapter(cfg).availability()
        assert av.status is A.NOT_INSTALLED and av.installed_version is None

    def test_installed_but_dependency_missing_is_not_not_installed(self, tmp_path: Path) -> None:
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID,
                           options={"dependency_path": str(tmp_path / "jre")})  # fmt: skip
        av = TestModKitAdapter(cfg).availability()
        assert av.status is A.DEPENDENCY_MISSING
        assert "dependency_path" in av.reason
        (tmp_path / "jre").mkdir()
        assert TestModKitAdapter(cfg).availability().status is A.AVAILABLE

    @pytest.mark.parametrize("version", ["0.9.0", "2.0.0", "3.1"])
    def test_version_unsupported(self, tmp_path: Path, version: str) -> None:
        tool = _fake_tool(tmp_path, f"print('test-modkit {version}')\n")
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=tool)
        av = TestModKitAdapter(cfg).availability()
        assert av.status is A.VERSION_UNSUPPORTED and av.installed_version == version

    @pytest.mark.parametrize(
        "body", ["print('no version here')\n", "import sys; sys.exit(4)\n", "raise SystemExit(1)\n"]
    )
    def test_version_not_reported(self, tmp_path: Path, body: str) -> None:
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=_fake_tool(tmp_path, body))
        av = TestModKitAdapter(cfg).availability()
        assert av.status is A.EXECUTION_UNAVAILABLE and "version" in av.reason

    def test_disabled_and_directory(self, tmp_path: Path) -> None:
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID, enabled=False)
        assert TestModKitAdapter(cfg).availability().status is A.EXECUTION_UNAVAILABLE
        cfg = ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=tmp_path)
        assert TestModKitAdapter(cfg).availability().status is A.EXECUTION_UNAVAILABLE

    def test_native_executable_needs_exec_bit(self, tmp_path: Path) -> None:
        exe = _fake_tool(tmp_path, "#!/bin/sh\necho 'plain-kit 1.0.0'\n", "plain-kit")
        cfg = ModKitConfig(modkit_id="plain-kit", executable_path=exe)
        assert PlainKit(cfg).availability().status is A.EXECUTION_UNAVAILABLE
        exe.chmod(0o755)
        av = PlainKit(cfg).availability()
        assert av.status is A.AVAILABLE and av.installed_version == "1.0.0"

    def test_no_executable_configured(self) -> None:
        assert PlainKit().availability().status is A.NOT_INSTALLED


class PlainKit(ExternalProcessAdapter):
    """Minimal pure external adapter (argv[0] is the executable itself)."""

    modkit_id: ClassVar[str] = "plain-kit"
    display_name: ClassVar[str] = "Plain Kit"
    adapter_version: ClassVar[str] = "0.1.0"

    def capabilities(self) -> tuple[ModKitCapability, ...]:
        return ()

    def operations(self) -> tuple[OperationSpec, ...]:
        return ()

    def version_argv(self, executable: Path) -> list[str]:
        return [str(executable)]

    def parse_version(self, text: str) -> str | None:
        return text.split()[-1] if text.startswith("plain-kit") else None

    def build_command(self, ctx: ExecutionContext) -> CommandSpec:
        raise NotImplementedError

    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        return OutputDeclaration()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_deterministic_sorted_discovery(self) -> None:
        cs = parse_modkit_config({"modkits": {"c-kit": {}, "a-kit": {"enabled": False}}})
        m = ModKitManager(cs)
        m.register("b-kit", lambda cfg: PlainKit(cfg))
        m.register(TEST_MODKIT_ID, TestModKitAdapter)
        first = m.discover()
        assert [i.identity.modkit_id for i in first] == ["a-kit", "b-kit", "c-kit", TEST_MODKIT_ID]
        assert m.discover() == first == m.list()

    def test_configuration_without_adapter_is_never_available(self) -> None:
        cs = parse_modkit_config({"modkits": {"example-kit": {"executable_path": sys.executable}}})
        info = ModKitManager(cs).info("example-kit")
        assert info is not None and not info.adapter_registered
        assert info.availability.status is A.CONFIGURATION_INVALID
        assert info.identity.installed_version is None and info.capabilities == ()

    def test_config_issue_blocks_probe(self, tmp_path: Path) -> None:
        m = _manager(_config(tmp_path, environment={"SESSION_TOKEN": "x"}))
        info = m.info(TEST_MODKIT_ID)
        assert info is not None and info.availability.status is A.CONFIGURATION_INVALID
        assert info.config_errors

    def test_default_manager_registers_test_modkit_only_on_request(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # morphe (H.8.1) is always registered but unconfigured, so NOT_INSTALLED.
        assert [i.identity.modkit_id for i in default_manager().discover()] == [MORPHE_MODKIT_ID]
        morphe_info = default_manager().info(MORPHE_MODKIT_ID)
        assert morphe_info is not None and morphe_info.availability.status is A.NOT_INSTALLED
        monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
        assert [i.identity.modkit_id for i in default_manager().discover()] == [
            MORPHE_MODKIT_ID,
            TEST_MODKIT_ID,
        ]
        monkeypatch.delenv(TEST_MODKIT_ENV_VAR)
        cfg = tmp_path / "c.toml"
        cfg.write_text("[modkits.test-modkit]\nenabled = true\n")
        assert default_manager(cfg).registered_ids() == [MORPHE_MODKIT_ID, TEST_MODKIT_ID]

    def test_duplicate_and_invalid_registration(self) -> None:
        m = _manager()
        with pytest.raises(ValueError, match="already registered"):
            m.register(TEST_MODKIT_ID, TestModKitAdapter)
        with pytest.raises(ValueError, match="invalid"):
            m.register("Bad Id", TestModKitAdapter)

    def test_unknown_modkit_execution(self, apk: Path, tmp_path: Path) -> None:
        res = ModKitManager().execute("nope", _request(apk, tmp_path))
        assert res.status is R.NOT_AVAILABLE


# ---------------------------------------------------------------------------
# Execution scenarios (reference ModKit as a real external process)
# ---------------------------------------------------------------------------

EXPECTED: dict[str, tuple[ModKitResultStatus, FailureCategory | None]] = {
    "success": (R.SUCCESS, None),
    "noop": (R.NO_OP, None),
    "noop-empty": (R.NO_OP, None),
    "noop-undeclared": (R.OUTPUT_INVALID, F.OUTPUT_UNCHANGED),
    "missing-output": (R.OUTPUT_MISSING, F.OUTPUT_MISSING),
    "no-declaration": (R.OUTPUT_INVALID, F.UNEXPECTED_ARTIFACT),
    "invalid-apk": (R.OUTPUT_INVALID, F.OUTPUT_MALFORMED),
    "truncated-apk": (R.OUTPUT_INVALID, F.OUTPUT_MALFORMED),
    "nonzero-exit": (R.EXECUTION_FAILED, F.NON_ZERO_EXIT),
    "crash": (R.EXECUTION_FAILED, F.PROCESS_CRASH),
    "multiple-outputs": (R.OUTPUT_INVALID, F.OUTPUT_AMBIGUOUS),
    "extra-artifact": (R.OUTPUT_INVALID, F.UNEXPECTED_ARTIFACT),
    "outside-workspace": (R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE),
    "outside-undeclared": (R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE),
    "symlink-escape": (R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE),
    "malicious-filename": (R.OUTPUT_INVALID, F.UNSAFE_FILENAME),
    "traversal-entry": (R.OUTPUT_INVALID, F.OUTPUT_MALFORMED),
    "directory-output": (R.OUTPUT_INVALID, F.OUTPUT_NOT_REGULAR_FILE),
    "mutate-input": (R.EXECUTION_FAILED, F.INPUT_MUTATED),
    "noisy": (R.SUCCESS, None),
    "echo-env": (R.SUCCESS, None),
    "echo-args": (R.SUCCESS, None),
    "replace-output-dir": (R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE),
}


def test_every_tool_scenario_has_an_expectation() -> None:
    assert set(EXPECTED) | {"timeout"} == set(SCENARIOS)


@pytest.mark.parametrize("scenario", sorted(EXPECTED))
def test_scenario(apk: Path, tmp_path: Path, scenario: str) -> None:
    status, failure = EXPECTED[scenario]
    res = _run(apk, tmp_path, scenario)
    assert (res.status, res.failure) == (status, failure), res.reason
    assert res.original is not None and res.original.sha256 == _sha(apk)
    assert res.original_unchanged is True
    assert res.provenance is not None and res.provenance.input_sha256 == _sha(apk)
    assert res.outcome is not None and res.outcome.command is not None


def test_success_output_is_published_under_apkforge_name(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path)
    assert res.status is R.SUCCESS and res.published is not None
    out = Path(res.published.path)
    assert out == (tmp_path / "out" / "success" / "app.test-modkit.apk").resolve()
    assert _sha(out) == res.published.sha256 == res.provenance.output_sha256  # type: ignore[union-attr]
    assert res.candidate is not None and res.candidate.sha256 == res.published.sha256
    with zipfile.ZipFile(out) as zf:
        assert zf.read(MARKER_ENTRY) == b"test-modkit"
    ids = [c.id for c in res.validation]
    assert {"apk_archive_valid", "no_unexpected_artifacts", "published_sha256_verified"} <= set(ids)
    assert all(c.passed for c in res.validation)
    assert list(out.parent.iterdir()) == [out]  # no partial/temporary files left behind


def test_noop_publishes_nothing(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, "noop")
    assert res.status is R.NO_OP and res.published is None
    assert res.provenance is not None and res.provenance.output_sha256 == _sha(apk)


def test_unchanged_output_accepted_when_no_change_expected(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, "noop-undeclared", expect_change=False)
    assert res.status is R.NO_OP


def test_timeout_kills_process(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, "timeout", timeout_seconds=1)
    assert (res.status, res.failure) == (R.TIMEOUT, F.TIMEOUT)
    assert res.outcome is not None and res.outcome.timed_out
    assert res.outcome.duration_seconds < 30


def test_configured_timeout_is_used(apk: Path, tmp_path: Path) -> None:
    m = _manager(_config(tmp_path, timeout_seconds=1))
    res = _run(apk, tmp_path, "timeout", manager=m)
    assert res.status is R.TIMEOUT


def test_no_automatic_retry(apk: Path, tmp_path: Path) -> None:
    calls: list[str] = []

    class Counting(TestModKitAdapter):
        def execute(self, ctx: ExecutionContext) -> ExecutionOutcome:
            calls.append(ctx.execution_id)
            return super().execute(ctx)

    m = ModKitManager()
    m.register(TEST_MODKIT_ID, Counting)
    for scenario in ("nonzero-exit", "crash", "invalid-apk"):
        res = _run(apk, tmp_path, scenario, manager=m)
        assert not res.succeeded
    assert len(calls) == 3 and len(set(calls)) == 3


def test_noisy_output_is_captured_and_ansi_free(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, "noisy", keep_workspace=True)
    o = res.outcome
    assert res.status is R.SUCCESS and o is not None
    assert o.stdout_bytes > 10_000 and o.stderr_bytes > 10_000
    assert "\x1b" not in o.stdout_tail + o.stderr_tail and "progress 1999" in o.stdout_tail
    assert o.stdout_log is not None and Path(o.stdout_log).stat().st_size == o.stdout_bytes


def test_output_size_limit(apk: Path, tmp_path: Path) -> None:
    m = _manager(runner=ModKitProcessRunner(max_log_bytes=2_000))
    res = _run(apk, tmp_path, "noisy", manager=m)
    assert (res.status, res.failure) == (R.EXECUTION_FAILED, F.RESOURCE_LIMIT)


# ---------------------------------------------------------------------------
# Request / input validation and availability gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "fragment"),
    [
        ({"operation": "explode"}, "unknown operation"),
        ({"parameters": {"bogus": "1"}}, "unknown parameter"),
        ({"parameters": {"scenario": "rm -rf"}}, "must be one of"),
        ({"parameters": {"marker": "$(touch pwned); `id`"}}, "invalid value"),
        ({"parameters": {"marker": "a\nb"}}, "invalid value"),
        ({"capabilities": (ModKitCapability.DEX_TRANSFORMATION,)}, "does not provide"),
        ({"output_name": "../escape.apk"}, "plain"),
        ({"output_name": "x.txt"}, "plain"),
    ],
)
def test_invalid_requests(apk: Path, tmp_path: Path, kw: dict[str, Any], fragment: str) -> None:
    res = _run(apk, tmp_path, **kw)
    assert (res.status, res.failure) == (R.INVALID_INPUT, F.INVALID_REQUEST), res.reason
    assert fragment in res.reason
    assert not (tmp_path / "ws").exists(), "no workspace before the request is valid"


def test_invalid_inputs(tmp_path: Path) -> None:
    not_apk = tmp_path / "x.apk"
    not_apk.write_text("plain text")
    no_manifest = tmp_path / "y.apk"
    with zipfile.ZipFile(no_manifest, "w") as zf:
        zf.writestr("classes.dex", b"dex")
    for bad in (not_apk, no_manifest, tmp_path / "missing.apk", tmp_path):
        res = _manager().execute(TEST_MODKIT_ID, _request(bad, tmp_path))
        assert (res.status, res.failure) == (R.INVALID_INPUT, F.INVALID_INPUT), bad


def test_refuses_to_overwrite_existing_output(apk: Path, tmp_path: Path) -> None:
    dest = tmp_path / "out" / "success" / "app.test-modkit.apk"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"precious")
    res = _manager().execute(TEST_MODKIT_ID, _request(apk, tmp_path))
    assert res.status is R.INVALID_INPUT and "overwrite" in res.reason
    assert dest.read_bytes() == b"precious"


@pytest.mark.parametrize(
    ("entry", "status"),
    [
        ({"options": {"dependency_path": "/nonexistent/apkforge-dep"}}, R.DEPENDENCY_ERROR),
        ({"environment": {"DB_PASSWORD": "x"}}, R.CONFIGURATION_ERROR),
        ({"executable_path": "/nonexistent/test-modkit.py"}, R.NOT_AVAILABLE),
        ({"enabled": False}, R.NOT_AVAILABLE),
    ],
)
def test_unavailable_modkit_is_not_executed(
    apk: Path, tmp_path: Path, entry: dict[str, Any], status: ModKitResultStatus
) -> None:
    res = _run(apk, tmp_path, manager=_manager(_config(tmp_path, **entry)))
    assert res.status is status and res.outcome is None
    assert not (tmp_path / "ws").exists()


def test_version_mismatch_is_not_executed(apk: Path, tmp_path: Path) -> None:
    tool = _fake_tool(tmp_path, "print('test-modkit 0.1.0')\n")
    res = _run(apk, tmp_path, manager=_manager(_config(tmp_path, executable_path=str(tool))))
    assert res.status is R.NOT_AVAILABLE and "VERSION_UNSUPPORTED" in res.reason


# ---------------------------------------------------------------------------
# Workspace isolation
# ---------------------------------------------------------------------------


class TestWorkspace:
    def test_layout_and_read_only_staging(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, keep_workspace=True)
        ws = Path(res.workspace_path)
        assert res.workspace_retained
        assert sorted(p.name for p in ws.iterdir()) == [
            "input", "logs", "metadata", "output", "working",
        ]  # fmt: skip
        staged = ws / "input" / "input.apk"
        assert _sha(staged) == _sha(apk) == res.staged_input.sha256  # type: ignore[union-attr]
        assert stat.S_IMODE(staged.stat().st_mode) == 0o444
        assert {"request.json", "result.json", "provenance.json"} <= {
            p.name for p in (ws / "metadata").iterdir()
        }
        assert {"stdout.log", "stderr.log", "execution.log"} <= {
            p.name for p in (ws / "logs").iterdir()
        }
        assert res.outcome.command.cwd == str(ws / "working")  # type: ignore[union-attr]

    def test_fresh_workspace_per_execution(self, apk: Path, tmp_path: Path) -> None:
        a = _run(apk, tmp_path, "nonzero-exit")
        b = _run(apk, tmp_path, "nonzero-exit")
        assert a.execution_id != b.execution_id and a.workspace_path != b.workspace_path

    def test_retention(self, apk: Path, tmp_path: Path) -> None:
        ok = _run(apk, tmp_path)
        assert not ok.workspace_retained
        assert sorted(p.name for p in Path(ok.workspace_path).iterdir()) == ["logs", "metadata"]
        failed = _run(apk, tmp_path, "nonzero-exit")
        assert failed.workspace_retained  # keep_on_failure (default) for diagnosis
        ex = ModKitExecutor(workspace_settings=WorkspaceSettings(keep_on_failure=False))
        m = ModKitManager(executor=ex)
        m.register(TEST_MODKIT_ID, TestModKitAdapter)
        dropped = _run(apk, tmp_path, "mutate-input", manager=m)
        assert not dropped.workspace_retained
        assert sorted(p.name for p in Path(dropped.workspace_path).iterdir()) == [
            "logs", "metadata",
        ]  # fmt: skip

    def test_workspace_base_from_config(self, apk: Path, tmp_path: Path) -> None:
        base = tmp_path / "configured-base"
        m = _manager(_config(tmp_path, working_directory=str(base)))
        res = m.execute(TEST_MODKIT_ID, _request(apk, tmp_path, workspace_base=None))
        assert res.status is R.SUCCESS and Path(res.workspace_path).parent == base.resolve()

    def test_ids_and_paths_cannot_escape(self, tmp_path: Path) -> None:
        for bad in ("../x", "a/b", ".hidden", ""):
            with pytest.raises(WorkspaceError):
                ModKitWorkspace.create(tmp_path, bad or "..")
        ws = ModKitWorkspace.create(tmp_path)
        with pytest.raises(WorkspaceError):
            ws.subpath("..", "escape")
        with pytest.raises(WorkspaceError):
            ws.subpath("/etc/passwd")
        with pytest.raises(WorkspaceError):
            ModKitWorkspace.create(tmp_path, ws.execution_id)  # never reused

    def test_staging_mismatch_aborts(
        self, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import apkforge.modkit.workspace as wsmod

        def corrupt(src: Path, dst: Path, **_: Any) -> None:
            Path(dst).write_bytes(Path(src).read_bytes() + b"x")

        monkeypatch.setattr(wsmod.shutil, "copyfile", corrupt)
        res = _run(apk, tmp_path)
        assert (res.status, res.failure) == (R.EXECUTION_FAILED, F.STAGING_MISMATCH)
        assert res.outcome is None


# ---------------------------------------------------------------------------
# Library-style adapters (in-process) and adapter faults
# ---------------------------------------------------------------------------


class LibraryKit(ModKitAdapter):
    """In-process adapter: proves the contract does not assume a subprocess."""

    modkit_id: ClassVar[str] = "library-kit"
    display_name: ClassVar[str] = "Library Kit"
    adapter_version: ClassVar[str] = "0.1.0"
    mode: ClassVar[str] = "ok"
    cleaned: ClassVar[list[str]] = []

    def capabilities(self) -> tuple[ModKitCapability, ...]:
        return (ModKitCapability.RESOURCE_TRANSFORMATION,)

    def operations(self) -> tuple[OperationSpec, ...]:
        return (OperationSpec(id="transform", capabilities=self.capabilities()),)

    def requirements(self) -> tuple[Requirement, ...]:
        return ()

    def check_availability(self) -> AvailabilityReport:
        return AvailabilityReport(status=A.AVAILABLE, installed_version="0.1.0")

    def execute(self, ctx: ExecutionContext) -> ExecutionOutcome:
        if self.mode == "raise":
            raise RuntimeError("library blew up")
        if self.mode == "touch-original":
            with ctx.request.input_apk.open("ab") as f:
                f.write(b"!")
        with zipfile.ZipFile(ctx.staged_input) as zin, \
                zipfile.ZipFile(ctx.output_dir / "out.apk", "w") as zout:  # fmt: skip
            for info in zin.infolist():
                zout.writestr(info, zin.read(info))
            zout.writestr("res/raw/added.txt", b"added")
        return ExecutionOutcome(exit_code=0)

    def collect_output(self, ctx: ExecutionContext) -> OutputDeclaration:
        if self.mode == "collect-raise":
            raise ValueError("cannot collect")
        return OutputDeclaration(primary=("out.apk",))

    def cleanup(self, ctx: ExecutionContext) -> None:
        self.cleaned.append(ctx.execution_id)
        if self.mode == "cleanup-raise":
            raise OSError("cleanup failed")


@pytest.mark.parametrize(
    ("mode", "status", "failure"),
    [
        ("ok", R.SUCCESS, None),
        ("raise", R.EXECUTION_FAILED, F.ADAPTER_ERROR),
        ("collect-raise", R.OUTPUT_INVALID, F.ADAPTER_ERROR),
        ("touch-original", R.EXECUTION_FAILED, F.ORIGINAL_MUTATED),
        ("cleanup-raise", R.SUCCESS, None),
    ],
)
def test_library_adapter(
    apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
    status: ModKitResultStatus, failure: FailureCategory | None,
) -> None:  # fmt: skip
    monkeypatch.setattr(LibraryKit, "mode", mode)
    LibraryKit.cleaned.clear()
    m = ModKitManager()
    m.register("library-kit", LibraryKit)
    res = m.execute("library-kit", _request(apk, tmp_path, None))
    assert (res.status, res.failure) == (status, failure), res.reason
    assert LibraryKit.cleaned == [res.execution_id], "cleanup always runs exactly once"
    assert res.outcome is not None and res.outcome.command is None
    if mode == "cleanup-raise":
        assert any("cleanup failed" in m for m in res.messages)
    if mode == "touch-original":
        assert res.original_unchanged is False


# ---------------------------------------------------------------------------
# Security: injection, env leakage, secret masking, paths, archives
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_no_shell_interpretation(self, apk: Path, tmp_path: Path) -> None:
        payload = "$(touch PWNED1); `touch PWNED2` && touch PWNED3 | x > PWNED4"
        res = _run(apk, tmp_path, "echo-args", parameters={"api_token": payload},
                   keep_workspace=True)  # fmt: skip
        assert res.status is R.SUCCESS
        ws = Path(res.workspace_path)
        assert not list(tmp_path.rglob("PWNED*"))
        assert not list(ws.rglob("PWNED*"))

    def test_malicious_filename_not_executed_or_published(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, "malicious-filename")
        assert res.failure is F.UNSAFE_FILENAME
        assert not list(tmp_path.rglob("pwned"))

    def test_parent_environment_does_not_leak(
        self, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APKFORGE_KEYSTORE_PASSWORD", "leak-me-keystore")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me-aws")
        monkeypatch.setenv("UNRELATED_VARIABLE", "leak-me-plain")
        m = _manager(_config(tmp_path, environment={"KIT_LOG_LEVEL": "debug"}))
        res = _run(apk, tmp_path, "echo-env", manager=m, keep_workspace=True)
        ws = Path(res.workspace_path)
        child_env = json.loads((ws / "logs" / "stdout.log").read_text())
        allowed = {*INHERITED_ENVIRONMENT, "HOME", "TMPDIR", "KIT_LOG_LEVEL"}
        assert set(child_env) <= allowed | {"PWD", "LC_CTYPE", "PYTHONHASHSEED"}
        assert child_env["HOME"].startswith(str(ws)) and child_env["TMPDIR"].startswith(str(ws))
        assert child_env["KIT_LOG_LEVEL"] == "debug"
        everything = res.to_json() + "".join(
            p.read_text(errors="replace") for p in ws.rglob("*") if p.is_file() and
            p.suffix in (".log", ".json")
        )  # fmt: skip
        assert "leak-me" not in everything

    def test_secret_parameter_masked_everywhere(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, "echo-args", parameters={"api_token": SECRET},
                   keep_workspace=True)  # fmt: skip
        assert res.status is R.SUCCESS
        ws = Path(res.workspace_path)
        # the tool really received the secret (it echoed argv) ...
        assert MASK in (ws / "logs" / "stdout.log").read_text()
        # ... but no record, log or metadata file contains it
        files = [p for p in ws.rglob("*") if p.is_file() and p.suffix in (".log", ".json")]
        assert files
        for p in files:
            assert SECRET not in p.read_text(errors="replace"), p
        assert SECRET not in res.to_json()
        cmd = res.outcome.command  # type: ignore[union-attr]
        assert cmd is not None and cmd.masked_arguments == 1 and MASK in cmd.argv
        assert res.provenance.parameters["api_token"] == MASK  # type: ignore[union-attr]

    def test_masker(self) -> None:
        m = SecretMasker(["hunter2-secret"])
        argv, n = m.argv(["tool", "--password", "pw1", "--ks-pass=pw2", "token=pw3",
                          "--name", "x-hunter2-secret-y", "--verbose"])  # fmt: skip
        assert argv == ["tool", "--password", MASK, f"--ks-pass={MASK}", f"token={MASK}",
                        "--name", f"x-{MASK}-y", "--verbose"]  # fmt: skip
        assert n == 4
        env, names = m.environment({"GITHUB_TOKEN": "a", "PLAIN": "b", "X": "hunter2-secret"})
        assert env == {"GITHUB_TOKEN": MASK, "PLAIN": "b", "X": MASK}
        assert names == ["GITHUB_TOKEN", "X"]
        assert is_sensitive_name("db_password") and not is_sensitive_name("marker")

    @pytest.mark.parametrize(
        ("name", "ok"),
        [
            ("patched.apk", True), ("sub/patched.apk", True), ("../x.apk", False),
            ("/abs.apk", False), (".hidden", False), ("a\\b.apk", False),
            ("evil\n.apk", False), ("$(x).apk", False), ("a/../b.apk", False), ("", False),
        ],
    )  # fmt: skip
    def test_safe_names(self, name: str, ok: bool) -> None:
        assert is_safe_name(name) is ok

    def test_archive_validation(self, apk: Path, tmp_path: Path) -> None:
        assert validate_apk_archive(apk) == []
        empty = tmp_path / "e.apk"
        empty.write_bytes(b"")
        assert validate_apk_archive(empty) == ["empty file"]
        slip = tmp_path / "s.apk"
        with zipfile.ZipFile(slip, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"m")
            zf.writestr("/etc/cron.d/x", b"x")
        assert any("unsafe entry" in p for p in validate_apk_archive(slip))

    def test_process_runner_failures(self, tmp_path: Path) -> None:
        ws = ModKitWorkspace.create(tmp_path / "ws")
        runner = ModKitProcessRunner()
        missing = runner.run(CommandSpec(argv=(str(tmp_path / "nope"),)), ws, timeout_seconds=5)
        assert missing.error is F.MISSING_EXECUTABLE
        noexec = tmp_path / "noexec"
        noexec.write_text("#!/bin/sh\n")
        denied = runner.run(CommandSpec(argv=(str(noexec),)), ws, timeout_seconds=5)
        assert denied.error is F.PERMISSION_DENIED
        relative = runner.run(CommandSpec(argv=("python3", "-c", "1")), ws, timeout_seconds=5)
        assert relative.error is F.ADAPTER_ERROR and "absolute" in relative.error_detail
        nul = runner.run(CommandSpec(argv=(sys.executable, "a\x00b")), ws, timeout_seconds=5)
        assert nul.error is F.ADAPTER_ERROR
        ok = runner.run(CommandSpec(argv=(sys.executable, "-c", "print('hi')")), ws,
                        timeout_seconds=30)  # fmt: skip
        assert ok.error is None and ok.exit_code == 0 and ok.stdout_tail.strip() == "hi"


# ---------------------------------------------------------------------------
# Reproducibility and provenance
# ---------------------------------------------------------------------------


def _normalised_provenance(res: Any) -> dict[str, Any]:
    data = res.provenance.model_dump(mode="json")
    ws = data["workspace_path"]
    for k in ("execution_id", "workspace_id", "workspace_path", "start_time", "end_time"):
        data.pop(k)
    text = json.dumps(data, sort_keys=True).replace(ws, "<WS>")
    return json.loads(text)  # type: ignore[no-any-return]


def test_reproducible_execution(apk: Path, tmp_path: Path) -> None:
    a = _run(apk, tmp_path, output_dir=tmp_path / "a")
    b = _run(apk, tmp_path, output_dir=tmp_path / "b")
    assert a.status is b.status is R.SUCCESS
    assert a.execution_id != b.execution_id
    # deterministic transformation: identical published bytes
    assert a.published.sha256 == b.published.sha256  # type: ignore[union-attr]
    assert _normalised_provenance(a) == _normalised_provenance(b)
    assert [c.id for c in a.validation] == [c.id for c in b.validation]


def test_provenance_fields(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, parameters={"marker": "hello"})
    p = res.provenance
    assert p is not None
    assert (p.modkit_id, p.modkit_version, p.adapter_version) == ("test-modkit", "1.0.0", "1.0.0")
    assert p.requested_operation == "transform"
    assert p.capabilities == (ModKitCapability.APK_TRANSFORMATION,)
    assert p.parameters == {"marker": "hello", "scenario": "success"}
    assert p.input_sha256 == _sha(apk) and p.input_size == apk.stat().st_size
    assert p.output_sha256 == res.published.sha256 and p.exit_code == 0  # type: ignore[union-attr]
    assert p.start_time <= p.end_time and p.workspace_id == res.execution_id
    assert p.toolchain["test-modkit-runtime"] and p.command is not None
    assert p.command.argv[0] == sys.executable


def test_two_modkits_are_independent_transformations(apk: Path, tmp_path: Path) -> None:
    """Conflict-model foundation: two ModKits are two separate results; nothing chains."""
    m = _manager()
    m.register("library-kit", LibraryKit)
    a = m.execute(TEST_MODKIT_ID, _request(apk, tmp_path, output_dir=tmp_path / "a"))
    b = m.execute("library-kit", _request(apk, tmp_path, None, output_dir=tmp_path / "b"))
    assert a.status is b.status is R.SUCCESS
    # both consumed the *original*, neither the other's output
    assert a.original.sha256 == b.original.sha256 == _sha(apk)  # type: ignore[union-attr]
    assert a.published.sha256 != b.published.sha256  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Finding comparison (Phase F reuse)
# ---------------------------------------------------------------------------


def _finding(fid: str, sev: str = "low", ev: tuple[str, ...] = ()) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(id=fid, severity=sev, confidence="high", evidence_values=list(ev))


def test_compare_findings() -> None:
    before = [_finding("A"), _finding("B"), _finding("C", ev=("x",)), _finding("D"), _finding("D")]
    after = [_finding("B"), _finding("C", ev=("y",)), _finding("D"), _finding("E")]
    d = compare_findings("privacy", before, after, status_before="complete",
                         status_after="complete")  # fmt: skip
    assert d.removed == ("A", "D#2") and d.introduced == ("E",)
    assert d.retained == ("B", "C", "D") and d.changed == ("C",) and d.complete
    partial = compare_findings("privacy", before, after, status_before="complete",
                               status_after="partial")  # fmt: skip
    assert not partial.complete and partial.limitations


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

runner = CliRunner()


def test_cli_modkits_empty() -> None:
    # morphe (H.8.1) is always registered, so the list is never empty, just NOT_INSTALLED.
    res = runner.invoke(app, ["modkits", "--json"])
    data = json.loads(res.stdout)
    assert [d["identity"]["modkit_id"] for d in data] == [MORPHE_MODKIT_ID]
    assert data[0]["availability"]["status"] == "NOT_INSTALLED"


def test_cli_modkits_lists_status_and_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    monkeypatch.setenv("FORCE_COLOR", "3")
    cfg = tmp_path / "modkits.toml"
    cfg.write_text('[modkits.example-kit]\nexecutable_path = "/opt/example-kit/kit"\n')
    res = runner.invoke(app, ["modkits", "--json", "--config", str(cfg)])
    assert res.exit_code == 0 and "\x1b" not in res.stdout
    data = {d["identity"]["modkit_id"]: d for d in json.loads(res.stdout)}
    assert list(data) == ["example-kit", MORPHE_MODKIT_ID, TEST_MODKIT_ID]
    assert data[TEST_MODKIT_ID]["availability"]["status"] == "AVAILABLE"
    assert data[TEST_MODKIT_ID]["identity"]["trust"] == "TEST_ONLY"
    assert data["example-kit"]["availability"]["status"] == "CONFIGURATION_INVALID"
    assert data["example-kit"]["identity"]["installed_version"] is None
    monkeypatch.delenv("FORCE_COLOR")
    text = runner.invoke(app, ["modkits", "--verbose", "--config", str(cfg)],
                         env={"COLUMNS": "200"})  # fmt: skip
    assert text.exit_code == 0
    assert "EXTERNAL / UNVERIFIED" in text.stdout and "TEST ONLY" in text.stdout
    assert "not trusted" in text.stdout


def test_cli_modkit_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    res = runner.invoke(app, ["modkit", "info", TEST_MODKIT_ID, "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["identity"]["adapter_version"] == "1.0.0"
    assert data["capabilities"] == ["APK_TRANSFORMATION"]
    assert {r["kind"] for r in data["requirements"]} >= {"EXECUTABLE", "RUNTIME", "MIN_VERSION"}
    assert data["operations"][0]["input_types"] == ["apk"]
    text = runner.invoke(app, ["modkit", "info", TEST_MODKIT_ID, "-v"], env={"COLUMNS": "200"})
    assert text.exit_code == 0
    for s in ("Adapter version", "AVAILABLE", "Trust", "TEST ONLY", "Requirements", "Operations"):
        assert s in text.stdout
    unknown = runner.invoke(app, ["modkit", "info", "nope"])
    assert unknown.exit_code == 2 and "Unknown ModKit" in unknown.stdout

    morphe = runner.invoke(app, ["modkit", "info", MORPHE_MODKIT_ID, "--json"])
    assert morphe.exit_code == 0
    mdata = json.loads(morphe.stdout)
    assert mdata["availability"]["status"] == "NOT_INSTALLED"
    # H.8.3: morphe declares a real "patch" operation now, unlike test-modkit's
    # "transform" - unavailability (no executable configured) is orthogonal to that.
    assert mdata["capabilities"] == ["APK_TRANSFORMATION", "PATCH_SELECTION", "MULTI_PATCH"]
    assert [o["id"] for o in mdata["operations"]] == ["patch"]


def test_cli_modkit_run(apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    base = ["modkit", "run", TEST_MODKIT_ID, str(apk), "--work-dir", str(tmp_path / "ws")]
    ok = runner.invoke(app, [*base, "-o", str(tmp_path / "o1"), "-p", f"api_token={SECRET}",
                             "--json", "--report", str(tmp_path / "r.json")])  # fmt: skip
    assert ok.exit_code == 0, ok.output
    data = json.loads(ok.stdout)["result"]
    assert data["status"] == "SUCCESS" and Path(data["published"]["path"]).is_file()
    assert SECRET not in ok.stdout and SECRET not in (tmp_path / "r.json").read_text()
    bad = runner.invoke(app, [*base, "-o", str(tmp_path / "o2"), "-p", "scenario=invalid-apk"])
    assert bad.exit_code == 3 and "OUTPUT_INVALID" in bad.stdout
    crash = runner.invoke(app, [*base, "-o", str(tmp_path / "o3"), "-p", "scenario=nonzero-exit"])
    assert crash.exit_code == 1
    malformed = runner.invoke(app, [*base, "-o", str(tmp_path / "o4"), "-p", "novalue"])
    assert malformed.exit_code == 2
    missing = runner.invoke(app, ["modkit", "run", "nope", str(apk), "-o", str(tmp_path / "o5")])
    assert missing.exit_code == 2
    assert _sha(apk) == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert os.listdir(tmp_path / "o1") == ["app.test-modkit.apk"]
