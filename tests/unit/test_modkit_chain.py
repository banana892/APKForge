"""Phase H.9 - sequential ModKit chains, run against the reference ``test-modkit``."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.modkit import (
    ChainSpec,
    ChainStep,
    ModKitChainRunner,
    ModKitExecutor,
    ModKitManager,
    ModKitResultStatus,
    load_chain_spec,
)
from apkforge.modkit.config import CONFIG_ENV_VAR
from apkforge.modkit.manager import TEST_MODKIT_ENV_VAR
from apkforge.modkit.testing import MARKER_ENTRY, TEST_MODKIT_ID, TestModKitAdapter
from tests.fixtures import create_synthetic_apk

R = ModKitResultStatus


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.delenv(TEST_MODKIT_ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _runner() -> ModKitChainRunner:
    m = ModKitManager(executor=ModKitExecutor())
    m.register(TEST_MODKIT_ID, TestModKitAdapter)
    return ModKitChainRunner(m)


def _step(scenario: str = "success", marker: str | None = None, **kw: object) -> ChainStep:
    params = {"scenario": scenario, **({"marker": marker} if marker else {})}
    return ChainStep(modkit=TEST_MODKIT_ID, operation="transform", parameters=params, **kw)  # type: ignore[arg-type]


def _run(apk: Path, tmp_path: Path, *steps: ChainStep, **kw: object):  # type: ignore[no-untyped-def]
    before = _sha(apk)
    res = _runner().run(ChainSpec(steps=steps), apk, tmp_path / "out",
                        workspace_base=tmp_path / "ws", **kw)  # type: ignore[arg-type]  # fmt: skip
    assert _sha(apk) == before and res.original_unchanged is not False
    return res


def test_each_step_consumes_the_previous_validated_output(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, _step(marker="first"), _step(marker="second"))
    assert res.status is R.SUCCESS, res.reason
    s0, s1 = res.steps
    assert s0.original.sha256 == _sha(apk)  # type: ignore[union-attr]
    assert s1.original.sha256 == s0.published.sha256  # type: ignore[union-attr]
    assert res.published is not None and res.published.sha256 == s1.published.sha256  # type: ignore[union-attr]
    with zipfile.ZipFile(res.published.path) as zf:
        assert zf.read(MARKER_ENTRY) == b"second"
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["app.chain.apk"]
    chain_dir = Path(res.chain_dir or "")
    assert not list(chain_dir.glob("step-*.apk")) and not res.intermediates_retained
    assert json.loads((chain_dir / "chain-result.json").read_text())["status"] == "SUCCESS"


def test_chain_stops_at_first_failure_and_publishes_nothing(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, _step(marker="a"), _step("nonzero-exit"), _step(marker="c"))
    assert res.status is R.EXECUTION_FAILED and res.failed_step == 1
    assert len(res.steps) == 2 and res.published is None
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
    # intermediates are kept as evidence of a failed chain
    assert res.intermediates_retained and (Path(res.chain_dir or "") / "step-0.apk").is_file()


def test_noop_step_passes_its_input_through(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, _step(marker="same"), _step(marker="same", allow_noop=True))
    assert res.status is R.SUCCESS, res.reason
    assert res.steps[1].status is R.NO_OP
    assert res.published.sha256 == res.steps[0].published.sha256  # type: ignore[union-attr]


def test_unexpected_unchanged_step_fails_without_allow_noop(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, _step(marker="same"), _step(marker="same"))
    assert res.status is R.OUTPUT_INVALID and res.failed_step == 1


def test_all_noop_chain_publishes_nothing(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, _step("noop", allow_noop=True))
    assert res.status is R.NO_OP and res.published is None


def test_preflight_rejects_unknown_modkit_before_running_anything(
    apk: Path, tmp_path: Path
) -> None:
    res = _run(apk, tmp_path, _step(), ChainStep(modkit="nope", operation="x"))
    assert res.status is R.NOT_AVAILABLE and "step 1" in res.reason
    assert res.steps == () and not (tmp_path / "ws").exists()
    bad_op = _run(apk, tmp_path, _step(), ChainStep(modkit=TEST_MODKIT_ID, operation="x"))
    assert bad_op.status is R.INVALID_INPUT and "unknown operation" in bad_op.reason


def test_refuses_to_overwrite_existing_output(apk: Path, tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "app.chain.apk").write_bytes(b"keep")
    res = _run(apk, tmp_path, _step())
    assert res.status is R.INVALID_INPUT and res.steps == ()
    assert (tmp_path / "out" / "app.chain.apk").read_bytes() == b"keep"


def test_load_chain_spec_toml_and_json(tmp_path: Path) -> None:
    toml = tmp_path / "p.toml"
    toml.write_text(
        '[[steps]]\nmodkit = "morphe"\noperation = "patch"\nallow_noop = true\n'
        '[steps.parameters]\npatches = "/b.mpp"\nenable = "Clone app"\n'
    )
    spec = load_chain_spec(toml)
    assert spec.steps[0].parameters == {"patches": "/b.mpp", "enable": "Clone app"}
    assert spec.steps[0].allow_noop
    js = tmp_path / "p.json"
    js.write_text(json.dumps({"steps": [{"modkit": "a", "operation": "b"}]}))
    assert load_chain_spec(js).steps[0].modkit == "a"


@pytest.mark.parametrize(
    "body",
    [
        "steps = []",  # no steps
        '[[steps]]\nmodkit = "a"',  # missing operation
        '[[steps]]\nmodkit = "a"\noperation = "b"\nshell = "rm -rf /"',  # unknown key
        '[[steps]]\nmodkit = "a"\noperation = "b"\n[steps.parameters]\nn = 1',  # non-string
        "not = [toml",
    ],
)
def test_load_chain_spec_rejects_bad_pipelines(tmp_path: Path, body: str) -> None:
    p = tmp_path / "bad.toml"
    p.write_text(body)
    with pytest.raises(ValueError, match="invalid pipeline"):
        load_chain_spec(p)


def test_cli_modkit_chain(apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    pipeline = tmp_path / "chain.toml"
    pipeline.write_text(
        "".join(
            f'[[steps]]\nmodkit = "{TEST_MODKIT_ID}"\noperation = "transform"\n'
            f'[steps.parameters]\nscenario = "success"\nmarker = "{m}"\n'
            for m in ("one", "two")
        )
    )
    base = ["modkit", "chain", str(apk), "--pipeline", str(pipeline),
            "--work-dir", str(tmp_path / "ws")]  # fmt: skip
    runner = CliRunner()
    ok = runner.invoke(app, [*base, "-o", str(tmp_path / "o1"), "--json"])
    assert ok.exit_code == 0, ok.output
    data = json.loads(ok.stdout)
    assert data["status"] == "SUCCESS" and len(data["steps"]) == 2
    assert Path(data["published"]["path"]).is_file()
    again = runner.invoke(app, [*base, "-o", str(tmp_path / "o1")])
    assert again.exit_code == 2  # refuses to overwrite
    bad = tmp_path / "bad.toml"
    bad.write_text("steps = []")
    assert runner.invoke(app, ["modkit", "chain", str(apk), "--pipeline", str(bad),
                               "-o", str(tmp_path / "o2")]).exit_code == 2  # fmt: skip
