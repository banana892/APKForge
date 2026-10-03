"""Phase H.2 integration: planning over real synthetic APKs and the ``transform`` CLI.

Fixtures from tests/fixtures/h1_apks.py and h2_apks.py are built into real APKs with
BuildService (Apktool 3.0.3), then planned through the full H.1 -> H.2 path. Skipped when
the build toolchain is unavailable.
"""

# ruff: noqa: E501 - the decision table keeps one case per line

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkforge.builders import BuildService, ToolchainConfig
from apkforge.cli.main import app
from apkforge.reference import ReferenceAnalysisService
from apkforge.transformation import (
    DecisionReason,
    EligibilityState,
    PlanningResult,
    TransformationPlanningService,
    TransformationRequest,
)
from tests.fixtures.h1_apks import FIXTURES, PKG, build_fixture
from tests.fixtures.h2_apks import H2_FIXTURES

pytestmark = pytest.mark.integration

ES = EligibilityState
R = DecisionReason
_USED = {"f01_isolated", "f09_reflection", "f10_native_method", "f12_manifest"}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("h2")
    svc = BuildService(
        ToolchainConfig.discover(framework_dir=base / "framework"), work_dir=base / "ws"
    )
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    return svc


@pytest.fixture(scope="module")
def apks(service: BuildService, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    work = tmp_path_factory.mktemp("h2-fixtures")
    fixtures = [fx for fx in FIXTURES if fx.name in _USED] + H2_FIXTURES
    return {fx.name: build_fixture(service, fx, work) for fx in fixtures}


@pytest.fixture(scope="module")
def planner(service: BuildService, tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    work = tmp_path_factory.mktemp("h2-analysis")
    return TransformationPlanningService(ReferenceAnalysisService(service, work_dir=work)), work


def _plan(planner, apk: Path, *reqs: tuple[str, str]) -> PlanningResult:  # type: ignore[no-untyped-def]
    svc, work = planner
    before = _sha(apk)
    result = svc.plan(apk, [TransformationRequest(transformation_id=t, target=x) for t, x in reqs])
    assert _sha(apk) == before
    assert result.original_unchanged is True
    assert not result.errors, result.errors
    assert result.applied is False
    assert not any(work.iterdir()), "decode workspace left behind"
    return result


def test_real_apk_decisions(planner, apks: dict[str, Path]) -> None:  # type: ignore[no-untyped-def]
    cases = [
        ("f01_isolated", ("H-TRANS-001", f"{PKG}.B"), ES.ELIGIBLE, set()),
        ("f12_manifest", ("H-TRANS-001", f"{PKG}.B"), ES.REFUSED, {R.MANIFEST_COMPONENT_REFERENCE}),
        ("f09_reflection", ("H-TRANS-001", f"{PKG}.C"), ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("f10_native_method", ("H-TRANS-002", f"{PKG}.B->nativeCall(I)I"), ES.UNSUPPORTED, {R.NATIVE_METHOD}),
        ("g01_methods", ("H-TRANS-002", f"{PKG}.D->helper()V"), ES.ELIGIBLE, set()),
        ("g01_methods", ("H-TRANS-002", f"{PKG}.D->shared()V"), ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        ("g01_methods", ("H-TRANS-002", f"{PKG}.E->run()V"), ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("g01_methods", ("H-TRANS-002", f"{PKG}.K->k()V"), ES.CONDITIONALLY_ELIGIBLE, {R.KOTLIN_METADATA_UPDATE_REQUIRED}),
        ("g02_method_reflection", ("H-TRANS-002", f"{PKG}.D->secret()V"), ES.REFUSED, {R.REFLECTION_TARGET_PRESENT}),
        ("g03_duplicate_class", ("H-TRANS-001", f"{PKG}.C"), ES.REFUSED, {R.TARGET_AMBIGUOUS}),
    ]  # fmt: skip
    for fixture, req, state, codes in cases:
        d = _plan(planner, apks[fixture], req).decisions[0]
        assert d.eligibility is state, (fixture, req, d.reasons)
        assert codes <= {r.code for r in d.reasons}, (fixture, req, d.reasons)
        assert (d.plan is not None) == state.plannable


def test_real_apk_plans_are_deterministic(planner, apks: dict[str, Path]) -> None:  # type: ignore[no-untyped-def]
    reqs = [
        ("H-TRANS-002", f"{PKG}.D->helper()V"),
        ("H-TRANS-002", f"{PKG}.K->k()V"),
        ("H-TRANS-001", f"{PKG}.B"),
    ]
    a = _plan(planner, apks["g01_methods"], *reqs)
    b = _plan(planner, apks["g01_methods"], *reqs)
    assert a.to_json() == b.to_json()
    assert len(a.plans) == 3
    assert a.apk.sha256 == _sha(apks["g01_methods"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli(args: list[str]):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, args, env={"FORCE_COLOR": "3"})


def test_cli_json_is_ansi_free_and_deterministic(
    apks: dict[str, Path], tmp_path: Path, service: BuildService
) -> None:
    apk = apks["g01_methods"]
    before = _sha(apk)
    args = [
        "transform",
        str(apk),
        "--transform",
        "H-TRANS-002",
        "--target",
        f"{PKG}.D->helper()V",
        "--target",
        f"{PKG}.D->used()V",
        "--dry-run",
        "--json",
        "--work-dir",
        str(tmp_path / "ws"),
    ]
    r1 = _cli(args)
    r2 = _cli(args)
    assert r1.exit_code == 0, r1.output
    assert "\x1b" not in r1.stdout
    assert r1.stdout == r2.stdout
    data = json.loads(r1.stdout)
    assert [d["eligibility"] for d in data["decisions"]] == ["ELIGIBLE", "REFUSED"]
    assert data["decisions"][0]["plan"]["planned_changes"][0]["type"] == "remove_method"
    assert data["decisions"][1]["reasons"][0]["code"] == "METHOD_CALLER_PRESENT"
    assert data["applied"] is False and data["original_unchanged"] is True
    assert data["limitations"][0].startswith("H.2 determines whether")
    assert _sha(apk) == before
    assert not any((tmp_path / "ws").iterdir())


def test_cli_pairs_transforms_with_targets(apks: dict[str, Path], tmp_path: Path) -> None:
    res = _cli(
        [
            "transform",
            str(apks["g01_methods"]),
            "-t",
            "H-TRANS-001",
            "--target",
            f"{PKG}.B",
            "-t",
            "H-TRANS-002",
            "--target",
            f"{PKG}.B->bar()V",
            "--json",
            "--work-dir",
            str(tmp_path / "ws"),
        ]
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert [d["transformation_id"] for d in data["decisions"]] == ["H-TRANS-001", "H-TRANS-002"]
    assert all(d["eligibility"] == "REFUSED" for d in data["decisions"])
    assert data["conflicts"][0]["kind"] == "class_method_overlap"


def test_cli_rejects_apply(apks: dict[str, Path]) -> None:
    apk = apks["f01_isolated"]
    before = _sha(apk)
    res = _cli(["transform", str(apk), "-t", "H-TRANS-001", "--target", f"{PKG}.B", "--apply"])
    assert res.exit_code == 2
    assert "planning-only" in res.output
    assert _sha(apk) == before


@pytest.mark.parametrize(
    "extra",
    [
        [],  # no transform / target
        ["-t", "H-TRANS-001"],
        ["-t", "H-TRANS-001", "-t", "H-TRANS-002", "--target", f"{PKG}.B"],
    ],
)
def test_cli_usage_errors(apks: dict[str, Path], extra: list[str]) -> None:
    res = _cli(["transform", str(apks["f01_isolated"]), *extra])
    assert res.exit_code == 2, res.output


def test_cli_reports(apks: dict[str, Path], tmp_path: Path) -> None:
    apk = apks["f01_isolated"]
    md = tmp_path / "out" / "plan.md"
    js = tmp_path / "out" / "plan.json"
    for report in (md, js):
        res = _cli(
            [
                "transform",
                str(apk),
                "-t",
                "H-TRANS-001",
                "--target",
                f"{PKG}.B",
                "--report",
                str(report),
                "--verbose",
                "--work-dir",
                str(tmp_path / "ws"),
            ]
        )
        assert res.exit_code == 0, res.output
        assert "ELIGIBLE" in res.output
    assert "remove_class" in md.read_text()
    assert "\x1b" not in md.read_text()
    data = json.loads(js.read_text())
    assert data["decisions"][0]["plan"]["plan_id"].startswith("plan-")
