"""Phase H.3 integration: applying H.2 plans to real synthetic APKs (H-TRANS-001 only).

Fixtures from tests/fixtures/h3_apks.py are built into real APKs, published once
(round trip + v2/v3 signature by a separate publisher key), planned through H.1 -> H.2
and applied with :class:`TransformationExecutor` (BuildService, H.1 re-analysis, Phase E
diff). Skipped when the build toolchain is unavailable.

A  positive transformation (VERIFIED)          G  source SHA mismatch
B  caller -> REFUSED by H.2, H.3 refuses        H  tampered / invalid plans
C  unresolved reflection -> UNDETERMINED        I  unexpected mutation detected
D  native declaration / native code            J  controlled build failure
E  manifest component (+ forged plan)          K  reproducibility
F  target missing from the decoded workspace
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner, Result

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.cli.main import app
from apkforge.inspection.dex import DEXInspector
from apkforge.modification.catalog import default_catalog
from apkforge.modification.pipeline import measure_noise_floor
from apkforge.reference import ReferenceAnalysisService
from apkforge.transformation import (
    H3_MODIFIER_ID,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CheckOutcome,
    DecisionReason,
    EligibilityState,
    PlanningResult,
    RemoveIsolatedClassModifier,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlanningService,
    TransformationRequest,
)
from apkforge.transformation.planner import decision_id_for
from tests.fixtures.h3_apks import H3_FIXTURES, PKG, TARGET, publish_fixture, publisher_key

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkforge.builders.models import StageResult
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.workspace import BuildWorkspace

pytestmark = pytest.mark.integration

AR = ApplicationReason
AS = ApplicationStatus
ES = EligibilityState
R = DecisionReason
C1 = "H-TRANS-001"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("h3")


@pytest.fixture(scope="module")
def service(base: Path) -> BuildService:
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    svc = BuildService(toolchain, ensure_dev_keystore(toolchain.keytool, base / "dev-key"),
                       work_dir=base / "ws")  # fmt: skip
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    return svc


@pytest.fixture(scope="module")
def apks(service: BuildService, base: Path) -> dict[str, Path]:
    assert service.toolchain.keytool is not None
    pub = publisher_key(service.toolchain.keytool, base / "publisher-key")
    return {fx.name: publish_fixture(service, fx, base / "fixtures", pub) for fx in H3_FIXTURES}


@pytest.fixture(scope="module")
def reference(service: BuildService, base: Path) -> ReferenceAnalysisService:
    return ReferenceAnalysisService(service, work_dir=base / "analysis")


@pytest.fixture(scope="module")
def baselines(service: BuildService, apks: dict[str, Path], base: Path) -> dict[str, Any]:
    out = {}
    for name in ("h3_isolated", "h3_isolated_alt"):
        bl = measure_noise_floor(service, apks[name], work_dir=base / "noise" / name)
        assert bl.entries[0].result == "EQUIVALENT", bl.entries[0]
        out[name] = bl
    return out


def _planning(
    reference: ReferenceAnalysisService, apk: Path, target: str = TARGET
) -> PlanningResult:
    before = _sha(apk)
    res = TransformationPlanningService(reference).plan(
        apk, [TransformationRequest(transformation_id=C1, target=target)]
    )
    assert _sha(apk) == before and not res.errors
    return res


def _write(plan: PlanningResult | dict[str, Any], path: Path) -> Path:
    text = plan.to_json() if isinstance(plan, PlanningResult) else json.dumps(plan, indent=2)
    path.write_text(text)
    return path


def _run(
    service: BuildService,
    reference: ReferenceAnalysisService,
    apk: Path,
    plan: Any,
    tmp_path: Path,
    *,
    baseline: NoopSemanticBaseline | None = None,
    apply: bool = True,
    name: str = "out.apk",
    executor: TransformationExecutor | None = None,
) -> TransformationApplicationResult:
    before = _sha(apk)
    ex = executor or TransformationExecutor(service, reference_service=reference)
    out = tmp_path / name
    res = ex.run(apk, plan, apply=apply, output_apk=out, noop_baseline=baseline,
                 work_dir=tmp_path / "work")  # fmt: skip
    # mandatory invariant for every run
    assert _sha(apk) == before == res.source_apk_sha256 == res.source_apk_sha256_after
    assert res.original_unchanged is True
    assert out.resolve() != apk.resolve()
    if res.status is not AS.VERIFIED:
        assert not out.exists() and res.output_apk is None
    return res


def _assert_refused(res: TransformationApplicationResult, code: ApplicationReason) -> None:
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is code, res.failure
    assert AS.APPLYING not in res.status_history
    assert res.mutation is None and res.output_apk is None and res.workspace is None


def _classes(apk: Path) -> set[str]:
    insp, _ = DEXInspector().inspect(apk)
    return {c.name for df in insp.dex_files if df.inventory for c in df.inventory.classes}


# ---------------------------------------------------------------------------
# A positive / K reproducibility
# ---------------------------------------------------------------------------


def test_a_positive_transformation(service, reference, apks, baselines, tmp_path) -> None:
    apk = apks["h3_isolated"]
    planning = _planning(reference, apk)
    (decision,) = planning.decisions
    assert decision.eligibility is ES.ELIGIBLE and decision.plan is not None
    res = _run(service, reference, apk, _write(planning, tmp_path / "plan.json"), tmp_path,
               baseline=baselines["h3_isolated"])  # fmt: skip
    assert res.status is AS.VERIFIED, (res.failure, res.diff)
    assert res.status_history == [AS.PLANNED, AS.APPLYING, AS.BUILT, AS.VERIFIED]
    assert res.failure is None and res.plan_id == decision.plan.plan_id
    assert [r.status for r in res.verification] == [CheckOutcome.PASS] * 14
    m = res.mutation
    assert m is not None and m.count == 1 and m.removed_classes == [TARGET]
    assert (m.classes_before, m.classes_after) == (3, 2) and m.post_transform_sha256 is None
    assert m.target_file == "smali/com/example/h1/B.smali"
    # Phase E: exactly the declared changes, nothing unexpected
    assert res.diff["passed"] and not res.diff["unexpected"] and not res.diff["expected_missing"]
    assert sorted(res.diff["expected_observed"]) == [
        "dex_api_reference removed android.os.Looper;->getMainLooper()Landroid.os.Looper",
        f"dex_class removed {TARGET}",
        "dex_string removed B.java",
        "dex_string removed Landroid/os/Looper;",
        "dex_string removed Lcom/example/h1/B;",
        "dex_string removed Ljava/lang/String;",  # only B.stamp() returns a String
        "dex_string removed getMainLooper",
        "dex_string removed h3-only-in-b",
        "dex_string removed stamp",
    ]
    assert len(res.expected_changes) == 9  # declared before mutation; all observed
    assert res.diff["matrix"]["overall"] == "VERIFIED"
    assert res.build["verification"]["signature_verified"] is True
    # H.1 re-analysis
    a = res.analysis
    assert a is not None and a.sufficient and not a.target_defined
    assert (a.defined_classes_before, a.defined_classes_after) == (3, 2)
    assert not a.other_classes_removed and not a.classes_added and not a.weakened_components
    assert a.definitive_references == a.indirect_references == 0
    # the published APK, checked independently
    out = Path(res.output_apk or "")
    assert out.is_file() and _sha(out) == res.output_apk_sha256
    assert _classes(out) == {f"{PKG}.A", f"{PKG}.C"} and TARGET in _classes(apk)
    assert res.workspace is not None and not Path(res.workspace).exists()


def test_k_reproducibility(service, reference, apks, baselines, tmp_path) -> None:
    apk = apks["h3_isolated"]
    plan = _write(_planning(reference, apk), tmp_path / "plan.json")
    runs = [
        _run(service, reference, apk, plan, tmp_path / f"r{i}", baseline=baselines["h3_isolated"])
        for i in (1, 2)
    ]
    assert all(r.status is AS.VERIFIED for r in runs)
    a, b = (r.comparable() for r in runs)
    assert a == b
    # entry content is identical; archive bytes may differ only by ZIP metadata
    assert runs[0].output_content_sha256 == runs[1].output_content_sha256


def test_dry_run_reports_without_building(service, reference, apks, tmp_path) -> None:
    apk = apks["h3_isolated"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path, apply=False)
    assert res.status is AS.PLANNED and res.dry_run and res.failure is None
    assert res.planned_changes[0]["type"] == "remove_class"
    assert res.mutation is None and res.workspace is None and not res.build
    assert not res.verification and not (tmp_path / "work").exists()
    # the plan binds the APK by SHA-256: a renamed copy validates too
    renamed = tmp_path / "renamed.apk"
    shutil.copyfile(apk, renamed)
    again = _run(service, reference, renamed, _planning(reference, apk), tmp_path, apply=False)
    assert again.status is AS.PLANNED, again.failure


def test_output_must_differ_from_source(service, reference, apks, tmp_path) -> None:
    apk = apks["h3_isolated"]
    ex = TransformationExecutor(service, reference_service=reference)
    res = ex.run(apk, _planning(reference, apk), apply=True, output_apk=apk)
    _assert_refused(res, AR.OUTPUT_INVALID)
    assert res.original_unchanged


# ---------------------------------------------------------------------------
# B-E: H.2 refusals cannot be bypassed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "target", "state", "codes"),
    [
        ("h3_caller", TARGET, ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        ("h3_reflection", TARGET, ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("h3_native", TARGET, ES.UNSUPPORTED, {R.NATIVE_METHOD_DECLARED}),
        ("h3_native", f"{PKG}.C", ES.UNDETERMINED, {R.NATIVE_DEPENDENCY_UNKNOWN}),
        ("h3_manifest", TARGET, ES.REFUSED, {R.MANIFEST_COMPONENT_REFERENCE}),
    ],
)
def test_bcde_ineligible_plans_are_refused(
    service, reference, apks, tmp_path, fixture, target, state, codes
) -> None:
    apk = apks[fixture]
    planning = _planning(reference, apk, target)
    (d,) = planning.decisions
    assert d.eligibility is state and codes <= {r.code for r in d.reasons}, d.reasons
    assert d.plan is None
    res = _run(service, reference, apk, _write(planning, tmp_path / "p.json"), tmp_path)
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)
    assert res.failure is not None and res.failure.details["eligibility"] == state.value


def _forge(plan: dict[str, Any], apk: Path, target: str = TARGET) -> dict[str, Any]:
    """Rebind an ELIGIBLE plan to another APK with a *correctly recomputed* plan id."""
    forged: dict[str, Any] = json.loads(json.dumps(plan))
    sha = _sha(apk)
    forged["apk"]["sha256"] = sha
    forged["target"]["class_name"] = forged["target"]["raw"] = target
    did = decision_id_for(sha, C1, target, {}, forged["analysis_schema"])
    forged["plan_id"] = f"plan-{did}"
    return forged


@pytest.mark.parametrize("fixture", ["h3_caller", "h3_reflection", "h3_manifest"])
def test_e_forged_eligible_plan_is_refused(service, reference, apks, tmp_path, fixture) -> None:
    good = _planning(reference, apks["h3_isolated"]).decisions[0].plan
    assert good is not None
    forged = _forge(good.model_dump(mode="json"), apks[fixture])
    res = _run(service, reference, apks[fixture], _write(forged, tmp_path / "f.json"), tmp_path)
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)
    assert res.failure is not None and res.failure.stage is ApplicationStage.ELIGIBILITY


# ---------------------------------------------------------------------------
# F-J
# ---------------------------------------------------------------------------


class _DropTargetOnDecode(BuildService):
    """A BuildService whose decoded workspace lacks the target (simulated drift)."""

    def decode(
        self, input_apk: Path | str, workspace: BuildWorkspace, *, timeout: int | None = None
    ) -> StageResult:
        stage = super().decode(input_apk, workspace, timeout=timeout)
        ws = workspace
        (ws.decoded_dir / "smali/com/example/h1/B.smali").unlink()
        return stage


def test_f_target_missing_in_workspace(service, reference, apks, baselines, tmp_path) -> None:
    apk = apks["h3_isolated"]
    drifting = _DropTargetOnDecode(service.toolchain, service.signing, work_dir=tmp_path / "ws")
    ex = TransformationExecutor(drifting, reference_service=reference)
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path,
               baseline=baselines["h3_isolated"], executor=ex)  # fmt: skip
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is AR.TARGET_NOT_FOUND
    assert res.failure.stage is ApplicationStage.PRE_TRANSFORM
    assert res.mutation is None and not res.workspace_kept


def test_g_source_sha_mismatch(service, reference, apks, tmp_path) -> None:
    plan = _write(_planning(reference, apks["h3_isolated"]), tmp_path / "a.json")
    res = _run(service, reference, apks["h3_isolated_alt"], plan, tmp_path)
    _assert_refused(res, AR.SOURCE_SHA_MISMATCH)


def test_h_tampered_plans(service, reference, apks, tmp_path) -> None:
    apk = apks["h3_isolated"]
    planning = _planning(reference, apk)
    data = json.loads(planning.to_json())
    plan = data["decisions"][0]["plan"]

    def run(mutate: Callable[[dict[str, Any]], object]) -> TransformationApplicationResult:
        p = json.loads(json.dumps(plan))
        mutate(p)
        return _run(service, reference, apk, _write(p, tmp_path / "t.json"), tmp_path)

    cases = [
        (lambda p: p["target"].update(class_name=f"{PKG}.C", raw=f"{PKG}.C"), AR.PLAN_ID_MISMATCH),
        (lambda p: p.update(plan_id="plan-00000000000000000000"), AR.PLAN_ID_MISMATCH),
        (lambda p: p.update(eligibility="CONDITIONALLY_ELIGIBLE"), AR.PLAN_NOT_ELIGIBLE),
        (lambda p: p["expected_changes"].append("nothing else"), AR.PLAN_MISMATCH),
        (lambda p: p["planned_changes"][0].update(artifact="smali/com/example/h1/C.smali"),
         AR.PLAN_MISMATCH),
        # relabelling a remove_class plan as H-TRANS-002 (which removes methods) is rejected
        # by the plan-shape check before the id is recomputed
        (lambda p: p.update(transformation_id="H-TRANS-002"), AR.PLAN_INVALID),
        (lambda p: p.pop("apk"), AR.PLAN_INVALID),
        (lambda p: p.update(analysis_schema=1), AR.PLAN_INVALID),
    ]  # fmt: skip
    for mutate, code in cases:
        _assert_refused(run(mutate), code)
    (tmp_path / "bad.json").write_text("{not json")
    _assert_refused(_run(service, reference, apk, tmp_path / "bad.json", tmp_path), AR.PLAN_INVALID)
    missing = _run(service, reference, apk, tmp_path / "missing.json", tmp_path)
    _assert_refused(missing, AR.PLAN_NOT_FOUND)


def test_i_unexpected_mutation_is_detected(
    service, reference, apks, baselines, tmp_path, monkeypatch
) -> None:
    def remove_two(self, path: Path) -> None:  # a faulty mutation: also removes C
        path.unlink()
        (path.parent / "C.smali").unlink()

    monkeypatch.setattr(RemoveIsolatedClassModifier, "_remove", remove_two)
    apk = apks["h3_isolated"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path,
               baseline=baselines["h3_isolated"])  # fmt: skip
    assert res.status is AS.FAILED
    assert res.failure is not None and res.failure.code is AR.UNEXPECTED_MUTATION
    assert res.failure.stage is ApplicationStage.MUTATION
    assert res.mutation is not None and res.mutation.count == 2
    assert sorted(res.mutation.removed_classes) == [f"{PKG}.B", f"{PKG}.C"]
    assert "build" not in [s["stage"] for s in res.build["stages"]]
    assert AS.BUILT not in res.status_history
    rows = {r.check: r.status for r in res.verification}
    assert rows["Classes removed"] is CheckOutcome.FAIL
    assert rows["Build"] is CheckOutcome.NOT_RUN
    assert res.workspace_kept and Path(res.workspace or "").is_dir()  # diagnostics kept


def test_j_build_failure(service, reference, apks, baselines, tmp_path, monkeypatch) -> None:
    real: Callable[..., StageResult] = service.build

    def broken(project: Path, out: Path, **kw: Any) -> StageResult:
        (project / "smali/com/example/h1/C.smali").write_text(".class public Lbroken\n")
        return real(project, out, **kw)

    monkeypatch.setattr(service, "build", broken)
    apk = apks["h3_isolated"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path,
               baseline=baselines["h3_isolated"])  # fmt: skip
    assert res.status is AS.FAILED
    assert res.failure is not None and res.failure.code is AR.BUILD_FAILED
    assert res.failure.stage is ApplicationStage.BUILD
    assert res.mutation is not None and res.mutation.count == 1
    rows = {r.check: r.status for r in res.verification}
    assert rows["Build"] is CheckOutcome.FAIL and rows["Sign"] is CheckOutcome.NOT_RUN
    assert res.workspace_kept


def test_h3_modifier_cannot_be_requested_through_modify() -> None:
    assert H3_MODIFIER_ID not in default_catalog()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli(args: list[str], base: Path) -> Result:
    env = {"FORCE_COLOR": "3", "APKFORGE_DEV_KEY_DIR": str(base / "dev-key")}
    return CliRunner().invoke(app, args, env=env)


def test_cli_plan_then_apply(apks, base, tmp_path) -> None:
    apk = apks["h3_isolated"]
    before = _sha(apk)
    work = ["--work-dir", str(tmp_path / "ws")]
    plan = tmp_path / "plan.json"
    res = _cli(
        ["transform", str(apk), "-t", C1, "--target", TARGET, "--report", str(plan), *work], base
    )
    assert res.exit_code == 0, res.output
    # dry run: validated, nothing built
    res = _cli(["transform", str(apk), "--plan", str(plan), "--json", *work], base)
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["status"] == "PLANNED" and data["output_apk"] is None
    # apply (noise floor measured by default)
    out = tmp_path / "out.apk"
    report = tmp_path / "h3.md"
    res = _cli(["transform", str(apk), "--plan", str(plan), "--apply", "-o", str(out),
                "--report", str(report), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "VERIFIED" in res.output and out.is_file()
    text = report.read_text()
    assert "| Target class after | absent" in text and "\x1b" not in text
    assert _sha(apk) == before


def test_cli_refusal_exit_code(apks, base, tmp_path) -> None:
    apk = apks["h3_caller"]
    plan = tmp_path / "plan.json"
    work = ["--work-dir", str(tmp_path / "ws")]
    res = _cli(
        ["transform", str(apk), "-t", C1, "--target", TARGET, "--report", str(plan), *work], base
    )
    assert res.exit_code == 0, res.output
    out = tmp_path / "out.apk"
    res = _cli(
        ["transform", str(apk), "--plan", str(plan), "--apply", "-o", str(out), "--json", *work],
        base,
    )
    assert res.exit_code == 3, res.output
    data = json.loads(res.stdout)
    assert data["status"] == "REFUSED" and data["failure"]["code"] == "PLAN_NOT_ELIGIBLE"
    assert not out.exists()


def test_published_fixtures_are_v2_only(apks) -> None:
    with zipfile.ZipFile(apks["h3_isolated"]) as z:
        assert not [n for n in z.namelist() if n.startswith("META-INF/")]
