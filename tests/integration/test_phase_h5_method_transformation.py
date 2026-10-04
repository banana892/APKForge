"""Phase H.5 integration: applying H.2 plans for H-TRANS-002 (remove isolated method).

Real synthetic APKs (tests/fixtures/h5_apks.py), published like real apps, are planned
through H.1 -> H.2, applied with :class:`TransformationExecutor` and verified against an
unmodified control rebuild with :class:`ControlExperiment` / H.4. Skipped when the build
toolchain is unavailable.

A  positive method removal (H.3-style VERIFIED + H.4 VERIFIED/COMPLETE)
B  overloaded methods (only the targeted descriptor is removed; the ambiguous name refused)
C  H.2 refusals cannot be bypassed (caller, reflection, native, override, interface,
   constructor, missing target)
D  mutation faults (wrong method, two methods, method + class) detected before build
E  build-time faults (other method/class, resource, manifest, native, asset, left
   reference) rejected by H.4
F  target missing before mutation / source SHA mismatch / forged plan
G  reproducibility, SHA preservation, CLI
"""

from __future__ import annotations

import hashlib
import json
import re
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
    H5_MODIFIER_ID,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CheckOutcome,
    ControlExperiment,
    ControlPresence,
    DecisionReason,
    DifferenceClass,
    EligibilityState,
    PlanningResult,
    RemoveIsolatedMethodModifier,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationStatus,
)
from apkforge.transformation.planner import decision_id_for
from tests.fixtures.h5_apks import (
    FAULTS,
    OVERLOAD_KEEP,
    OVERLOAD_TARGET,
    PKG,
    TARGET,
    TARGET_CLASS,
    TARGET_SMALI,
    build_corpus,
    inject_at_build,
    publisher_key,
)

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
S = TransformationVerificationStatus
K = DifferenceClass
C2 = "H-TRANS-002"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _strip_method(text: str, signature: str) -> str:
    """Remove one ``.method <signature> ... .end method`` block from smali *text*."""
    pattern = r"\n\.method[^\n]*\b" + re.escape(signature) + r".*?\n\.end method\n"
    return re.sub(pattern, "\n", text, flags=re.DOTALL)


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("h5")


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
    return build_corpus(service, base / "fixtures", pub)


@pytest.fixture(scope="module")
def reference(service: BuildService, base: Path) -> ReferenceAnalysisService:
    return ReferenceAnalysisService(service, work_dir=base / "analysis")


@pytest.fixture(scope="module")
def baselines(service: BuildService, apks: dict[str, Path], base: Path) -> dict[str, Any]:
    out = {}
    for name in ("h5_isolated", "h5_overloads"):
        bl = measure_noise_floor(service, apks[name], work_dir=base / "noise" / name)
        assert bl.entries[0].result == "EQUIVALENT", bl.entries[0]
        out[name] = bl
    return out


def _planning(
    reference: ReferenceAnalysisService, apk: Path, target: str = TARGET
) -> PlanningResult:
    before = _sha(apk)
    res = TransformationPlanningService(reference).plan(
        apk, [TransformationRequest(transformation_id=C2, target=target)]
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
    assert res.mutation is None and res.output_apk is None


def _methods(apk: Path, cls: str) -> set[str]:
    insp, _ = DEXInspector().inspect(apk)
    return {
        f"{m.name}({','.join(m.parameters)}){m.return_type}"
        for df in insp.dex_files
        if df.inventory
        for m in df.inventory.methods
        if m.class_name == cls
    }


def _classes(apk: Path) -> set[str]:
    insp, _ = DEXInspector().inspect(apk)
    return {c.name for df in insp.dex_files if df.inventory for c in df.inventory.classes}


# ---------------------------------------------------------------------------
# A positive
# ---------------------------------------------------------------------------


def test_a_positive_method_removal(service, reference, apks, baselines, tmp_path) -> None:
    apk = apks["h5_isolated"]
    planning = _planning(reference, apk)
    (decision,) = planning.decisions
    assert decision.eligibility is ES.ELIGIBLE and decision.plan is not None
    assert decision.plan.planned_changes[0].type == "remove_method"
    res = _run(service, reference, apk, _write(planning, tmp_path / "plan.json"), tmp_path,
               baseline=baselines["h5_isolated"])  # fmt: skip
    assert res.status is AS.VERIFIED, (res.failure, res.diff)
    assert res.status_history == [AS.PLANNED, AS.APPLYING, AS.BUILT, AS.VERIFIED]
    assert [r.status for r in res.verification] == [CheckOutcome.PASS] * 14
    m = res.mutation
    assert m is not None and m.operation == "REMOVE_METHOD" and m.count == 1
    assert m.removed_methods == ["isolatedStamp()Ljava/lang/String;"]
    assert m.method_key == "isolatedStamp()java.lang.String"
    assert (m.methods_before, m.methods_after) == (3, 2)
    assert (m.classes_before, m.classes_after) == (2, 2)  # the class is retained
    assert m.target_file == TARGET_SMALI and m.post_transform_sha256 is not None
    # Phase E: exactly the declared changes, nothing unexpected
    assert res.diff["passed"] and not res.diff["unexpected"] and not res.diff["expected_missing"]
    assert sorted(res.diff["expected_observed"]) == [
        "dex_api_reference removed android.os.Looper;->getMainLooper()Landroid.os.Looper",
        f"dex_class modified {TARGET_CLASS}",
        "dex_string removed Landroid/os/Looper;",
        "dex_string removed Ljava/lang/String;",
        "dex_string removed getMainLooper",
        "dex_string removed h5-only-in-this-method",
        "dex_string removed isolatedStamp",
    ]
    # method-level H.1 re-analysis
    ma = res.method_analysis
    assert ma is not None and ma.sufficient and ma.class_defined and not ma.target_method_present
    assert (ma.methods_before, ma.methods_after) == (3, 2)
    assert ma.definitive_references == ma.indirect_references == 0
    assert not ma.other_methods_removed and not ma.methods_added
    # the published APK, checked independently: class kept, method gone, other methods remain
    out = Path(res.output_apk or "")
    assert out.is_file() and _sha(out) == res.output_apk_sha256
    assert TARGET_CLASS in _classes(out)
    assert "isolatedStamp()java.lang.String" not in _methods(out, TARGET_CLASS)
    assert {"bar()V", "<init>()V"} <= _methods(out, TARGET_CLASS)


def test_a_h4_verifies_the_removal(service, reference, apks, tmp_path) -> None:
    apk = apks["h5_isolated"]
    exp = ControlExperiment(service, reference_service=reference)
    res = exp.run(apk, _planning(reference, apk), tmp_path / "exp")
    assert res.application is not None and res.application.status is AS.VERIFIED
    v = res.verification
    from apkforge.verification.models import CheckStatus

    assert v.status is S.VERIFIED, v.status_reason
    assert all(d.status is CheckStatus.PASSED for d in v.domains.values()), v.status_reason
    assert len(v.unexpected_changes) == 0 and len(v.unknown_changes) == 0
    from apkforge.verification.models import CheckStatus

    inv = {i.name: i.status for i in v.invariants}
    assert inv["target_class_retained"] is CheckStatus.PASSED
    assert inv["target_method_absent_after"] is CheckStatus.PASSED
    assert inv["exactly_one_method_removed[original->transformed]"] is CheckStatus.PASSED
    assert inv["method_count"] is CheckStatus.PASSED
    assert inv["h1_reference_state"] is CheckStatus.PASSED
    mpa = v.method_post_analysis
    assert mpa is not None and mpa.class_defined and not mpa.target_method_present
    assert _sha(apk) == res.original_sha256 == res.original_sha256_after


def test_g_reproducibility_and_sha_preservation(
    service, reference, apks, baselines, tmp_path
) -> None:
    apk = apks["h5_isolated"]
    before = _sha(apk)
    plan = _write(_planning(reference, apk), tmp_path / "plan.json")
    runs = [
        _run(service, reference, apk, plan, tmp_path / f"r{i}", baseline=baselines["h5_isolated"])
        for i in (1, 2)
    ]
    assert all(r.status is AS.VERIFIED for r in runs)
    assert runs[0].comparable() == runs[1].comparable()
    assert runs[0].output_content_sha256 == runs[1].output_content_sha256
    assert _sha(apk) == before


def test_dry_run_reports_without_building(service, reference, apks, tmp_path) -> None:
    apk = apks["h5_isolated"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path, apply=False)
    assert res.status is AS.PLANNED and res.dry_run and res.failure is None
    assert res.planned_changes[0]["type"] == "remove_method"
    assert res.mutation is None and not res.build and not res.verification


def test_output_must_differ_from_source(service, reference, apks) -> None:
    apk = apks["h5_isolated"]
    ex = TransformationExecutor(service, reference_service=reference)
    res = ex.run(apk, _planning(reference, apk), apply=True, output_apk=apk)
    _assert_refused(res, AR.OUTPUT_INVALID)
    assert res.original_unchanged


# ---------------------------------------------------------------------------
# B overloaded methods
# ---------------------------------------------------------------------------


def test_b_overload_only_targeted_descriptor_removed(
    service, reference, apks, baselines, tmp_path
) -> None:
    apk = apks["h5_overloads"]
    planning = _planning(reference, apk, OVERLOAD_TARGET)
    (d,) = planning.decisions
    assert d.eligibility is ES.ELIGIBLE and d.plan is not None
    res = _run(service, reference, apk, planning, tmp_path, baseline=baselines["h5_overloads"])
    assert res.status is AS.VERIFIED, (res.failure, res.diff)
    assert res.mutation is not None and res.mutation.removed_methods == ["foo(I)V"]
    assert res.mutation.method_key == "foo(int)V"
    out = Path(res.output_apk or "")
    methods = _methods(out, f"{PKG}.B")
    assert "foo(int)V" not in methods
    assert {"foo()V", "foo(java.lang.String)V"} <= methods  # the other overloads remain


def test_b_ambiguous_overload_name_is_refused(service, reference, apks, tmp_path) -> None:
    apk = apks["h5_overloads"]
    planning = _planning(reference, apk, f"{PKG}.B->foo")
    (d,) = planning.decisions
    assert d.eligibility is ES.REFUSED and {R.TARGET_AMBIGUOUS} <= {r.code for r in d.reasons}
    assert d.plan is None
    res = _run(service, reference, apk, _write(planning, tmp_path / "p.json"), tmp_path)
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)


def test_b_keep_overloads_are_independently_eligible(reference, apks) -> None:
    # each surviving overload is itself isolated; H.2 would plan it too (no hidden coupling)
    for target in OVERLOAD_KEEP:
        (d,) = _planning(reference, apks["h5_overloads"], target).decisions
        assert d.eligibility is ES.ELIGIBLE, (target, d.reasons)


# ---------------------------------------------------------------------------
# C H.2 refusals cannot be bypassed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "target", "state", "codes"),
    [
        ("h5_caller", f"{PKG}.B->callee()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        ("h5_reflection", TARGET, ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("h5_native", TARGET, ES.UNDETERMINED, {R.NATIVE_DEPENDENCY_UNKNOWN}),
        ("h5_override", f"{PKG}.B->run()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("h5_override", f"{PKG}.A->run()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDDEN}),
        ("h5_interface", f"{PKG}.B->handle()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("h5_interface", f"{PKG}.Iface->handle()V", ES.UNSUPPORTED,
         {R.ABSTRACT_METHOD, R.INTERFACE_METHOD}),
        ("h5_isolated", f"{PKG}.B-><init>()V", ES.UNSUPPORTED, {R.CONSTRUCTOR_METHOD}),
        ("h5_isolated", f"{PKG}.B->doesNotExist()V", ES.REFUSED, {R.TARGET_NOT_FOUND}),
    ],
)  # fmt: skip
def test_c_ineligible_plans_are_refused(
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


def test_c_forged_eligible_plan_rebound_to_caller_is_refused(
    service, reference, apks, tmp_path
) -> None:
    """An ELIGIBLE plan from h5_isolated forged onto h5_caller (B.callee has a caller) is
    refused by the H.2 re-evaluation; H.5 adds no eligibility rule of its own."""
    good = _planning(reference, apks["h5_isolated"]).decisions[0].plan
    assert good is not None
    forged: dict[str, Any] = json.loads(good.model_dump_json())
    target = f"{PKG}.B->callee()V"
    sha = _sha(apks["h5_caller"])
    forged["apk"]["sha256"] = sha
    forged["target"].update(class_name=f"{PKG}.B", method_name="callee", descriptor="()V",
                            raw=target)  # fmt: skip
    did = decision_id_for(sha, C2, f"{PKG}.B->callee()V", {}, forged["analysis_schema"])
    forged["plan_id"] = f"plan-{did}"
    res = _run(service, reference, apks["h5_caller"], _write(forged, tmp_path / "f.json"), tmp_path)
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)
    assert res.failure is not None and res.failure.stage is ApplicationStage.ELIGIBILITY


# ---------------------------------------------------------------------------
# D mutation faults (detected before any build)
# ---------------------------------------------------------------------------


def _fault_run(
    service, reference, apks, baselines, tmp_path, patch: Callable[[Any, Path, str], None]
) -> TransformationApplicationResult:
    def _write_hook(self: Any, path: Path, text: str) -> None:
        patch(self, path, text)

    ex = TransformationExecutor(service, reference_service=reference)
    import pytest as _pytest  # local monkeypatch

    mp = _pytest.MonkeyPatch()
    mp.setattr(RemoveIsolatedMethodModifier, "_write", _write_hook)
    try:
        isolated = apks["h5_isolated"]
        return _run(service, reference, isolated, _planning(reference, isolated), tmp_path,
                    baseline=baselines["h5_isolated"], executor=ex)  # fmt: skip
    finally:
        mp.undo()


def test_d_remove_wrong_method(service, reference, apks, baselines, tmp_path) -> None:
    def patch(self: Any, path: Path, text: str) -> None:  # remove bar() instead of the target
        import re

        new = re.sub(r"\n\.method public static bar\(\)V\n.*?\n\.end method\n", "\n",
                     path.read_text(), flags=re.DOTALL)  # fmt: skip
        path.write_text(new)

    res = _fault_run(service, reference, apks, baselines, tmp_path, patch)
    assert res.status is AS.FAILED and res.failure is not None
    assert res.failure.code is AR.UNEXPECTED_MUTATION
    assert res.failure.stage is ApplicationStage.MUTATION
    assert "build" not in [s["stage"] for s in res.build.get("stages", [])]


def test_d_remove_two_methods(service, reference, apks, baselines, tmp_path) -> None:
    def patch(self: Any, path: Path, text: str) -> None:  # also delete bar()
        import re

        new = re.sub(r"\n\.method public static bar\(\)V\n.*?\n\.end method\n", "\n", text,
                     flags=re.DOTALL)  # fmt: skip
        path.write_text(new)

    res = _fault_run(service, reference, apks, baselines, tmp_path, patch)
    assert res.status is AS.FAILED and res.failure is not None
    assert res.failure.code is AR.UNEXPECTED_MUTATION
    assert res.mutation is not None and res.mutation.count == 2


def test_d_remove_method_and_class(service, reference, apks, baselines, tmp_path) -> None:
    def patch(self: Any, path: Path, text: str) -> None:  # delete the whole class file
        path.unlink()

    res = _fault_run(service, reference, apks, baselines, tmp_path, patch)
    assert res.status is AS.FAILED and res.failure is not None
    assert res.failure.code is AR.UNEXPECTED_MUTATION
    assert res.mutation is not None and res.mutation.removed_classes == [TARGET_CLASS]


def test_d_h5_modifier_cannot_be_requested_through_modify() -> None:
    assert H5_MODIFIER_ID not in default_catalog()


# ---------------------------------------------------------------------------
# E build-time faults rejected by H.4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fault", sorted(FAULTS))
def test_e_build_faults_fail_verification(service, reference, apks, base, tmp_path, fault) -> None:
    edit, domain = FAULTS[fault]
    exp = ControlExperiment(service, reference_service=reference)
    with inject_at_build(service, edit):
        res = exp.run(apks["h5_isolated"], _planning(reference, apks["h5_isolated"]),
                      tmp_path / f"fault-{fault}", verify_unpublished=True)  # fmt: skip
    app_res = res.application
    assert app_res is not None and app_res.status is AS.FAILED  # H.5 refuses to publish
    assert AS.BUILT in app_res.status_history and app_res.output_apk is None
    assert res.transformed_source == "unpublished"
    v = res.verification
    assert v.status is S.FAILED, v.status_reason
    assert v.control_rebuild.noop_result == "EQUIVALENT"  # control untouched
    domains = {d.domain.value for d in v.unexpected_changes}
    assert domain in domains, (domain, domains)
    from apkforge.verification.models import CheckStatus

    assert v.domains[domain].status == CheckStatus.FAILED
    assert all(d.in_control is not ControlPresence.SAME_CONTENT for d in v.unexpected_changes)
    if fault == "reference_left":
        mpa = v.method_post_analysis
        assert mpa is not None and mpa.definitive_references >= 1


# ---------------------------------------------------------------------------
# F integrity: target gone / sha mismatch / forged plan
# ---------------------------------------------------------------------------


class _DropMethodOnDecode(BuildService):
    """A BuildService whose decoded workspace lacks the target method (simulated drift)."""

    def decode(
        self, input_apk: Path | str, workspace: BuildWorkspace, *, timeout: int | None = None
    ) -> StageResult:
        stage = super().decode(input_apk, workspace, timeout=timeout)
        path = workspace.decoded_dir / TARGET_SMALI
        path.write_text(_strip_method(path.read_text(), "isolatedStamp()Ljava/lang/String;"))
        return stage


def test_f_target_missing_in_workspace(service, reference, apks, baselines, tmp_path) -> None:
    drifting = _DropMethodOnDecode(service.toolchain, service.signing, work_dir=tmp_path / "ws")
    ex = TransformationExecutor(drifting, reference_service=reference)
    res = _run(service, reference, apks["h5_isolated"], _planning(reference, apks["h5_isolated"]),
               tmp_path, baseline=baselines["h5_isolated"], executor=ex)  # fmt: skip
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is AR.TARGET_NOT_FOUND
    assert res.failure.stage is ApplicationStage.PRE_TRANSFORM
    assert res.mutation is None


def test_f_source_sha_mismatch(service, reference, apks, tmp_path) -> None:
    plan = _write(_planning(reference, apks["h5_isolated"]), tmp_path / "a.json")
    res = _run(service, reference, apks["h5_isolated_alt"], plan, tmp_path)
    _assert_refused(res, AR.SOURCE_SHA_MISMATCH)


def test_f_forged_plan_id(service, reference, apks, tmp_path) -> None:
    planning = _planning(reference, apks["h5_isolated"])
    data = json.loads(planning.to_json())
    plan = data["decisions"][0]["plan"]
    plan["plan_id"] = "plan-00000000000000000000"
    res = _run(service, reference, apks["h5_isolated"], _write(plan, tmp_path / "t.json"), tmp_path)
    _assert_refused(res, AR.PLAN_ID_MISMATCH)


def test_f_tampered_expected_changes(service, reference, apks, tmp_path) -> None:
    planning = _planning(reference, apks["h5_isolated"])
    data = json.loads(planning.to_json())
    plan = data["decisions"][0]["plan"]
    plan["expected_changes"].append("nothing else")
    res = _run(service, reference, apks["h5_isolated"], _write(plan, tmp_path / "t.json"), tmp_path)
    _assert_refused(res, AR.PLAN_MISMATCH)


# ---------------------------------------------------------------------------
# G CLI + corpus hygiene
# ---------------------------------------------------------------------------


def _cli(args: list[str], base: Path) -> Result:
    env = {"FORCE_COLOR": "3", "APKFORGE_DEV_KEY_DIR": str(base / "dev-key")}
    return CliRunner().invoke(app, args, env=env)


def test_g_cli_plan_then_apply(apks, base, tmp_path) -> None:
    apk = apks["h5_isolated"]
    before = _sha(apk)
    work = ["--work-dir", str(tmp_path / "ws")]
    plan = tmp_path / "plan.json"
    res = _cli(["transform", str(apk), "-t", C2, "--target", TARGET, "--report", str(plan), *work],
               base)  # fmt: skip
    assert res.exit_code == 0, res.output
    res = _cli(["transform", str(apk), "--plan", str(plan), "--json", *work], base)
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["status"] == "PLANNED"
    out = tmp_path / "out.apk"
    report = tmp_path / "h5.md"
    res = _cli(["transform", str(apk), "--plan", str(plan), "--apply", "-o", str(out),
                "--report", str(report), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "VERIFIED" in res.output and out.is_file()
    text = report.read_text()
    assert "| Target method after | absent" in text and "\x1b" not in text
    assert _sha(apk) == before


def test_g_published_fixtures_are_v2_only(apks) -> None:
    with zipfile.ZipFile(apks["h5_isolated"]) as z:
        assert not [n for n in z.namelist() if n.startswith("META-INF/")]
