"""Phase H.6 integration: applying H.2 plans for H-TRANS-003 (controlled call-site
replacement).

Real synthetic APKs (tests/fixtures/h6_apks.py), published like real apps, are planned
through H.1 -> H.2, applied with :class:`TransformationExecutor` and verified against an
unmodified control rebuild with :class:`ControlExperiment` / H.4. Skipped when the build
toolchain is unavailable.

A  positive static replacement (H.6 VERIFIED + H.4 VERIFIED/COMPLETE)
B  wide/primitive arguments + primitive result, private-instance invoke-direct, the
   second of two identical calls (only the selected call site changes; H.4 too)
C  H.2 refusals cannot be bypassed; an already transformed APK; a conflicting request set
D  mutation faults (wrong call site, two call sites, wrong replacement / descriptor,
   unrelated method / class) detected before build
E  build-time faults (second call site, other method / class, resource, manifest,
   native, asset) rejected by H.4; nothing published
F  call site gone before mutation / source SHA mismatch / forged plan / tampered plan
G  reproducibility, SHA preservation, CLI
"""

# ruff: noqa: E501 - verbatim smali call-site targets (long type descriptors) cannot be wrapped

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner, Result

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.cli.main import app
from apkforge.inspection.dex import DEXInspector
from apkforge.modification.pipeline import measure_noise_floor
from apkforge.reference import ReferenceAnalysisService
from apkforge.transformation import (
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CheckOutcome,
    ControlExperiment,
    ControlPresence,
    DecisionReason,
    EligibilityState,
    PlanningResult,
    ReplaceCallSiteModifier,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationStatus,
)
from apkforge.transformation.planner import decision_id_for
from tests.fixtures.h6_apks import (
    ARGS_REPLACEMENT,
    ARGS_TARGET,
    CALLER_SMALI,
    FAULTS,
    INSTANCE_REPLACEMENT,
    INSTANCE_TARGET,
    PKG,
    REPEATED_TARGET,
    REPLACEMENT,
    STATIC_TARGET,
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
C3 = "H-TRANS-003"
G = "getValue()Ljava/lang/String;"
_P = PKG.replace(".", "/")
SRC_REF = f"L{_P}/Source;->{G}"
REP_REF = f"L{_P}/Replacement;->{G}"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("h6")


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
def baseline(service: BuildService, apks: dict[str, Path], base: Path) -> NoopSemanticBaseline:
    bl = measure_noise_floor(service, apks["h6_callsite"], work_dir=base / "noise")
    assert bl.entries[0].result == "EQUIVALENT", bl.entries[0]
    return bl


def _planning(
    reference: ReferenceAnalysisService,
    apk: Path,
    target: str = STATIC_TARGET,
    replacement: str = REPLACEMENT,
    *extra: TransformationRequest,
) -> PlanningResult:
    before = _sha(apk)
    req = TransformationRequest(
        transformation_id=C3, target=target, parameters={"replacement": replacement}
    )
    res = TransformationPlanningService(reference).plan(apk, [req, *extra])
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
    if res.status is not AS.VERIFIED:
        assert not out.exists() and res.output_apk is None
    return res


def _assert_refused(res: TransformationApplicationResult, code: ApplicationReason) -> None:
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is code, res.failure
    assert AS.APPLYING not in res.status_history
    assert res.mutation is None and res.output_apk is None


def _code_hashes(apk: Path, cls: str) -> dict[str, str | None]:
    insp, _ = DEXInspector().inspect(apk)
    return {
        f"{m.name}({','.join(m.parameters)}){m.return_type}": m.code_hash
        for df in insp.dex_files
        if df.inventory
        for m in df.inventory.methods
        if m.class_name == cls
    }


def _calls(
    reference: ReferenceAnalysisService, apk: Path, method: str, cls: str = f"{PKG}.A"
) -> list[str]:
    result = reference.analyze(apk)
    return [e.target for e in result.index().invocations_in(cls, method)]


# ---------------------------------------------------------------------------
# A positive static replacement
# ---------------------------------------------------------------------------


def test_a_positive_static_call_site(service, reference, apks, baseline, tmp_path) -> None:
    apk = apks["h6_callsite"]
    planning = _planning(reference, apk)
    (decision,) = planning.decisions
    assert decision.eligibility is ES.ELIGIBLE and decision.plan is not None
    res = _run(service, reference, apk, _write(planning, tmp_path / "plan.json"), tmp_path,
               baseline=baseline)  # fmt: skip
    assert res.status is AS.VERIFIED, (res.failure, res.diff)
    assert res.status_history == [AS.PLANNED, AS.APPLYING, AS.BUILT, AS.VERIFIED]
    assert [r.status for r in res.verification] == [CheckOutcome.PASS] * 15
    m = res.mutation
    assert m is not None and m.operation == "REPLACE_CALL_SITE" and m.count == 1
    assert m.target_file == CALLER_SMALI and m.changed_lines == [m.source_line]
    assert m.original_instruction == f"invoke-static {{}}, {SRC_REF}"
    assert m.replacement_instruction == f"invoke-static {{}}, {REP_REF}"
    assert len(m.removed_invocations) == len(m.added_invocations) == 1 and not m.other_changes
    assert (m.classes_before, m.classes_after) == (3, 3)
    # Phase E: exactly the declared changes (the caller method's code + the new API reference)
    assert res.diff["passed"] and not res.diff["unexpected"] and not res.diff["expected_missing"]
    assert sorted(res.diff["expected_observed"]) == [
        "dex_api_reference added com.example.h1.Replacement;->getValue()Ljava.lang.String",
        f"dex_class modified {PKG}.A",
    ]
    # call-site H.1 re-analysis
    ca = res.call_site_analysis
    assert ca is not None and ca.sufficient and ca.caller_present
    assert ca.changed_positions == [0] and ca.replacement_at_planned_position
    assert (ca.original_calls_before, ca.original_calls_after) == (1, 0)
    assert (ca.replacement_calls_before, ca.replacement_calls_after) == (0, 1)
    assert not ca.other_reference_changes and not ca.caller_reference_changes
    assert not ca.declaration_changes
    # the published APK, checked independently: only A.run's code differs
    out = Path(res.output_apk or "")
    assert out.is_file() and _sha(out) == res.output_apk_sha256
    before, after = _code_hashes(apk, f"{PKG}.A"), _code_hashes(out, f"{PKG}.A")
    assert before.keys() == after.keys()
    assert [k for k in before if before[k] != after[k]] == ["run()java.lang.String"]
    for cls in ("Source", "Replacement"):
        assert _code_hashes(apk, f"{PKG}.{cls}") == _code_hashes(out, f"{PKG}.{cls}")
    assert _calls(reference, out, "run()Ljava/lang/String;") == [f"{PKG}.Replacement.{G}"]


def test_a_h4_verifies_the_replacement(service, reference, apks, tmp_path) -> None:
    apk = apks["h6_callsite"]
    exp = ControlExperiment(service, reference_service=reference)
    res = exp.run(apk, _planning(reference, apk), tmp_path / "exp")
    assert res.application is not None and res.application.status is AS.VERIFIED
    v = res.verification
    from apkforge.verification.models import CheckStatus

    assert v.status is S.VERIFIED, v.status_reason
    assert v.completeness.value == "COMPLETE"
    assert all(d.status is CheckStatus.PASSED for d in v.domains.values()), v.status_reason
    assert not v.unexpected_changes and not v.unknown_changes
    inv = {i.name: i.status for i in v.invariants}
    for name in (
        "caller_class_retained",
        "exactly_one_method_body_changed[original->transformed]",
        "exactly_one_method_body_changed[control->transformed]",
        "no_other_change[original->transformed]",
        "no_other_change[control->transformed]",
        "h1_call_site_state",
        "declared_changes_observed",
    ):
        assert inv[name] is CheckStatus.PASSED, name
    # the transformation signal is exactly the declared change (+ the planned DEX entry)
    assert {(d.observation.category, d.observation.identifier) for d in v.expected_changes} == {
        ("dex_class", f"{PKG}.A"),
        ("dex_api_reference", "com.example.h1.Replacement;->getValue()Ljava.lang.String"),
        ("file", "classes.dex"),
    }
    cpa = v.call_site_post_analysis
    assert cpa is not None and cpa.replacement_at_planned_position
    assert _sha(apk) == res.original_sha256 == res.original_sha256_after


def test_a_dry_run_and_output_path(service, reference, apks, tmp_path) -> None:
    apk = apks["h6_callsite"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path, apply=False)
    assert res.status is AS.PLANNED and res.dry_run and res.failure is None
    assert res.planned_changes[0]["type"] == "replace_call_site"
    assert res.mutation is None and not res.build and not res.verification
    ex = TransformationExecutor(service, reference_service=reference)
    bad = ex.run(apk, _planning(reference, apk), apply=True, output_apk=apk)
    _assert_refused(bad, AR.OUTPUT_INVALID)


# ---------------------------------------------------------------------------
# B the other positive shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "replacement", "method", "calls_after"),
    [
        (ARGS_TARGET, ARGS_REPLACEMENT, "calc(IJLjava/lang/String;)I",
         [f"{PKG}.Replacement.compute(IJLjava/lang/String;)I"]),
        (INSTANCE_TARGET, INSTANCE_REPLACEMENT, "instanceCall()Ljava/lang/String;",
         [f"{PKG}.A.secretAlt()Ljava/lang/String;"]),
        (REPEATED_TARGET, REPLACEMENT, "twice()Ljava/lang/String;",
         [f"{PKG}.Source.{G}", f"{PKG}.Replacement.{G}"]),
    ],
)  # fmt: skip
def test_b_positive_shapes(
    service, reference, apks, baseline, tmp_path, target, replacement, method, calls_after
) -> None:
    apk = apks["h6_callsite"]
    planning = _planning(reference, apk, target, replacement)
    assert planning.decisions[0].eligibility is ES.ELIGIBLE
    res = _run(service, reference, apk, planning, tmp_path, baseline=baseline)
    assert res.status is AS.VERIFIED, (res.failure, res.diff)
    m = res.mutation
    assert m is not None and m.count == 1 and m.changed_lines == [m.source_line]
    ca = res.call_site_analysis
    assert ca is not None and len(ca.changed_positions) == 1 and ca.replacement_at_planned_position
    out = Path(res.output_apk or "")
    assert _calls(reference, out, method) == calls_after
    # registers and result handling are unchanged
    before = res.call_site_analysis.invocations_before  # type: ignore[union-attr]
    after = res.call_site_analysis.invocations_after  # type: ignore[union-attr]
    (pos,) = ca.changed_positions

    def regs_and_result(s: str) -> tuple[str, str]:
        return s[s.index("{") : s.index("}") + 1], s.partition(" -> ")[2]

    assert regs_and_result(before[pos]) == regs_and_result(after[pos])


def test_b_h4_repeated_call_site(service, reference, apks, tmp_path) -> None:
    apk = apks["h6_callsite"]
    exp = ControlExperiment(service, reference_service=reference)
    res = exp.run(apk, _planning(reference, apk, REPEATED_TARGET), tmp_path / "exp")
    v = res.verification
    assert v.status is S.VERIFIED, v.status_reason
    cpa = v.call_site_post_analysis
    assert cpa is not None and cpa.changed_positions == [1]  # #2, not #1
    assert (cpa.original_calls_before, cpa.original_calls_after) == (2, 1)


# ---------------------------------------------------------------------------
# C refusals, already transformed, conflicts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "target", "replacement", "state", "codes"),
    [
        ("h6_callsite", f"{PKG}.A->run()Ljava/lang/String;@{PKG}.Source->missing()V", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_NOT_FOUND}),
        ("h6_callsite", f"{PKG}.A->over@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_AMBIGUOUS}),
        ("h6_callsite", f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_MULTIPLE_MATCHES}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueInstance()Ljava/lang/String;",
         ES.REFUSED, {R.REPLACEMENT_SIGNATURE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueArg(I)Ljava/lang/String;",
         ES.REFUSED, {R.REGISTER_TYPE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueInt()I",
         ES.REFUSED, {R.RESULT_TYPE_MISMATCH}),
        ("h6_callsite", f"{PKG}.A->make()Ljava/lang/Object;@{PKG}.Source-><init>()V", REPLACEMENT,
         ES.UNSUPPORTED, {R.CONSTRUCTOR_INVOCATION}),
        ("h6_dynamic", f"{PKG}.A->poly(Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;@java.lang.invoke.MethodHandle->invoke",
         REPLACEMENT, ES.UNSUPPORTED, {R.INVOKE_POLYMORPHIC_UNSUPPORTED}),
        ("h6_dynamic", f"{PKG}.D->custom()Ljava/lang/Runnable;@{PKG}.Source->bsm", REPLACEMENT,
         ES.UNSUPPORTED, {R.INVOKE_CUSTOM_UNSUPPORTED}),
        ("h6_dynamic", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.DEX_ANALYSIS_INCOMPLETE}),
        ("h6_dynamic", f"{PKG}.D->mixed()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT,
         ES.UNDETERMINED, {R.CALLER_ANALYSIS_INCOMPLETE}),
        ("h6_reflection", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("h6_native", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.NATIVE_DEPENDENCY_UNKNOWN}),
    ],
)  # fmt: skip
def test_c_ineligible_plans_are_refused(
    service, reference, apks, tmp_path, fixture, target, replacement, state, codes
) -> None:
    apk = apks[fixture]
    planning = _planning(reference, apk, target, replacement)
    (d,) = planning.decisions
    assert d.eligibility is state and codes <= {r.code for r in d.reasons}, d.reasons
    assert d.plan is None
    res = _run(service, reference, apk, _write(planning, tmp_path / "p.json"), tmp_path)
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)
    assert res.failure is not None and res.failure.details["eligibility"] == state.value


def test_c_already_transformed_apk(service, reference, apks, baseline, tmp_path) -> None:
    """Re-planning the same call site on H.6's own (verified) output is refused."""
    apk = apks["h6_callsite"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path, baseline=baseline)
    assert res.status is AS.VERIFIED
    out = Path(res.output_apk or "")
    (d,) = _planning(reference, out).decisions
    assert d.eligibility is ES.REFUSED
    assert {r.code for r in d.reasons} == {R.CALL_SITE_ALREADY_REPLACED}


def test_c_conflicting_request_set(reference, apks) -> None:
    removal = TransformationRequest(transformation_id="H-TRANS-002", target=REPLACEMENT)
    planning = _planning(reference, apks["h6_callsite"], STATIC_TARGET, REPLACEMENT, removal)
    assert [d.eligibility for d in planning.decisions] == [ES.REFUSED, ES.REFUSED]
    assert all(
        R.CONFLICTING_TRANSFORMATION in {r.code for r in d.reasons} for d in planning.decisions
    )
    assert planning.conflicts and planning.conflicts[0].kind == "call_site_overlap"


# ---------------------------------------------------------------------------
# D mutation faults (detected before any build)
# ---------------------------------------------------------------------------


def _fault_run(
    service, reference, apks, baseline, tmp_path, patch: Callable[[Any, str], str | None],
    target: str = REPEATED_TARGET,
) -> TransformationApplicationResult:  # fmt: skip
    mp = pytest.MonkeyPatch()
    mp.setattr(ReplaceCallSiteModifier, "_rewrite", lambda self, text: patch(self, text))
    try:
        apk = apks["h6_callsite"]
        return _run(service, reference, apk, _planning(reference, apk, target), tmp_path,
                    baseline=baseline)  # fmt: skip
    finally:
        mp.undo()


def _nth(text: str, old: str, new: str, n: int) -> str:
    """Replace only the n-th (1-based) occurrence of *old*."""
    parts = text.split(old)
    return old.join(parts[:n]) + new + old.join(parts[n:])


def _first_twice(text: str) -> int:
    start = text.index("twice()")
    return text[:start].count(SRC_REF) + 1


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_call_site",
        "two_call_sites",
        "wrong_replacement",
        "wrong_descriptor",
        "unrelated_method",
        "unrelated_class",
    ],
)
def test_d_mutation_faults(service, reference, apks, baseline, tmp_path, fault) -> None:
    def patch(self: Any, text: str) -> str | None:
        k = _first_twice(text)  # occurrence index of twice()'s first call in the file
        if fault == "wrong_call_site":  # #1 instead of the planned #2
            return _nth(text, SRC_REF, REP_REF, k)
        if fault == "two_call_sites":
            return _nth(_nth(text, SRC_REF, REP_REF, k + 1), SRC_REF, REP_REF, k)
        if fault == "wrong_replacement":
            return _nth(
                text, SRC_REF, f"L{_P}/Replacement;->getValueInstance()Ljava/lang/String;", k + 1
            )
        if fault == "wrong_descriptor":
            return _nth(text, SRC_REF, f"L{_P}/Replacement;->getValue()Ljava/lang/Object;", k + 1)
        good = _nth(text, SRC_REF, REP_REF, k + 1)
        if fault == "unrelated_method":
            return good.replace("move-result v0\n", "move-result v0\n    nop\n", 1)
        root = Path(self._root)  # unrelated_class: another file of the project changes
        src = root / "smali/com/example/h1/Source.smali"
        src.write_text(src.read_text().replace('"h6-source"', '"h6-tampered"'))
        return good

    mp = pytest.MonkeyPatch()
    real_apply = ReplaceCallSiteModifier.apply

    def apply(self: Any, plan: Any, project: Any) -> Any:
        self._root = project.decoded_dir
        return real_apply(self, plan, project)

    mp.setattr(ReplaceCallSiteModifier, "apply", apply)
    try:
        res = _fault_run(service, reference, apks, baseline, tmp_path, patch)
    finally:
        mp.undo()
    assert res.status is AS.FAILED and res.failure is not None, res.failure
    assert res.failure.code is AR.UNEXPECTED_MUTATION, res.failure
    assert res.failure.stage is ApplicationStage.MUTATION
    assert "build" not in [s["stage"] for s in res.build.get("stages", [])]
    m = res.mutation
    assert m is not None
    if fault == "two_call_sites":
        assert m.count == 2 and len(m.changed_lines) == 2
    if fault == "unrelated_class":
        assert any("Source.smali" in x for x in m.other_changes)


def test_d_h6_modifier_cannot_be_requested_through_modify() -> None:
    from apkforge.modification.catalog import default_catalog
    from apkforge.transformation import H6_MODIFIER_ID

    assert H6_MODIFIER_ID not in default_catalog()


# ---------------------------------------------------------------------------
# E build-time faults rejected by H.4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fault", sorted(FAULTS))
def test_e_build_faults_fail_verification(service, reference, apks, tmp_path, fault) -> None:
    edit, domain = FAULTS[fault]
    exp = ControlExperiment(service, reference_service=reference)
    with inject_at_build(service, edit):
        res = exp.run(apks["h6_callsite"], _planning(reference, apks["h6_callsite"]),
                      tmp_path / f"fault-{fault}", verify_unpublished=True)  # fmt: skip
    app_res = res.application
    assert app_res is not None and app_res.status is AS.FAILED  # H.6 refuses to publish
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
    if domain == "dex":
        inv = {i.name: i.status for i in v.invariants}
        assert inv["h1_call_site_state"] is CheckStatus.FAILED


# ---------------------------------------------------------------------------
# F integrity: call site gone / sha mismatch / forged plan
# ---------------------------------------------------------------------------


class _DropCallOnDecode(BuildService):
    """A BuildService whose decoded workspace no longer invokes the original at the
    planned site (simulated drift between planning and application)."""

    def decode(
        self, input_apk: Path | str, workspace: BuildWorkspace, *, timeout: int | None = None
    ) -> StageResult:
        stage = super().decode(input_apk, workspace, timeout=timeout)
        path = workspace.decoded_dir / CALLER_SMALI
        text = path.read_text()
        start = text.index("run()")
        path.write_text(text[:start] + text[start:].replace(SRC_REF, REP_REF, 1))
        return stage


def test_f_call_site_missing_in_workspace(service, reference, apks, baseline, tmp_path) -> None:
    drifting = _DropCallOnDecode(service.toolchain, service.signing, work_dir=tmp_path / "ws")
    ex = TransformationExecutor(drifting, reference_service=reference)
    apk = apks["h6_callsite"]
    res = _run(service, reference, apk, _planning(reference, apk), tmp_path, baseline=baseline,
               executor=ex)  # fmt: skip
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is AR.TARGET_NOT_FOUND
    assert res.failure.stage is ApplicationStage.PRE_TRANSFORM
    assert res.mutation is None


def test_f_source_sha_mismatch(service, reference, apks, tmp_path) -> None:
    plan = _write(_planning(reference, apks["h6_callsite"]), tmp_path / "a.json")
    res = _run(service, reference, apks["h6_callsite_alt"], plan, tmp_path)
    _assert_refused(res, AR.SOURCE_SHA_MISMATCH)


def test_f_forged_plan_id(service, reference, apks, tmp_path) -> None:
    data = json.loads(_planning(reference, apks["h6_callsite"]).to_json())
    plan = data["decisions"][0]["plan"]
    plan["plan_id"] = "plan-00000000000000000000"
    res = _run(service, reference, apks["h6_callsite"], _write(plan, tmp_path / "t.json"), tmp_path)
    _assert_refused(res, AR.PLAN_ID_MISMATCH)


def test_f_tampered_call_site_details(service, reference, apks, tmp_path) -> None:
    """Editing the plan's replacement (or line) keeps the id but not H.2's plan."""
    for key, value in (("replacement", f"L{_P}/Replacement;->getValueInstance()Ljava/lang/String;"),
                       ("source_line", "1")):  # fmt: skip
        data = json.loads(_planning(reference, apks["h6_callsite"]).to_json())
        plan = data["decisions"][0]["plan"]
        plan["planned_changes"][0]["details"][key] = value
        res = _run(service, reference, apks["h6_callsite"], _write(plan, tmp_path / "t.json"),
                   tmp_path)  # fmt: skip
        _assert_refused(res, AR.PLAN_MISMATCH)


def test_f_forged_plan_rebound_to_ineligible_call_site(service, reference, apks, tmp_path) -> None:
    """A valid plan rebound (with a recomputed id) to the h6_reflection APK, where the same
    call site is UNDETERMINED, is refused by the H.2 re-evaluation."""
    good = _planning(reference, apks["h6_callsite"]).decisions[0].plan
    assert good is not None
    forged: dict[str, Any] = json.loads(good.model_dump_json())
    sha = _sha(apks["h6_reflection"])
    forged["apk"]["sha256"] = sha
    did = decision_id_for(sha, C3, STATIC_TARGET, good.parameters, forged["analysis_schema"])
    forged["plan_id"] = f"plan-{did}"
    res = _run(service, reference, apks["h6_reflection"], _write(forged, tmp_path / "f.json"),
               tmp_path)  # fmt: skip
    _assert_refused(res, AR.PLAN_NOT_ELIGIBLE)
    assert res.failure is not None and res.failure.stage is ApplicationStage.ELIGIBILITY


# ---------------------------------------------------------------------------
# G reproducibility, CLI, corpus hygiene
# ---------------------------------------------------------------------------


def test_g_reproducibility_and_sha_preservation(
    service, reference, apks, baseline, tmp_path
) -> None:
    apk = apks["h6_callsite"]
    before = _sha(apk)
    plannings = [_planning(reference, apk, REPEATED_TARGET) for _ in (1, 2)]
    assert plannings[0].to_json() == plannings[1].to_json()  # identical plan + eligibility
    plan = _write(plannings[0], tmp_path / "plan.json")
    runs = [
        _run(service, reference, apk, plan, tmp_path / f"r{i}", baseline=baseline) for i in (1, 2)
    ]
    assert all(r.status is AS.VERIFIED for r in runs)
    assert runs[0].comparable() == runs[1].comparable()  # mutation record, post-analysis...
    assert runs[0].mutation == runs[1].mutation
    assert runs[0].call_site_analysis == runs[1].call_site_analysis
    # identical entry contents (outer APK bytes may differ: ZIP timestamps / signing)
    assert runs[0].output_content_sha256 == runs[1].output_content_sha256
    assert _sha(apk) == before


def _cli(args: list[str], base: Path) -> Result:
    env = {"FORCE_COLOR": "3", "APKFORGE_DEV_KEY_DIR": str(base / "dev-key")}
    return CliRunner().invoke(app, args, env=env)


def test_g_cli_plan_then_apply(apks, base, tmp_path) -> None:
    apk = apks["h6_callsite"]
    before = _sha(apk)
    work = ["--work-dir", str(tmp_path / "ws")]
    plan = tmp_path / "plan.json"
    res = _cli(["transform", str(apk), "-t", C3, "--target", STATIC_TARGET, "--replacement",
                REPLACEMENT, "--report", str(plan), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    res = _cli(["transform", str(apk), "-t", C3, "--target", STATIC_TARGET, "--replacement",
                REPLACEMENT, "--json", *work], base)  # fmt: skip
    assert res.exit_code == 0 and "\x1b" not in res.stdout
    assert json.loads(res.stdout)["decisions"][0]["eligibility"] == "ELIGIBLE"
    res = _cli(["transform", str(apk), "--plan", str(plan), "--json", *work], base)
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["status"] == "PLANNED" and "\x1b" not in res.stdout
    out = tmp_path / "out.apk"
    report = tmp_path / "h6.md"
    res = _cli(["transform", str(apk), "--plan", str(plan), "--apply", "-o", str(out),
                "--report", str(report), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "VERIFIED" in res.output and out.is_file()
    text = report.read_text()
    assert "| Replacement invocation after | exactly at the planned location" in text
    assert "Phase H.6" in text and "\x1b" not in text
    assert _sha(apk) == before


def test_g_cli_refused_plan_exit_code(apks, base, tmp_path) -> None:
    apk = apks["h6_callsite"]
    work = ["--work-dir", str(tmp_path / "ws")]
    plan = tmp_path / "plan.json"
    target = f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}"
    res = _cli(["transform", str(apk), "-t", C3, "--target", target, "--replacement",
                REPLACEMENT, "--report", str(plan), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output  # planning itself succeeded (decision REFUSED)
    res = _cli(["transform", str(apk), "--plan", str(plan), "--apply", "-o",
                str(tmp_path / "o.apk"), "--json", *work], base)  # fmt: skip
    assert res.exit_code == 3 and json.loads(res.stdout)["status"] == "REFUSED"
    assert not (tmp_path / "o.apk").exists()


def test_g_published_fixtures_are_v2_only(apks) -> None:
    with zipfile.ZipFile(apks["h6_callsite"]) as z:
        assert not [n for n in z.namelist() if n.startswith("META-INF/")]
