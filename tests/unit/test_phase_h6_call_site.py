"""Phase H.6 unit tests: H-TRANS-003 controlled call-site replacement.

Everything here runs without the build toolchain: the H.6 fixtures' Apktool projects are
indexed directly (``ReferenceAnalysisService.analyze_decoded``) and planned with the H.2
planner; the executor is exercised only up to its integrity checks.

A  H.1 schema 3 (registers, move-result, invoke-custom record)
B  call-site target and replacement parsing, determinism
C  eligibility decisions (positive shapes and every refusal class)
D  register / result safety on tampered evidence
E  conflicts
F  the single-line rewrite and the exact-mutation comparison
G  plan loading / executor integrity / CLI usage / report
"""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.reference import ApkIdentity, ReferenceAnalysisService
from apkforge.reference.models import SCHEMA_VERSION, InvokeKind, ReferenceKind, evidence_id_for
from apkforge.reference.smali import parse_smali
from apkforge.transformation import (
    CATALOG,
    H6_MODIFIER_ID,
    ApplicationReason,
    ApplicationStatus,
    DecisionReason,
    EligibilityState,
    PlanningResult,
    TargetKind,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlan,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
    format_application_report,
    format_planning_report,
)
from apkforge.transformation.dexstate import replace_invocation
from apkforge.transformation.eligibility import expected_result_instruction, register_words
from apkforge.transformation.executor import _matrix, _Refusal, load_plan
from apkforge.transformation.modifier import invocation_diff
from apkforge.transformation.planner import decision_id_for
from apkforge.transformation.targets import ParseError, parse_target
from tests.fixtures.h1_apks import write_project
from tests.fixtures.h6_apks import (
    ARGS_REPLACEMENT,
    ARGS_TARGET,
    CALLER_SMALI,
    H6_FIXTURES,
    INSTANCE_REPLACEMENT,
    INSTANCE_TARGET,
    PKG,
    REPEATED_TARGET,
    REPLACEMENT,
    STATIC_TARGET,
)

AR = ApplicationReason
AS = ApplicationStatus
ES = EligibilityState
R = DecisionReason
C3 = "H-TRANS-003"
ALL = {fx.name: fx for fx in H6_FIXTURES}
G = "getValue()Ljava/lang/String;"


def _result(tmp_path: Path, fixture: str, sha: str = "0" * 64) -> Any:
    project = tmp_path / "projects" / fixture
    if not project.exists():
        write_project(ALL[fixture], project)
    return ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name=f"{fixture}.apk", sha256=sha)
    )


def _req(
    target: str, replacement: str | None = REPLACEMENT, tid: str = C3
) -> TransformationRequest:
    params = {"replacement": replacement} if replacement is not None else {}
    return TransformationRequest(transformation_id=tid, target=target, parameters=params)


def _decide(
    tmp_path: Path, fixture: str, target: str, replacement: str | None = REPLACEMENT
) -> Any:
    planning = TransformationPlanner(_result(tmp_path, fixture)).plan([_req(target, replacement)])
    return planning.decisions[0]


def _codes(d: Any) -> set[DecisionReason]:
    return {r.code for r in d.reasons}


# ---------------------------------------------------------------------------
# A  H.1 schema 3
# ---------------------------------------------------------------------------

_SMALI = """\
.class public Lcom/x/T;
.super Ljava/lang/Object;

.method public static m(JLjava/lang/String;)I
    .registers 6
    invoke-static {p0, p1, p2}, Lcom/x/S;->f(JLjava/lang/String;)I

    .line 7
    move-result v0
    invoke-static/range {p0 .. p2}, Lcom/x/S;->f(JLjava/lang/String;)I
    invoke-static {}, Lcom/x/S;->g()V
    move-result-wide v1
    invoke-custom {v0}, call_site_0("run", (I)Ljava/lang/Runnable;)@Lcom/x/S;->bsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    move-result-object v2
    return v0
.end method
"""


def test_a_schema_3_invocation_registers_and_results() -> None:
    assert SCHEMA_VERSION == 3
    res = parse_smali(_SMALI, "smali/com/x/T.smali", "classes.dex")
    inv = [e for e in res.evidence if e.kind is ReferenceKind.METHOD_REFERENCE]
    assert [(e.source_line, e.instruction) for e in inv] == [
        (6, "invoke-static"),
        (10, "invoke-static/range"),
        (11, "invoke-static"),
        (13, "invoke-custom"),
    ]
    first, rng, void, custom = inv
    # a blank line and a .line directive between invoke and move-result do not break it
    assert first.registers == ("p0", "p1", "p2")
    assert (first.result_instruction, first.result_register) == ("move-result", "v0")
    # /range is expanded; nothing consumes its value
    assert rng.registers == ("p0", "p1", "p2") and rng.result_register is None
    # the record keeps whatever follows (H.2 checks it against the descriptor)
    assert (void.result_instruction, void.result_register) == ("move-result-wide", "v1")
    # invoke-custom: recorded against its bootstrap method, the file stays PARTIAL
    assert custom.invoke_kind is InvokeKind.CUSTOM and custom.registers == ("v0",)
    assert custom.target.startswith("com.x.S.bsm(") and custom.context == "call-site-bootstrap"
    assert custom.result_register == "v2"
    assert res.state.value == "PARTIAL"
    assert [i.code for i in res.issues] == ["UNSUPPORTED_INSTRUCTION"]


def test_a_evidence_ids_do_not_depend_on_schema_3_fields() -> None:
    res = parse_smali(_SMALI, "smali/com/x/T.smali", "classes.dex")
    e = next(e for e in res.evidence if e.kind is ReferenceKind.METHOD_REFERENCE)
    before = e.evidence_id
    e.registers, e.result_register, e.result_instruction = None, None, None
    assert evidence_id_for(e) == before  # schema-2 ids stay stable


def test_a_invocations_in_index(tmp_path: Path) -> None:
    result = _result(tmp_path, "h6_callsite")
    calls = result.index().invocations_in(f"{PKG}.A", "twice()Ljava/lang/String;")
    assert [e.target for e in calls] == [f"{PKG}.Source.{G}"] * 2
    assert calls[0].source_line < calls[1].source_line
    assert [e.result_register for e in calls] == ["v0", "v1"]
    assert result.index().invocations_in(f"{PKG}.A", "nope()V") == []


# ---------------------------------------------------------------------------
# B  parsing / determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        (STATIC_TARGET, STATIC_TARGET),
        (f"Lcom/example/h1/A;->run()Ljava/lang/String;@Lcom/example/h1/Source;->{G}",
         STATIC_TARGET),
        (REPEATED_TARGET, REPEATED_TARGET),
        (f"{PKG}.A->over@{PKG}.Source->getValue", f"{PKG}.A->over@{PKG}.Source->getValue"),
    ],
)  # fmt: skip
def test_b_call_site_targets_normalise(raw: str, canonical: str) -> None:
    t = parse_target(TargetKind.CALL_SITE, raw)
    assert not isinstance(t, ParseError) and t.kind is TargetKind.CALL_SITE
    assert t.canonical == canonical and t.raw == raw


@pytest.mark.parametrize(
    "raw",
    [
        f"{PKG}.A->run()V",  # no invoked part
        f"{PKG}.A->run()V@{PKG}.B->x()V@{PKG}.C->y()V",
        f"{PKG}.A->run()V@{PKG}.B->x()V#0",
        f"{PKG}.A->run()V@{PKG}.B->x()V#two",
        f"{PKG}.A@{PKG}.B->x()V",  # caller is a class, not a method
        f"{PKG}.A->run(Q)V@{PKG}.B->x()V",
    ],
)
def test_b_malformed_call_site_targets(raw: str) -> None:
    assert isinstance(parse_target(TargetKind.CALL_SITE, raw), ParseError)


def test_b_unparseable_target_is_unsupported(tmp_path: Path) -> None:
    d = _decide(tmp_path, "h6_callsite", f"{PKG}.A->run()V")
    assert d.eligibility is ES.UNSUPPORTED and _codes(d) == {R.UNSUPPORTED_TARGET_TYPE}


def test_b_plan_is_deterministic_and_normalises_the_replacement(tmp_path: Path) -> None:
    result = _result(tmp_path, "h6_callsite", sha="a" * 64)
    smali_form = "Lcom/example/h1/Replacement;->" + G
    plans = [
        TransformationPlanner(result).plan([_req(STATIC_TARGET, repl)]).decisions[0].plan
        for repl in (REPLACEMENT, REPLACEMENT, smali_form)
    ]
    assert all(p is not None for p in plans)
    assert plans[0] == plans[1]
    assert plans[0].plan_id == plans[2].plan_id  # type: ignore[union-attr]
    p = plans[0]
    assert p is not None and p.parameters == {"replacement": REPLACEMENT}
    did = decision_id_for("a" * 64, C3, STATIC_TARGET, {"replacement": REPLACEMENT}, SCHEMA_VERSION)
    assert p.plan_id == f"plan-{did}"
    # different replacement / occurrence -> different plan id
    other = TransformationPlanner(result).plan([_req(ARGS_TARGET, ARGS_REPLACEMENT)])
    assert other.decisions[0].plan.plan_id != p.plan_id  # type: ignore[union-attr]
    json.loads(p.model_dump_json())  # serialisable; no paths / timestamps
    assert "/tmp" not in p.model_dump_json()


def test_b_plan_content(tmp_path: Path) -> None:
    d = _decide(tmp_path, "h6_callsite", ARGS_TARGET, ARGS_REPLACEMENT)
    assert d.eligibility is ES.ELIGIBLE and d.plan is not None
    (ch,) = d.plan.planned_changes
    assert ch.type == "replace_call_site" and ch.artifact == CALLER_SMALI
    det = ch.details
    assert (
        det["caller_class"] == f"{PKG}.A" and det["caller_method"] == "calc(IJLjava/lang/String;)I"
    )
    assert det["opcode"] == "invoke-static" and det["registers"] == "p0, p1, p2, p3"
    assert det["register_count"] == "4"
    assert (det["result_instruction"], det["result_register"]) == ("move-result", "v0")
    assert det["original"] == "Lcom/example/h1/Source;->compute(IJLjava/lang/String;)I"
    assert det["replacement"] == "Lcom/example/h1/Replacement;->compute(IJLjava/lang/String;)I"
    assert (det["occurrence"], det["occurrences_in_caller"]) == ("1", "1")
    assert det["expected_mutation_count"] == "1" and det["source_line"].isdigit()
    assert det["evidence_id"].startswith("ev-")
    assert any("exactly 1 call site changes" in x for x in d.plan.expected_changes)
    summary = {c.category: c for c in d.plan.target_evidence_summary.categories}
    assert summary["selected_call_site"].evidence_ids == [det["evidence_id"]]


# ---------------------------------------------------------------------------
# C  eligibility
# ---------------------------------------------------------------------------

_P = PKG.replace(".", "/")


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        (STATIC_TARGET, REPLACEMENT),
        (ARGS_TARGET, ARGS_REPLACEMENT),
        (INSTANCE_TARGET, INSTANCE_REPLACEMENT),
        (REPEATED_TARGET, REPLACEMENT),
        (f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}#1", REPLACEMENT),
    ],
)
def test_c_positive_shapes_are_eligible(tmp_path: Path, target: str, replacement: str) -> None:
    d = _decide(tmp_path, "h6_callsite", target, replacement)
    assert d.eligibility is ES.ELIGIBLE, d.reasons
    assert not d.reasons and d.plan is not None and not d.plan.conditions


@pytest.mark.parametrize(
    ("fixture", "target", "replacement", "state", "codes"),
    [
        # call-site resolution
        ("h6_callsite", f"{PKG}.A->run()Ljava/lang/String;@{PKG}.Source->missing()V", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_NOT_FOUND}),
        ("h6_callsite", f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}#3", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_NOT_FOUND}),
        ("h6_callsite", f"{PKG}.A->nope()V@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.TARGET_NOT_FOUND}),
        ("h6_callsite", f"{PKG}.Missing->run()V@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.TARGET_NOT_FOUND}),
        ("h6_callsite", f"{PKG}.A->over@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_AMBIGUOUS}),
        ("h6_callsite", f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT,
         ES.REFUSED, {R.CALL_SITE_MULTIPLE_MATCHES}),
        # replacement compatibility
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueInstance()Ljava/lang/String;",
         ES.REFUSED, {R.REPLACEMENT_SIGNATURE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueArg(I)Ljava/lang/String;",
         ES.REFUSED, {R.REGISTER_TYPE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueInt()I",
         ES.REFUSED, {R.RESULT_TYPE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->hidden()Ljava/lang/String;",
         ES.REFUSED, {R.REPLACEMENT_INACCESSIBLE}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->nothere()Ljava/lang/String;",
         ES.REFUSED, {R.REPLACEMENT_METHOD_NOT_FOUND}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Nowhere->{G}",
         ES.REFUSED, {R.REPLACEMENT_METHOD_NOT_FOUND}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Source->{G}",
         ES.REFUSED, {R.CALL_SITE_ALREADY_REPLACED}),
        ("h6_callsite", INSTANCE_TARGET, f"{PKG}.Replacement->{G}",
         ES.REFUSED, {R.REPLACEMENT_SIGNATURE_MISMATCH}),
        ("h6_callsite", STATIC_TARGET, None, ES.REFUSED, {R.PARAMETER_INVALID}),
        ("h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValue", ES.REFUSED,
         {R.PARAMETER_INVALID}),
        # unsupported invocation shapes
        ("h6_callsite", f"{PKG}.A->make()Ljava/lang/Object;@{PKG}.Source-><init>()V",
         REPLACEMENT, ES.UNSUPPORTED, {R.CONSTRUCTOR_INVOCATION}),
        # a constructor as the replacement is refused in addition (REFUSED dominates)
        ("h6_callsite", f"{PKG}.A->make()Ljava/lang/Object;@{PKG}.Source-><init>()V",
         f"{PKG}.Replacement-><init>()V", ES.REFUSED,
         {R.CONSTRUCTOR_INVOCATION, R.REPLACEMENT_SIGNATURE_MISMATCH}),
        ("h6_callsite", f"{PKG}.A->virt(L{_P}/Source;)Ljava/lang/String;@{PKG}.Source->instanceValue()Ljava/lang/String;",
         f"{PKG}.Replacement->getValueInstance()Ljava/lang/String;", ES.UNSUPPORTED,
         {R.POLYMORPHIC_INVOCATION}),
        ("h6_dynamic", f"{PKG}.A->poly(Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;@java.lang.invoke.MethodHandle->invoke",
         REPLACEMENT, ES.UNSUPPORTED, {R.INVOKE_POLYMORPHIC_UNSUPPORTED}),
        ("h6_dynamic", f"{PKG}.D->custom()Ljava/lang/Runnable;@{PKG}.Source->bsm", REPLACEMENT,
         ES.UNSUPPORTED, {R.INVOKE_CUSTOM_UNSUPPORTED, R.CALLER_ANALYSIS_INCOMPLETE}),
        # incomplete analysis / environment
        ("h6_dynamic", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.DEX_ANALYSIS_INCOMPLETE}),
        ("h6_dynamic", f"{PKG}.D->mixed()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT,
         ES.UNDETERMINED, {R.CALLER_ANALYSIS_INCOMPLETE}),
        ("h6_reflection", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("h6_native", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED, {R.NATIVE_DEPENDENCY_UNKNOWN}),
        ("h6_native", STATIC_TARGET, f"{PKG}.Replacement->nativeValue()Ljava/lang/String;",
         ES.UNSUPPORTED, {R.NATIVE_METHOD}),
    ],
)  # fmt: skip
def test_c_refusals(
    tmp_path: Path,
    fixture: str,
    target: str,
    replacement: str | None,
    state: EligibilityState,
    codes: set[DecisionReason],
) -> None:
    d = _decide(tmp_path, fixture, target, replacement)
    assert d.eligibility is state, d.reasons
    assert codes <= _codes(d), d.reasons
    assert d.plan is None


def test_c_target_method_outside_the_apk_is_refused(tmp_path: Path) -> None:
    """A call to a framework method cannot be resolved (flags / return type unknown)."""
    result = _result(tmp_path, "h6_callsite")
    d = (
        TransformationPlanner(result)
        .plan([_req(f"{PKG}.A-><init>()V@java.lang.Object-><init>()V", f"{PKG}.Replacement->{G}")])
        .decisions[0]
    )
    assert d.eligibility is ES.UNSUPPORTED and R.CONSTRUCTOR_INVOCATION in _codes(d)


def test_c_already_replaced_call_site(tmp_path: Path) -> None:
    """After the transformation the caller invokes the replacement, not the original."""
    project = tmp_path / "projects" / "h6_callsite"
    write_project(ALL["h6_callsite"], project)
    path = project / CALLER_SMALI
    text = path.read_text()
    path.write_text(text.replace(f"L{_P}/Source;->{G}\n    move-result-object v0\n    return-object v0",
                                 f"L{_P}/Replacement;->{G}\n    move-result-object v0\n    return-object v0", 1))  # fmt: skip
    result = ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(sha256="0" * 64)
    )
    d = TransformationPlanner(result).plan([_req(STATIC_TARGET)]).decisions[0]
    assert d.eligibility is ES.REFUSED and _codes(d) == {R.CALL_SITE_ALREADY_REPLACED}


def test_c_every_new_reason_maps_to_a_documented_state() -> None:
    from apkforge.transformation.models import REASON_STATES

    assert REASON_STATES[R.CALL_SITE_NOT_FOUND] is ES.REFUSED
    assert REASON_STATES[R.CALLER_ANALYSIS_INCOMPLETE] is ES.UNDETERMINED
    assert REASON_STATES[R.TARGET_RELATIONSHIP_UNRESOLVED] is ES.UNDETERMINED
    assert REASON_STATES[R.POLYMORPHIC_INVOCATION] is ES.UNSUPPORTED
    assert REASON_STATES[R.INVOKE_CUSTOM_UNSUPPORTED] is ES.UNSUPPORTED
    assert REASON_STATES[R.REGISTER_TYPE_MISMATCH] is ES.REFUSED
    spec = CATALOG[C3]
    assert spec.target_type is TargetKind.CALL_SITE
    assert "no_conflicting_transformation" in spec.preconditions


# ---------------------------------------------------------------------------
# D  register / result safety on tampered evidence
# ---------------------------------------------------------------------------


def _tampered(tmp_path: Path, **fields: Any) -> Any:
    result = _result(tmp_path, "h6_callsite")
    planner = TransformationPlanner(result)  # builds the index over these very records
    (sel,) = result.index().invocations_in(f"{PKG}.A", "calc(IJLjava/lang/String;)I")
    for k, v in fields.items():
        setattr(sel, k, v)
    return planner.plan([_req(ARGS_TARGET, ARGS_REPLACEMENT)]).decisions[0]


@pytest.mark.parametrize(
    ("fields", "state", "code"),
    [
        ({"registers": ("p0", "p1", "p2")}, ES.REFUSED, R.REGISTER_TYPE_MISMATCH),
        ({"registers": ("p0", "p1", "p3", "p2")}, ES.REFUSED, R.REGISTER_TYPE_MISMATCH),
        ({"result_instruction": "move-result-object"}, ES.REFUSED, R.RESULT_TYPE_MISMATCH),
        ({"registers": None}, ES.UNDETERMINED, R.CALLER_ANALYSIS_INCOMPLETE),
        ({"instruction": "invoke-super"}, ES.UNSUPPORTED, R.POLYMORPHIC_INVOCATION),
        ({"instruction": "invoke-interface"}, ES.UNSUPPORTED, R.POLYMORPHIC_INVOCATION),
        # invoke-direct of a static method: the resolution is not established, and a static
        # replacement of another class is no private-instance replacement (REFUSED dominates)
        ({"instruction": "invoke-direct"}, ES.REFUSED, R.TARGET_RELATIONSHIP_UNRESOLVED),
    ],
)
def test_d_register_and_result_safety(
    tmp_path: Path, fields: dict[str, Any], state: EligibilityState, code: DecisionReason
) -> None:
    d = _tampered(tmp_path, **fields)
    assert d.eligibility is state and code in _codes(d), d.reasons
    assert d.plan is None


def test_d_generated_caller_is_unsupported(tmp_path: Path) -> None:
    result = _result(tmp_path, "h6_callsite")
    planner = TransformationPlanner(result)
    caller = next(c for c in result.defined_classes if c.name == f"{PKG}.A")
    run = next(m for m in caller.methods if m.name == "run")
    run.access_flags = (*run.access_flags, "synthetic")
    d = planner.plan([_req(STATIC_TARGET)]).decisions[0]
    assert d.eligibility is ES.UNSUPPORTED and _codes(d) == {R.SYNTHETIC_METHOD}
    assert d.plan is None


def test_d_register_word_helpers() -> None:
    assert register_words("(IJLjava/lang/String;)I", static=True) == 4
    assert register_words("(DJ)V", static=False) == 5
    assert register_words("()V", static=True) == 0
    assert register_words("(Q)V", static=True) is None
    assert expected_result_instruction("()V") is None
    assert expected_result_instruction("()J") == "move-result-wide"
    assert expected_result_instruction("()[I") == "move-result-object"
    assert expected_result_instruction("()Z") == "move-result"


# ---------------------------------------------------------------------------
# E  conflicts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("other", "conflict"),
    [
        (TransformationRequest(transformation_id="H-TRANS-002", target=REPLACEMENT), True),
        (TransformationRequest(transformation_id="H-TRANS-002", target=f"{PKG}.Source->{G}"), True),
        (TransformationRequest(transformation_id="H-TRANS-002",
                               target=f"{PKG}.A->run()Ljava/lang/String;"), True),
        (TransformationRequest(transformation_id="H-TRANS-001", target=f"{PKG}.Replacement"), True),
        (TransformationRequest(transformation_id="H-TRANS-001", target=f"{PKG}.A"), True),
        (_req(f"{PKG}.A->run()Ljava/lang/String;@{PKG}.Source->{G}#1"), True),
        (_req(ARGS_TARGET, ARGS_REPLACEMENT), False),
        (TransformationRequest(transformation_id="H-TRANS-002",
                               target=f"{PKG}.Replacement->getValueInt()I"), False),
    ],
)  # fmt: skip
def test_e_conflicts(tmp_path: Path, other: TransformationRequest, conflict: bool) -> None:
    result = _result(tmp_path, "h6_callsite")
    planning = TransformationPlanner(result).plan([_req(STATIC_TARGET), other])
    first = planning.decisions[0]
    assert (R.CONFLICTING_TRANSFORMATION in _codes(first)) is conflict
    if conflict:
        assert first.eligibility is ES.REFUSED and first.plan is None and planning.conflicts
    else:
        assert first.eligibility is ES.ELIGIBLE and not planning.conflicts


# ---------------------------------------------------------------------------
# F  single-line rewrite / exact mutation
# ---------------------------------------------------------------------------

_ORIG = f"L{_P}/Source;->{G}"
_REPL = f"L{_P}/Replacement;->{G}"
_TEXT = (
    ".class public Lcom/example/h1/T;\n.super Ljava/lang/Object;\n\n"
    ".method public static t()Ljava/lang/String;\n    .registers 2\n"
    f"    invoke-static {{}}, {_ORIG}\n    move-result-object v0\n"
    f"    invoke-static {{}}, {_ORIG}\n    move-result-object v1\n"
    "    return-object v1\n.end method\n"
)


def test_f_replace_invocation_rewrites_one_line_only() -> None:
    out = replace_invocation(_TEXT, 8, _ORIG, _REPL)
    assert out is not None
    a, b = _TEXT.splitlines(), out.splitlines()
    assert [i + 1 for i in range(len(a)) if a[i] != b[i]] == [8]
    assert b[7] == f"    invoke-static {{}}, {_REPL}" and b[5] == a[5]
    # wrong line / not an invocation of it / out of range / with a comment -> refused
    assert replace_invocation(_TEXT, 7, _ORIG, _REPL) is None
    assert replace_invocation(_TEXT, 99, _ORIG, _REPL) is None
    assert (
        replace_invocation(
            _TEXT.replace(
                _ORIG + "\n    move-result-object v1", _ORIG + " # c\n    move-result-object v1"
            ),
            8,
            _ORIG,
            _REPL,
        )
        is None
    )


def test_f_invocation_diff_detects_exactly_one_changed_call() -> None:
    owners = {f"{PKG}.Source", f"{PKG}.Replacement"}
    path, method = "smali/com/example/h1/T.smali", "t()Ljava/lang/String;"
    good = replace_invocation(_TEXT, 8, _ORIG, _REPL)
    assert good is not None
    removed, added, other = invocation_diff(_TEXT, good, path, method, owners)
    assert len(removed) == len(added) == 1 and not other
    assert removed[0].startswith("8: invoke-static {} com.example.h1.Source.getValue")
    assert added[0].startswith("8: invoke-static {} com.example.h1.Replacement.getValue")
    both = _TEXT.replace(_ORIG, _REPL)
    removed, added, _ = invocation_diff(_TEXT, both, path, method, owners)
    assert len(removed) == len(added) == 2
    tampered = good.replace("move-result-object v1", "move-result-object v0")
    removed, added, other = invocation_diff(_TEXT, tampered, path, method, owners)
    assert "v0" in added[0]  # the consumed result register differs
    extra = good.replace("    return-object v1", '    const-string v1, "x"\n    return-object v1')
    assert invocation_diff(_TEXT, extra, path, method, owners)[2]  # other evidence changed


# ---------------------------------------------------------------------------
# G  plan loading / executor integrity / CLI / report
# ---------------------------------------------------------------------------


def _apk(tmp_path: Path, name: str) -> tuple[Path, str]:
    path = tmp_path / f"{name}.apk"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", name)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


class _NoAnalysis:
    def analyze(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("integrity checks must refuse before any H.1 analysis")


def _executor(tmp_path: Path) -> TransformationExecutor:
    svc = SimpleNamespace(work_dir=tmp_path / "ws")
    return TransformationExecutor(svc, reference_service=_NoAnalysis())  # type: ignore[arg-type]


@pytest.fixture
def plan_env(tmp_path: Path) -> tuple[Path, TransformationPlan]:
    apk, sha = _apk(tmp_path, "h6_callsite")
    planning = TransformationPlanningService.plan_from_result(
        _result(tmp_path, "h6_callsite", sha), [_req(STATIC_TARGET)]
    )
    plan = planning.decisions[0].plan
    assert plan is not None and plan.eligibility is ES.ELIGIBLE
    return apk, plan


def _refused(res: TransformationApplicationResult, code: ApplicationReason) -> None:
    assert res.status is AS.REFUSED, res.failure
    assert res.failure is not None and res.failure.code is code, res.failure
    assert res.mutation is None and res.output_apk is None


def test_g_load_plan_requires_complete_call_site_details(
    plan_env: tuple[Path, TransformationPlan],
) -> None:
    _, plan = plan_env
    assert load_plan(plan) is plan
    for key, value in (
        ("caller_method", ""),
        ("source_line", "x"),
        ("expected_mutation_count", "2"),
    ):
        data = json.loads(plan.model_dump_json())
        data["planned_changes"][0]["details"][key] = value
        with pytest.raises(_Refusal) as exc:
            load_plan(TransformationPlan.model_validate(data))
        assert exc.value.failure.code is AR.PLAN_INVALID
    data = json.loads(plan.model_dump_json())
    del data["planned_changes"][0]["details"]["registers"]
    with pytest.raises(_Refusal):
        load_plan(TransformationPlan.model_validate(data))


def test_g_integrity_refusals(tmp_path: Path, plan_env: tuple[Path, TransformationPlan]) -> None:
    apk, plan = plan_env
    ex = _executor(tmp_path)
    other, _ = _apk(tmp_path, "h6_callsite_alt")
    _refused(ex.run(other, plan, apply=True, output_apk=tmp_path / "o.apk"), AR.SOURCE_SHA_MISMATCH)
    forged = plan.model_copy(update={"plan_id": "plan-00000000000000000000"})
    _refused(ex.run(apk, forged, apply=True, output_apk=tmp_path / "o.apk"), AR.PLAN_ID_MISMATCH)
    # retargeted to another call site without recomputing the id
    t = plan.target.model_copy(update={"occurrence": 2, "raw": plan.target.raw + "#2"})
    retarget = plan.model_copy(update={"target": t})
    _refused(ex.run(apk, retarget, apply=True, output_apk=tmp_path / "o.apk"), AR.PLAN_ID_MISMATCH)
    # relabelled as another transformation: the H-TRANS-002 transformer rejects it
    relabel = plan.model_copy(update={"transformation_id": "H-TRANS-002"})
    _refused(ex.run(apk, relabel, apply=True, output_apk=tmp_path / "o.apk"), AR.PLAN_INVALID)
    cond = plan.model_copy(update={"eligibility": ES.CONDITIONALLY_ELIGIBLE})
    res = ex.run(apk, cond, apply=True, output_apk=tmp_path / "o.apk")
    assert res.status is AS.REFUSED and res.failure is not None
    assert not (tmp_path / "o.apk").exists()


def test_g_modifier_not_in_default_catalog() -> None:
    from apkforge.modification.catalog import default_catalog

    assert H6_MODIFIER_ID not in default_catalog()


def test_g_matrix_rows_for_call_sites() -> None:
    rows = _matrix({}, "H-TRANS-003")
    checks = [r.check for r in rows]
    assert checks[3:7] == [
        "Original invocation before",
        "Original invocation after",
        "Replacement invocation after",
        "Call sites changed",
    ]
    assert len(rows) == 15 and all(r.status.value == "NOT_RUN" for r in rows)


def test_g_reports(tmp_path: Path) -> None:
    planning = TransformationPlanner(_result(tmp_path, "h6_callsite")).plan([_req(STATIC_TARGET)])
    text = format_planning_report(planning, verbose=True)
    assert "replace_call_site" in text and "selected_call_site" in text and "\x1b" not in text
    res = TransformationApplicationResult(
        source_apk="x.apk", source_apk_sha256="0" * 64, status=AS.PLANNED,
        transformation_id=C3, target={"call_site": STATIC_TARGET, "file": CALLER_SMALI},
    )  # fmt: skip
    assert "Phase H.6" in format_application_report(res)
    assert STATIC_TARGET in format_application_report(res)


@pytest.mark.parametrize(
    "args",
    [
        ["-t", "H-TRANS-002", "--target", f"{PKG}.B->foo()V", "--replacement", REPLACEMENT],
        ["-t", C3, "--target", STATIC_TARGET, "--target", ARGS_TARGET,
         "--replacement", REPLACEMENT, "--replacement", ARGS_REPLACEMENT,
         "--replacement", REPLACEMENT],
        ["--plan", "p.json", "--replacement", REPLACEMENT],
        ["--plan", "p.json", "--apply"],  # no --output
    ],
)  # fmt: skip
def test_g_cli_usage_errors(tmp_path: Path, args: list[str]) -> None:
    apk, _ = _apk(tmp_path, "h6_callsite")
    res = CliRunner().invoke(app, ["transform", str(apk), *args])
    assert res.exit_code == 2, res.output


def test_g_planning_result_json_round_trip(tmp_path: Path) -> None:
    planning = TransformationPlanner(_result(tmp_path, "h6_callsite")).plan([_req(REPEATED_TARGET)])
    again = PlanningResult.model_validate_json(planning.to_json())
    assert again == planning
    t = again.decisions[0].target
    assert t is not None and t.occurrence == 2 and t.invoked_name == "getValue"
