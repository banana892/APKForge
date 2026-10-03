"""Phase H.2 unit tests: eligibility, reasons, completeness, conflicts, determinism.

H.1 results come from ``ReferenceAnalysisService.analyze_decoded`` over the hand-written
fixture projects (tests/fixtures/h1_apks.py, h2_apks.py) — no APK is built here; the
real-APK path is covered by tests/integration/test_phase_h2_transformation.py.
"""

from __future__ import annotations

import hashlib
import json
import time
import tracemalloc
from pathlib import Path

import pytest

from apkforge.reference import (
    SCHEMA_VERSION,
    AnalysisState,
    ApkIdentity,
    Component,
    ComponentAnalysis,
    DefinedClass,
    DefinedMethod,
    Evidence,
    ReferenceAnalysisResult,
    ReferenceAnalysisService,
    ReferenceKind,
    parse_smali,
)
from apkforge.transformation import (
    CATALOG,
    REASON_STATES,
    AbsenceStatus,
    DecisionReason,
    EligibilityState,
    PlanningResult,
    RequirementStatus,
    TransformationDecision,
    TransformationPlanningService,
    TransformationRequest,
    format_planning_report,
)
from tests.fixtures.h1_apks import FIXTURES, PKG, Fixture, write_project
from tests.fixtures.h2_apks import H2_FIXTURES

ES = EligibilityState
R = DecisionReason
ALL_FIXTURES = {fx.name: fx for fx in (*FIXTURES, *H2_FIXTURES)}


def _result(
    tmp_path: Path, name: str, apk_entries: list[str] | None = None, **kw: object
) -> ReferenceAnalysisResult:
    fx = ALL_FIXTURES[name]
    project = write_project(fx, tmp_path / name)
    identity = ApkIdentity(
        file_name=f"{name}.apk", sha256=hashlib.sha256(name.encode()).hexdigest()
    )
    return ReferenceAnalysisService.analyze_decoded(
        project, identity=identity, apk_entries=apk_entries, **kw
    )


def _plan(result: ReferenceAnalysisResult, *reqs: tuple[str, str]) -> PlanningResult:
    requests = [TransformationRequest(transformation_id=t, target=x) for t, x in reqs]
    return TransformationPlanningService.plan_from_result(result, requests)


def _one(result: ReferenceAnalysisResult, tid: str, target: str) -> TransformationDecision:
    return _plan(result, (tid, target)).decisions[0]


def _codes(d: TransformationDecision) -> set[DecisionReason]:
    return {r.code for r in d.reasons}


def cls(name: str) -> tuple[str, str]:
    return ("H-TRANS-001", f"{PKG}.{name}")


def meth(spec: str) -> tuple[str, str]:
    return ("H-TRANS-002", f"{PKG}.{spec}")


# ---------------------------------------------------------------------------
# models / catalog
# ---------------------------------------------------------------------------


def test_every_reason_maps_to_a_state() -> None:
    assert set(REASON_STATES) == set(DecisionReason)
    assert REASON_STATES[R.CONFLICTING_TRANSFORMATION] is ES.REFUSED
    assert REASON_STATES[R.REFLECTION_TARGET_UNKNOWN] is ES.UNDETERMINED
    # no reason code maps to ELIGIBLE: eligibility is the absence of reasons
    assert ES.ELIGIBLE not in REASON_STATES.values()


def test_catalog_entries_have_required_fields() -> None:
    assert sorted(CATALOG) == ["H-TRANS-001", "H-TRANS-002"]
    for spec in CATALOG.values():
        for field in (
            "required_evidence",
            "preconditions",
            "eligibility_rules",
            "planned_changes",
            "verification_requirements",
            "compatibility_constraints",
        ):
            assert getattr(spec, field), (spec.id, field)
        assert "no_conflicting_transformation" in spec.preconditions


def test_h1_schema_records_declarations() -> None:
    assert SCHEMA_VERSION == 2
    text = (
        ".class public abstract Lcom/x/A;\n.super Landroid/app/Activity;\n"
        ".implements Ljava/lang/Runnable;\n"
        ".annotation runtime Lkotlin/Metadata;\n.end annotation\n"
        ".field private f:I\n    .annotation runtime Lcom/x/F;\n    .end annotation\n.end field\n"
        ".method public onClick(Landroid/view/View;)V\n    .registers 2\n"
        '    .param p1, "v"\n        .annotation build Lcom/x/P;\n        .end annotation\n'
        "    .end param\n"
        "    .annotation runtime Landroid/webkit/JavascriptInterface;\n    .end annotation\n"
        "    return-void\n.end method\n"
        ".method public static native n()V\n.end method\n"
    )
    r = parse_smali(text, "smali/com/x/A.smali")
    assert not r.issues
    assert r.access_flags == ["public", "abstract"]
    assert r.interfaces == ["java.lang.Runnable"]
    assert r.annotations == ["kotlin.Metadata"]  # field/param annotations excluded
    assert [(m.name, m.descriptor, m.access_flags, m.annotations) for m in r.methods] == [
        (
            "onClick",
            "(Landroid/view/View;)V",
            ("public",),
            ("android.webkit.JavascriptInterface",),
        ),
        ("n", "()V", ("public", "static", "native"), ()),
    ]


def test_compact_h1_json_omits_method_declarations(tmp_path: Path) -> None:
    r = _result(tmp_path, "g01_methods")
    compact = json.loads(r.to_json(include_code_references=False))
    full = json.loads(r.to_json())
    assert all("methods" not in c for c in compact["defined_classes"])
    assert any(c.get("methods") for c in full["defined_classes"])


# ---------------------------------------------------------------------------
# H-TRANS-001
# ---------------------------------------------------------------------------


def test_class_isolated_is_eligible_with_plan(tmp_path: Path) -> None:
    r = _result(tmp_path, "f01_isolated")
    d = _one(r, *cls("B"))
    assert d.eligibility is ES.ELIGIBLE, d.reasons
    assert not d.reasons
    assert all(c.status is RequirementStatus.SATISFIED for c in d.requirements)
    assert d.plan is not None and not d.plan.applied
    assert d.plan.planned_changes[0].type == "remove_class"
    assert d.plan.planned_changes[0].artifact == "smali/com/example/h1/B.smali"
    assert d.plan.preconditions == d.requirements
    assert d.target_evidence_summary is not None
    for cat in d.target_evidence_summary.categories:
        assert cat.absence is AbsenceStatus.ABSENCE_ESTABLISHED, cat


@pytest.mark.parametrize(
    ("fixture", "target", "codes"),
    [
        ("f02_class_ref", "B", {R.CLASS_CALLER_PRESENT, R.TYPE_REFERENCE_PRESENT}),
        ("f03_multiple_callers", "B", {R.CLASS_CALLER_PRESENT, R.TYPE_REFERENCE_PRESENT}),
        ("f04_method_ref", "B", {R.METHOD_CALLER_PRESENT}),
        ("f05_field_ref", "B", {R.FIELD_REFERENCE_PRESENT}),
        ("f06_constructor", "B", {R.CONSTRUCTOR_REFERENCE_PRESENT}),
        ("f07_const_class", "B", {R.CONST_CLASS_REFERENCE_PRESENT}),
        ("f12_manifest", "B", {R.MANIFEST_COMPONENT_REFERENCE}),
        ("f12_manifest", "C", {R.MANIFEST_COMPONENT_REFERENCE}),
        ("f13_resource", "B", {R.RESOURCE_REFERENCE_PRESENT}),
        ("f09_reflection", "B", {R.REFLECTION_TARGET_PRESENT}),
        ("f01_isolated", "Missing", {R.TARGET_NOT_FOUND}),
        ("g03_duplicate_class", "C", {R.TARGET_AMBIGUOUS}),
    ],
)
def test_class_refused(tmp_path: Path, fixture: str, target: str, codes: set[R]) -> None:
    d = _one(_result(tmp_path, fixture), *cls(target))
    assert d.eligibility is ES.REFUSED, d.reasons
    assert codes <= _codes(d), _codes(d)
    assert d.plan is None


def test_class_multiple_callers_lists_each_caller(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f03_multiple_callers"), *cls("B"))
    summary = d.target_evidence_summary
    assert summary is not None
    refs = next(c for c in summary.categories if c.category == "class_references")
    assert refs.absence is AbsenceStatus.REFERENCES_PRESENT
    assert refs.source_classes == [f"{PKG}.A", f"{PKG}.C"]
    caller = next(x for x in d.reasons if x.code is R.CLASS_CALLER_PRESENT)
    assert caller.evidence_count == 2 and len(caller.evidence_ids) == 2


def test_class_reflection_unresolved_is_undetermined(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f09_reflection"), *cls("C"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.REFLECTION_TARGET_UNKNOWN}


def test_class_string_mention_is_indirect_not_reference(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f08_string"), *cls("B"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.STRING_REFERENCE_UNRESOLVED}
    summary = d.target_evidence_summary
    assert summary is not None
    strings = next(c for c in summary.categories if c.category == "string_mentions")
    assert strings.absence is AbsenceStatus.ONLY_INDIRECT_EVIDENCE


def test_class_native_method_is_unsupported(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f10_native_method"), *cls("B"))
    assert d.eligibility is ES.UNSUPPORTED
    assert {R.NATIVE_METHOD_DECLARED, R.NATIVE_DEPENDENCY_UNKNOWN} <= _codes(d)


def test_class_unanalysed_native_code_is_undetermined(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f11_load_library"), *cls("B"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.NATIVE_DEPENDENCY_UNKNOWN}


def test_class_resource_textual_match_is_undetermined(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f13_resource"), *cls("C"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.RESOURCE_TEXTUAL_MATCH}


def test_class_incomplete_resources_is_undetermined(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f14_incomplete"), *cls("B"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.RESOURCE_ANALYSIS_INCOMPLETE}


def test_class_skipped_resources_is_undetermined(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "f01_isolated", include_resources=False), *cls("B"))
    assert d.eligibility is ES.UNDETERMINED
    assert _codes(d) == {R.RESOURCE_ANALYSIS_INCOMPLETE}


def test_class_incomplete_dex_is_undetermined(tmp_path: Path) -> None:
    # the APK lists classes2.dex but no decoded smali_classes2 exists -> dex PARTIAL
    r = _result(tmp_path, "f01_isolated", apk_entries=["classes.dex", "classes2.dex"])
    assert r.component_state(Component.DEX) is AnalysisState.PARTIAL
    d = _one(r, *cls("B"))
    assert d.eligibility is ES.UNDETERMINED
    assert R.DEX_ANALYSIS_INCOMPLETE in _codes(d)
    assert d.plan is None
    # a missing class may be in the undecoded DEX: not REFUSED as not found
    missing = _one(r, *cls("Missing"))
    assert missing.eligibility is ES.UNDETERMINED
    assert _codes(missing) == {R.ANALYSIS_INCOMPLETE}


def test_class_not_fully_qualified_and_ambiguous_simple_name(tmp_path: Path) -> None:
    r = _result(tmp_path, "f03_multiple_callers")
    d = _one(r, "H-TRANS-001", "C")
    assert d.eligibility is ES.REFUSED
    assert _codes(d) == {R.TARGET_NOT_FULLY_QUALIFIED}


def test_target_forms_are_normalised(tmp_path: Path) -> None:
    r = _result(tmp_path, "f01_isolated")
    ids = {
        _one(r, "H-TRANS-001", t).decision_id
        for t in (f"{PKG}.B", "com/example/h1/B", "Lcom/example/h1/B;")
    }
    assert len(ids) == 1


@pytest.mark.parametrize(
    ("tid", "target", "code"),
    [
        ("H-TRANS-001", f"{PKG}.B->bar()V", R.UNSUPPORTED_TARGET_TYPE),
        ("H-TRANS-002", f"{PKG}.B", R.UNSUPPORTED_TARGET_TYPE),
        ("H-TRANS-001", "[Lcom/example/h1/B;", R.UNSUPPORTED_TARGET_TYPE),
        ("H-TRANS-002", f"{PKG}.B->bar(Q)V", R.UNSUPPORTED_TARGET_TYPE),
        ("H-TRANS-999", f"{PKG}.B", R.UNKNOWN_TRANSFORMATION),
    ],
)
def test_unsupported_requests(tmp_path: Path, tid: str, target: str, code: R) -> None:
    d = _one(_result(tmp_path, "f01_isolated"), tid, target)
    assert d.eligibility is ES.UNSUPPORTED
    assert _codes(d) == {code}
    assert d.plan is None


# ---------------------------------------------------------------------------
# H-TRANS-002
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["D->helper()V", "D->recursive()V", "D->priv()V", "E->own()V"])
def test_method_isolated_is_eligible(tmp_path: Path, target: str) -> None:
    d = _one(_result(tmp_path, "g01_methods"), *meth(target))
    assert d.eligibility is ES.ELIGIBLE, d.reasons
    assert d.plan is not None
    change = d.plan.planned_changes[0]
    assert change.type == "remove_method"
    assert change.target == f"{PKG}.{target}"


@pytest.mark.parametrize(
    ("fixture", "target", "state", "codes"),
    [
        ("g01_methods", "D->used()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        # invoked through the subclass F (invoke-static F->sutil resolves to D.sutil)
        ("g01_methods", "D->sutil()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        ("f03_multiple_callers", "B-><init>()V", ES.UNSUPPORTED, {R.CONSTRUCTOR_METHOD}),
        ("g02_method_reflection", "D->secret()V", ES.REFUSED, {R.REFLECTION_TARGET_PRESENT}),
        ("f09_reflection", "C->bar()V", ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        ("g01_methods", "I->run()V", ES.UNSUPPORTED, {R.INTERFACE_METHOD, R.ABSTRACT_METHOD}),
        ("g01_methods", "E->run()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("g01_methods", "F->helper2()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("g01_methods", "D->helper2()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDDEN}),
        ("g01_methods", "D->equals(Ljava/lang/Object;)Z", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        ("f10_native_method", "B->nativeCall(I)I", ES.UNSUPPORTED, {R.NATIVE_METHOD}),
        ("g01_methods", "D-><init>()V", ES.REFUSED, {R.CONSTRUCTOR_METHOD}),
        ("f11_load_library", "A-><clinit>()V", ES.UNSUPPORTED, {R.CLASS_INITIALIZER}),
        (
            "g01_methods",
            "D->readResolve()Ljava/lang/Object;",
            ES.UNSUPPORTED,
            {R.SERIALIZATION_HOOK_METHOD},
        ),
        (
            "g01_methods",
            "N->values()[Lcom/example/h1/N;",
            ES.UNSUPPORTED,
            {R.ENUM_IMPLICIT_METHOD},
        ),
        ("g01_methods", "H->handle()V", ES.UNDETERMINED, {R.OVERRIDE_RELATIONSHIP_UNRESOLVED}),
        ("g01_methods", "J->js()V", ES.UNDETERMINED, {R.ANNOTATION_DRIVEN_ACCESS_POSSIBLE}),
        (
            "g01_methods",
            "D->onClick(Landroid/view/View;)V",
            ES.UNDETERMINED,
            {R.RESOURCE_METHOD_REFERENCE_NOT_ANALYZED},
        ),
        ("g01_methods", "D->over", ES.REFUSED, {R.TARGET_AMBIGUOUS}),
        ("g01_methods", "D->missing()V", ES.REFUSED, {R.TARGET_NOT_FOUND}),
        ("g01_methods", "Missing->m()V", ES.REFUSED, {R.TARGET_NOT_FOUND}),
    ],
)
def test_method_decisions(
    tmp_path: Path, fixture: str, target: str, state: ES, codes: set[R]
) -> None:
    d = _one(_result(tmp_path, fixture), *meth(target))
    assert d.eligibility is state, d.reasons
    assert codes <= _codes(d), _codes(d)
    assert d.plan is None


def test_method_multiple_callers(tmp_path: Path) -> None:
    # D.shared() is called from A.go() and from F.callShared() (owner D, receiver F)
    d = _one(_result(tmp_path, "g01_methods"), *meth("D->shared()V"))
    assert d.eligibility is ES.REFUSED
    assert _codes(d) == {R.METHOD_CALLER_PRESENT}
    summary = d.target_evidence_summary
    assert summary is not None
    calls = next(c for c in summary.categories if c.category == "call_sites")
    assert calls.count == 2
    assert calls.source_classes == [f"{PKG}.A", f"{PKG}.F"]


def test_refused_outranks_unsupported(tmp_path: Path) -> None:
    # D.<init> is a constructor (UNSUPPORTED) and is invoked by F.<init> (REFUSED)
    d = _one(_result(tmp_path, "g01_methods"), *meth("D-><init>()V"))
    assert {R.CONSTRUCTOR_METHOD, R.METHOD_CALLER_PRESENT} <= _codes(d)
    assert d.eligibility is ES.REFUSED


def test_method_overload_with_signature_is_resolved(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "g01_methods"), *meth("D->over(I)V"))
    assert d.eligibility is ES.ELIGIBLE, d.reasons


def test_method_kotlin_metadata_is_conditional(tmp_path: Path) -> None:
    d = _one(_result(tmp_path, "g01_methods"), *meth("K->k()V"))
    assert d.eligibility is ES.CONDITIONALLY_ELIGIBLE
    assert _codes(d) == {R.KOTLIN_METADATA_UPDATE_REQUIRED}
    assert d.plan is not None
    assert [c.code for c in d.plan.conditions] == [R.KOTLIN_METADATA_UPDATE_REQUIRED]
    assert not any(c.satisfied for c in d.plan.conditions)


def test_method_incomplete_analysis_is_undetermined(tmp_path: Path) -> None:
    r = _result(tmp_path, "g01_methods", apk_entries=["classes.dex", "classes2.dex"])
    d = _one(r, *meth("D->helper()V"))
    assert d.eligibility is ES.UNDETERMINED
    assert R.DEX_ANALYSIS_INCOMPLETE in _codes(d)


def test_method_partial_definition_file_is_undetermined(tmp_path: Path) -> None:
    fx = Fixture(
        "partial", "D has an uninterpreted directive", dict(ALL_FIXTURES["g01_methods"].classes)
    )
    fx.classes["D"] = fx.classes["D"].replace(
        ".method public helper()V\n", ".method public helper()V\n    .weird directive\n", 1
    )
    project = write_project(fx, tmp_path / "partial")
    r = ReferenceAnalysisService.analyze_decoded(project)
    d = _one(r, *meth("D->helper()V"))
    assert d.eligibility is ES.UNDETERMINED
    assert {R.TARGET_DEFINITION_INCOMPLETE, R.DEX_ANALYSIS_INCOMPLETE} <= _codes(d)


# ---------------------------------------------------------------------------
# completeness propagation
# ---------------------------------------------------------------------------


def test_reflection_partial_never_establishes_absence(tmp_path: Path) -> None:
    r = _result(tmp_path, "f09_reflection")
    assert r.component_state(Component.REFLECTION) is AnalysisState.PARTIAL
    d = _one(r, *cls("C"))
    summary = d.target_evidence_summary
    assert summary is not None
    for cat in summary.categories:
        if cat.category.startswith("reflection"):
            assert cat.absence is not AbsenceStatus.ABSENCE_ESTABLISHED
    check = next(c for c in d.requirements if c.id == "no_reflection_target")
    assert check.status is RequirementStatus.NOT_ESTABLISHED


def test_decode_failure_is_undetermined_not_eligible() -> None:
    failed = ReferenceAnalysisService._failed(ApkIdentity(sha256="0" * 64), "decode failed: x")
    pr = _plan(failed, cls("B"), meth("C->bar()V"))
    assert [d.eligibility for d in pr.decisions] == [ES.UNDETERMINED, ES.UNDETERMINED]
    assert all(_codes(d) == {R.ANALYSIS_INCOMPLETE} for d in pr.decisions)
    assert pr.errors == ["decode failed: x"]


# ---------------------------------------------------------------------------
# conflicts
# ---------------------------------------------------------------------------


def test_conflict_class_and_method_in_same_class(tmp_path: Path) -> None:
    r = _result(tmp_path, "g01_methods")
    pr = _plan(r, cls("B"), meth("B->bar()V"), meth("D->helper()V"))
    b_cls, b_meth, d_helper = pr.decisions
    for d in (b_cls, b_meth):
        assert d.eligibility is ES.REFUSED
        assert R.CONFLICTING_TRANSFORMATION in _codes(d)
        assert d.plan is None
    assert d_helper.eligibility is ES.ELIGIBLE
    assert [c.kind for c in pr.conflicts] == ["class_method_overlap"]


@pytest.mark.parametrize(
    ("reqs", "kind"),
    [
        ([cls("B"), cls("B")], "duplicate_class_target"),
        ([cls("B"), ("H-TRANS-001", "Lcom/example/h1/B;")], "duplicate_class_target"),
        ([meth("D->helper()V"), meth("D->helper()V")], "duplicate_method_target"),
        ([meth("D->over"), meth("D->over(I)V")], "duplicate_method_target"),
    ],
)
def test_conflicts_detected(tmp_path: Path, reqs: list[tuple[str, str]], kind: str) -> None:
    pr = _plan(_result(tmp_path, "g01_methods"), *reqs)
    assert all(d.eligibility is ES.REFUSED for d in pr.decisions)
    assert all(R.CONFLICTING_TRANSFORMATION in _codes(d) for d in pr.decisions)
    assert {c.kind for c in pr.conflicts} == {kind}
    assert not pr.plans


def test_different_overloads_do_not_conflict(tmp_path: Path) -> None:
    pr = _plan(_result(tmp_path, "g01_methods"), meth("D->over()V"), meth("D->over(I)V"))
    assert not pr.conflicts
    assert [d.eligibility for d in pr.decisions] == [ES.ELIGIBLE, ES.ELIGIBLE]


# ---------------------------------------------------------------------------
# determinism / serialization / size / no mutation
# ---------------------------------------------------------------------------


def test_plan_ids_and_json_are_deterministic(tmp_path: Path) -> None:
    reqs = [cls("B"), meth("D->helper()V"), meth("K->k()V"), cls("E")]
    a = _plan(_result(tmp_path / "a", "g01_methods"), *reqs)
    b = _plan(_result(tmp_path / "b", "g01_methods"), *reqs)
    assert a.to_json() == b.to_json()
    ids = [p.plan_id for p in a.plans]
    assert len(ids) == 4 and len(set(ids)) == 4
    # order of requests does not change a plan's id or content
    c = _plan(_result(tmp_path / "c", "g01_methods"), *reversed(reqs))
    assert {p.plan_id: p.model_dump_json() for p in c.plans} == {
        p.plan_id: p.model_dump_json() for p in a.plans
    }


def test_plan_id_depends_on_apk_identity(tmp_path: Path) -> None:
    r1 = _result(tmp_path / "a", "f01_isolated")
    r2 = _result(tmp_path / "b", "f01_isolated")
    r2.apk = r2.apk.model_copy(update={"sha256": "f" * 64})
    p1 = _one(r1, *cls("B")).plan
    p2 = _one(r2, *cls("B")).plan
    assert p1 is not None and p2 is not None and p1.plan_id != p2.plan_id


def test_json_has_no_paths_or_timestamps(tmp_path: Path) -> None:
    pr = _plan(_result(tmp_path, "g01_methods"), cls("B"), meth("K->k()V"))
    text = pr.to_json()
    assert str(tmp_path) not in text
    assert "\x1b" not in text
    data = json.loads(text)
    assert data["applied"] is False
    assert all(
        not p["applied"] for p in (d.get("plan") or {"applied": False} for d in data["decisions"])
    )
    for key in ("timestamp", "created_at", "generated_at", "uuid"):
        assert key not in text


def test_report_markdown(tmp_path: Path) -> None:
    pr = _plan(_result(tmp_path, "g01_methods"), cls("B"), meth("D->used()V"))
    md = format_planning_report(pr, verbose=True)
    assert "planning only" in md
    assert "`METHOD_CALLER_PRESENT`" in md
    assert "remove_class" in md
    assert format_planning_report(pr, verbose=True) == md


def test_planning_does_not_touch_the_project(tmp_path: Path) -> None:
    r = _result(tmp_path, "g01_methods")
    root = tmp_path / "g01_methods"

    def snapshot() -> dict[str, str]:
        return {
            p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*"))
            if p.is_file()
        }

    before = snapshot()
    _plan(r, cls("B"), meth("D->helper()V"), meth("D->used()V"))
    assert snapshot() == before


# ---------------------------------------------------------------------------
# performance: H.2 must not multiply H.1's cost
# ---------------------------------------------------------------------------

_N_CLASSES = 20_000
_N_REFS = 400_000


def _large_result() -> ReferenceAnalysisResult:
    """20k classes, 400k code references (deterministic), one hub class referenced by
    100k records, plus 20k string constants."""
    classes = [
        DefinedClass(
            name=f"com.big.C{i}",
            source_file=f"smali/com/big/C{i}.smali",
            source_dex="classes.dex",
            superclass="java.lang.Object",
            access_flags=["public"],
            methods=[
                DefinedMethod(name=f"m{j}", descriptor="()V", access_flags=("public",))
                for j in range(5)
            ],
        )
        for i in range(_N_CLASSES)
    ]
    refs: list[Evidence] = []
    for i in range(_N_REFS):
        src = f"com.big.C{(i * 7919) % _N_CLASSES}"
        # every 4th reference targets the hub C0; the rest spread over C1..C9999
        tgt = "com.big.C0" if i % 4 == 0 else f"com.big.C{1 + (i * 104729) % 9999}"
        kind = ReferenceKind.METHOD_REFERENCE if i % 2 else ReferenceKind.CLASS_REFERENCE
        refs.append(
            Evidence(
                kind=kind,
                source_file=f"smali/{src}.smali",
                target=tgt,
                evidence_id=f"ev-{i:016x}",
                source_class=src,
                source_method="x()V",
                target_class=tgt,
                member_name="m1" if kind is ReferenceKind.METHOD_REFERENCE else None,
                descriptor="()V" if kind is ReferenceKind.METHOD_REFERENCE else None,
            )
        )
    for i in range(_N_CLASSES):
        refs.append(
            Evidence(
                kind=ReferenceKind.STRING_REFERENCE,
                source_file="smali/s.smali",
                target=f"text {i}",
                evidence_id=f"ev-s{i:015x}",
                source_class="com.big.C1",
                string_value=f"text {i}",
            )
        )
    comps = [ComponentAnalysis(component=c.value, state=AnalysisState.COMPLETE) for c in Component]
    return ReferenceAnalysisResult.model_construct(
        apk=ApkIdentity(file_name="big.apk", sha256="b" * 64),
        analysis_state=AnalysisState.COMPLETE,
        components=comps,
        defined_classes=classes,
        references=refs,
        reflection=[],
        native=[],
        bundled_native_libraries=[],
        manifest=[],
        resources=[],
        limitations=[],
        errors=[],
    )


@pytest.mark.slow
def test_planning_is_index_based_and_compact(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _large_result()
    result.index()  # H.1's one-time cost, outside the measurement

    def forbidden(self: ReferenceAnalysisResult) -> list[Evidence]:
        raise AssertionError("H.2 must not traverse the full evidence list per target")

    monkeypatch.setattr(ReferenceAnalysisResult, "all_evidence", forbidden)
    requests = [
        TransformationRequest(transformation_id="H-TRANS-001", target=f"com.big.C{i}")
        for i in range(0, _N_CLASSES, 100)
    ] + [
        TransformationRequest(transformation_id="H-TRANS-002", target=f"com.big.C{i + 50}->m4()V")
        for i in range(0, _N_CLASSES, 100)
    ]
    tracemalloc.start()
    t0 = time.perf_counter()
    pr = TransformationPlanningService.plan_from_result(result, requests)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(pr.decisions) == 400
    hub = pr.decisions[0]
    assert hub.eligibility is ES.REFUSED
    assert next(r for r in hub.reasons if r.code is R.CLASS_CALLER_PRESENT).evidence_count > 90_000
    # isolated classes (>= C10000 are never referenced) are eligible with plans
    isolated = [d for d in pr.decisions[:200] if int(d.target.class_name[9:]) >= 10_000]  # type: ignore[union-attr]
    assert isolated and all(d.eligibility is ES.ELIGIBLE for d in isolated)
    # compact: the hub decision's JSON stays small although 100k records reference it
    assert len(hub.model_dump_json()) < 20_000
    assert max(len(p.model_dump_json()) for p in pr.plans) < 20_000
    # bounded cost (generous limits; the full index holds 420k records)
    assert elapsed < 30, elapsed
    assert peak < 200 * 1024 * 1024, peak
