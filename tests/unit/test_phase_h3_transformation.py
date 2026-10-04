"""Phase H.3 unit tests: plan loading and integrity, DEX-state helpers, status mapping, CLI.

No toolchain is needed: plans come from H.2 over ``analyze_decoded`` fixture projects
(as in the H.2 unit tests), and every case here is refused before any decode or build.
The real-APK path is covered by tests/integration/test_phase_h3_transformation.py.
"""

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
from apkforge.transformation import (
    APPLICATION_SCHEMA_VERSION,
    SUPPORTED_TRANSFORMATIONS,
    ApplicationFailure,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CheckOutcome,
    EligibilityState,
    PlanningResult,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlan,
    TransformationPlanningService,
    TransformationRequest,
    format_application_report,
    load_plan,
)
from apkforge.transformation.dexstate import pool_tokens, take_census
from apkforge.transformation.executor import _final_status, _matrix, _Refusal, content_sha256
from tests.fixtures.h1_apks import FIXTURES, PKG, write_project
from tests.fixtures.h2_apks import H2_FIXTURES
from tests.fixtures.h3_apks import H3_FIXTURES

AR = ApplicationReason
AS = ApplicationStatus
ALL = {fx.name: fx for fx in (*FIXTURES, *H2_FIXTURES, *H3_FIXTURES)}


def _apk(tmp_path: Path, name: str) -> tuple[Path, str]:
    """A stand-in APK file (never decoded: every case below stops before H.1)."""
    path = tmp_path / f"{name}.apk"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", name)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _planning(tmp_path: Path, fixture: str, sha: str, *reqs: tuple[str, str]) -> PlanningResult:
    project = write_project(ALL[fixture], tmp_path / "projects" / fixture)
    result = ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name=f"{fixture}.apk", sha256=sha)
    )
    requests = [TransformationRequest(transformation_id=t, target=x) for t, x in reqs]
    return TransformationPlanningService.plan_from_result(result, requests)


class _NoAnalysis:
    def analyze(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("integrity checks must refuse before any H.1 analysis")


def _executor(tmp_path: Path) -> TransformationExecutor:
    svc = SimpleNamespace(work_dir=tmp_path / "ws")
    return TransformationExecutor(svc, reference_service=_NoAnalysis())  # type: ignore[arg-type]


@pytest.fixture
def eligible(tmp_path: Path) -> tuple[Path, TransformationPlan]:
    apk, sha = _apk(tmp_path, "h3_isolated")
    planning = _planning(tmp_path, "h3_isolated", sha, ("H-TRANS-001", f"{PKG}.B"))
    plan = planning.decisions[0].plan
    assert plan is not None and plan.eligibility is EligibilityState.ELIGIBLE
    return apk, plan


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


def test_schema_and_scope() -> None:
    assert APPLICATION_SCHEMA_VERSION == 1
    # H.3 applies H-TRANS-001, H.5 adds H-TRANS-002 (both controlled, ELIGIBLE-only)
    assert SUPPORTED_TRANSFORMATIONS == ("H-TRANS-001", "H-TRANS-002")
    assert {s.value for s in AS} >= {
        "PLANNED", "APPLYING", "BUILT", "VERIFIED", "REFUSED", "FAILED", "UNKNOWN"
    }  # fmt: skip
    required = [
        "PLAN_NOT_FOUND",
        "PLAN_INVALID",
        "PLAN_ID_MISMATCH",
        "SOURCE_SHA_MISMATCH",
        "PLAN_NOT_ELIGIBLE",
        "TARGET_NOT_FOUND",
        "TARGET_AMBIGUOUS",
        "TARGET_STATE_MISMATCH",
        "ANALYSIS_INCOMPLETE",
        "TRANSFORMATION_PRECONDITION_FAILED",
        "POST_TRANSFORMATION_VERIFICATION_FAILED",
        "UNEXPECTED_DIFF",
        "BUILD_FAILED",
        "ALIGN_FAILED",
        "SIGN_FAILED",
        "SIGNATURE_VERIFICATION_FAILED",
    ]
    assert set(required) <= {r.value for r in AR}
    assert "TRANSFORMATION_FAILED" not in {r.value for r in AR}


@pytest.mark.parametrize(
    ("current", "code", "stage", "expected"),
    [
        (AS.PLANNED, AR.PLAN_NOT_ELIGIBLE, ApplicationStage.ELIGIBILITY, AS.REFUSED),
        (AS.PLANNED, AR.OUTPUT_INVALID, ApplicationStage.PREPARE, AS.REFUSED),
        (AS.APPLYING, AR.TARGET_NOT_FOUND, ApplicationStage.PRE_TRANSFORM, AS.REFUSED),
        (AS.APPLYING, AR.UNEXPECTED_MUTATION, ApplicationStage.MUTATION, AS.FAILED),
        (AS.APPLYING, AR.BUILD_FAILED, ApplicationStage.BUILD, AS.FAILED),
        (AS.BUILT, AR.UNEXPECTED_DIFF, ApplicationStage.DIFF, AS.FAILED),
        (AS.BUILT, AR.ANALYSIS_INCOMPLETE, ApplicationStage.POST_ANALYSIS, AS.UNKNOWN),
        (AS.BUILT, AR.POST_TRANSFORMATION_VERIFICATION_FAILED, ApplicationStage.POST_ANALYSIS,
         AS.FAILED),
    ],
)  # fmt: skip
def test_final_status(current, code, stage, expected) -> None:
    failure = ApplicationFailure(code=code, stage=stage, message="x")
    assert _final_status(current, failure) is expected


def test_matrix_marks_unreached_checks() -> None:
    rows = _matrix({"source": ("abc", True), "build": ("FAIL", False)})
    assert len(rows) == 14
    by = {r.check: r.status for r in rows}
    assert by["Source SHA"] is CheckOutcome.PASS
    assert by["Build"] is CheckOutcome.FAIL
    assert by["Sign"] is CheckOutcome.NOT_RUN
    assert all(r.mandatory for r in rows)


# ---------------------------------------------------------------------------
# plan loading
# ---------------------------------------------------------------------------


def _code(exc: pytest.ExceptionInfo[_Refusal]) -> ApplicationReason:
    return exc.value.failure.code


def test_load_plan_forms(tmp_path: Path, eligible: tuple[Path, TransformationPlan]) -> None:
    _, plan = eligible
    single = tmp_path / "plan.json"
    single.write_text(plan.model_dump_json())
    assert load_plan(single) == plan
    assert load_plan(plan) is plan


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (None, AR.PLAN_NOT_FOUND),
        ("{nope", AR.PLAN_INVALID),
        ('{"plan_id": "plan-x"}', AR.PLAN_INVALID),
        ("[1, 2]", AR.PLAN_INVALID),
    ],
)
def test_load_plan_errors(tmp_path: Path, content: str | None, code: ApplicationReason) -> None:
    path = tmp_path / "plan.json"
    if content is not None:
        path.write_text(content)
    with pytest.raises(_Refusal) as exc:
        load_plan(path)
    assert _code(exc) is code


def test_load_plan_requires_one_decision(tmp_path: Path) -> None:
    _, sha = _apk(tmp_path, "h3_isolated")
    two = _planning(
        tmp_path, "h3_isolated", sha, ("H-TRANS-001", f"{PKG}.B"), ("H-TRANS-001", f"{PKG}.C")
    )
    with pytest.raises(_Refusal) as exc:
        load_plan(two)
    assert _code(exc) is AR.PLAN_INVALID


def test_load_plan_refused_decision(tmp_path: Path) -> None:
    _, sha = _apk(tmp_path, "h3_caller")
    refused = _planning(tmp_path, "h3_caller", sha, ("H-TRANS-001", f"{PKG}.B"))
    with pytest.raises(_Refusal) as exc:
        load_plan(refused)
    assert _code(exc) is AR.PLAN_NOT_ELIGIBLE
    assert exc.value.failure.details["eligibility"] == "REFUSED"


def test_load_plan_schema_mismatch(eligible: tuple[Path, TransformationPlan]) -> None:
    _, plan = eligible
    for change in ({"planning_schema": 99}, {"analysis_schema": 1}):
        with pytest.raises(_Refusal) as exc:
            load_plan(plan.model_copy(update=change))
        assert _code(exc) is AR.PLAN_INVALID


# ---------------------------------------------------------------------------
# integrity order (refused before any analysis, decode or build)
# ---------------------------------------------------------------------------


def _refused(res: TransformationApplicationResult, code: ApplicationReason) -> None:
    assert res.status is AS.REFUSED and res.failure is not None, res
    assert res.failure.code is code, res.failure
    assert res.original_unchanged is True and res.output_apk is None
    assert AS.APPLYING not in res.status_history and res.mutation is None


def test_integrity_source_sha(tmp_path: Path, eligible: tuple[Path, TransformationPlan]) -> None:
    _, plan = eligible
    other, _ = _apk(tmp_path, "other")
    res = _executor(tmp_path).run(other, plan, apply=True, output_apk=tmp_path / "o.apk")
    _refused(res, AR.SOURCE_SHA_MISMATCH)
    assert {r.check: r.status for r in res.verification}["Source SHA"] is CheckOutcome.FAIL


def test_integrity_plan_id(tmp_path: Path, eligible: tuple[Path, TransformationPlan]) -> None:
    apk, plan = eligible
    target = plan.target.model_copy(update={"class_name": f"{PKG}.C", "raw": f"{PKG}.C"})
    for tampered in (
        plan.model_copy(update={"plan_id": "plan-0123456789abcdef0123"}),
        plan.model_copy(update={"target": target}),
        plan.model_copy(update={"parameters": {"x": "1"}}),
    ):
        res = _executor(tmp_path).run(apk, tampered, apply=True, output_apk=tmp_path / "o.apk")
        _refused(res, AR.PLAN_ID_MISMATCH)


def test_integrity_eligibility(tmp_path: Path, eligible: tuple[Path, TransformationPlan]) -> None:
    apk, plan = eligible
    for state in ("CONDITIONALLY_ELIGIBLE", "REFUSED", "UNDETERMINED", "UNSUPPORTED"):
        forged = plan.model_copy(update={"eligibility": EligibilityState(state)})
        res = _executor(tmp_path).run(apk, forged, apply=False)
        _refused(res, AR.PLAN_NOT_ELIGIBLE)


def test_integrity_h_trans_002_is_now_supported(tmp_path: Path) -> None:
    # H.5 added H-TRANS-002 (method removal); the planner produces an ELIGIBLE method plan.
    _, sha = _apk(tmp_path, "g01_methods")
    planning = _planning(tmp_path, "g01_methods", sha, ("H-TRANS-002", f"{PKG}.D->helper()V"))
    plan = planning.decisions[0].plan
    assert plan is not None and plan.eligibility is EligibilityState.ELIGIBLE
    assert plan.transformation_id == "H-TRANS-002"
    assert plan.planned_changes[0].type == "remove_method"
    assert plan.transformation_id in SUPPORTED_TRANSFORMATIONS


def test_integrity_cross_transformation_id_is_refused(tmp_path: Path) -> None:
    """A method (H-TRANS-002) plan relabelled as H-TRANS-001 (class removal) is refused by
    plan-id integrity before any analysis, decode or build: neither transformer accepts the
    other's plan."""
    apk, sha = _apk(tmp_path, "g01_methods")
    planning = _planning(tmp_path, "g01_methods", sha, ("H-TRANS-002", f"{PKG}.D->helper()V"))
    plan = planning.decisions[0].plan
    assert plan is not None
    forged = plan.model_copy(update={"transformation_id": "H-TRANS-001"})
    res = _executor(tmp_path).run(apk, forged, apply=True, output_apk=tmp_path / "o.apk")
    # the H-TRANS-001 transformer rejects a plan carrying a remove_method change
    _refused(res, AR.PLAN_INVALID)


# ---------------------------------------------------------------------------
# DEX-state helpers
# ---------------------------------------------------------------------------

_SMALI = r"""
.class public Lcom/example/h1/T;
.super Ljava/lang/Object;
.source "T.java"
# a comment naming Lcom/example/Ignored;

.field private static final NAME:Ljava/lang/String; = "café \"q\""

.method public static work([Ljava/lang/String;IJ)Ljava/util/List;
    .registers 4
    .param p0, "argv"
    .annotation runtime Lcom/example/Ann;
        value = "v"
    .end annotation
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;
    sget-object v0, Lcom/example/h1/T;->NAME:Ljava/lang/String;
    const/4 v0, 0x0
    return-object v0
.end method
"""


def test_pool_tokens() -> None:
    tokens = pool_tokens(_SMALI)
    for expected in (
        "Lcom/example/h1/T;", "Ljava/lang/Object;", "T.java", "NAME", 'café "q"',
        "work", "[Ljava/lang/String;", "Ljava/util/List;", "LLIJ", "argv",
        "Lcom/example/Ann;", "value", "v", "Landroid/os/Looper;", "getMainLooper",
    ):  # fmt: skip
        assert expected in tokens, expected
    assert "Lcom/example/Ignored;" not in tokens  # comments contribute nothing
    assert "invoke-static" not in tokens and "Lcom/example/h1/T" not in tokens
    generous = pool_tokens(_SMALI, generous=True)
    # generous (classes that stay): bare tokens too, so nothing they use is predicted gone
    assert tokens <= generous and "invoke-static" in generous


def test_census(tmp_path: Path) -> None:
    project = write_project(ALL["f14_incomplete"], tmp_path / "p")
    (project / "smali" / "junk.smali").write_text("not smali\n")
    census = take_census(project)
    assert sorted(census.classes) == [f"{PKG}.A", f"{PKG}.B", f"{PKG}.C"]
    assert census.dex_of["smali_classes2/com/example/h1/C.smali"] == "classes2.dex"
    assert census.unparsed == ["smali/junk.smali"] and census.count == 3
    assert census.classes_in("classes2.dex") == 1
    assert census.digest() == take_census(project).digest()


def test_content_sha256_ignores_zip_metadata(tmp_path: Path) -> None:
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    with zipfile.ZipFile(a, "w") as z:
        z.writestr(zipfile.ZipInfo("x", (2020, 1, 1, 0, 0, 0)), "1")
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(zipfile.ZipInfo("x", (2024, 1, 1, 0, 0, 0)), "1")
    assert a.read_bytes() != b.read_bytes()
    assert content_sha256(a) == content_sha256(b)


# ---------------------------------------------------------------------------
# report + CLI (usage errors; no APK is analysed)
# ---------------------------------------------------------------------------


def test_report(tmp_path: Path, eligible: tuple[Path, TransformationPlan]) -> None:
    _, plan = eligible
    other, _ = _apk(tmp_path, "other")
    res = _executor(tmp_path).run(other, plan, apply=True, output_apk=tmp_path / "o.apk")
    text = format_application_report(res)
    assert "SOURCE_SHA_MISMATCH" in text and "| Source SHA |" in text
    assert "\x1b" not in text
    assert json.loads(res.to_json())["phase"] == "H.3"


@pytest.mark.parametrize(
    "extra",
    [
        ["--apply"],  # no --plan: never plan-and-mutate in one step
        ["--apply", "-t", "H-TRANS-001", "--target", f"{PKG}.B"],
        ["--plan", "PLAN", "-t", "H-TRANS-001", "--target", f"{PKG}.B"],
        ["--plan", "PLAN", "--apply"],  # no --output
        ["--plan", "PLAN", "--apply", "--dry-run", "-o", "OUT"],
        ["-t", "H-TRANS-001", "--target", f"{PKG}.B", "-o", "OUT"],
    ],
)
def test_cli_usage_errors(tmp_path: Path, extra: list[str]) -> None:
    apk, _ = _apk(tmp_path, "x")
    before = apk.read_bytes()
    args = [a.replace("PLAN", str(tmp_path / "p.json")).replace("OUT", str(tmp_path / "o.apk"))
            for a in extra]  # fmt: skip
    res = CliRunner().invoke(app, ["transform", str(apk), *args])
    assert res.exit_code == 2, res.output
    assert apk.read_bytes() == before and not (tmp_path / "o.apk").exists()
