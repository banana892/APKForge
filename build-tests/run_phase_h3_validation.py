#!/usr/bin/env python3
"""Phase H.3 validation: controlled application of H.2 plans (H-TRANS-001 only).

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Build and publish the H.3 synthetic corpus (tests/fixtures/h3_apks.py:
               real APKs, one BuildService round trip, v2/v3 signature by a separate
               publisher key) and run scenarios A-K through H.1 -> H.2 -> H.3: the
               positive transformation must be VERIFIED; every refusal / failure must
               carry its exact reason code; two runs of the same plan must agree.
    corpus     For the 9 corpus APKs: H.1 analysis, the H.2 class targets of the H.2
               validation (manifest components, tracker-rule matches, 20 sampled
               classes), one H.2 plan JSON per target and an H.3 ``--apply`` attempt for
               each. Eligibility rules are never relaxed; 0 applications is a valid result.
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h3_validation.py all [--write]

Work files go to work/phase-h3/<run-id>/. ``--write`` publishes h3-*.json / .md under
artifacts/phase-h/ (H.1 and H.2 artifacts there are not touched). Corpus APKs are never
modified; every input SHA-256 is compared before and after.
Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import resource
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.h3_apks import (  # noqa: E402
    H3_FIXTURES,
    PKG,
    TARGET,
    publish_fixture,
    publisher_key,
)

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore  # noqa: E402
from apkforge.builders.semantic_baseline import NoopSemanticBaseline  # noqa: E402
from apkforge.modification.pipeline import measure_noise_floor  # noqa: E402
from apkforge.reference import ReferenceAnalysisService  # noqa: E402
from apkforge.transformation import (  # noqa: E402
    ApplicationReason,
    ApplicationStatus,
    EligibilityState,
    RemoveIsolatedClassModifier,
    TransformationApplicationResult,
    TransformationExecutor,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
)
from apkforge.transformation.planner import decision_id_for  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkforge.builders.models import StageResult
    from apkforge.builders.workspace import BuildWorkspace

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
PHASE_E_BASELINE = CORPUS / "results" / "phase-e-noise-baseline.json"
AR = ApplicationReason
AS = ApplicationStatus
C1 = "H-TRANS-001"


def _load_h2_runner() -> Any:  # noqa: ANN401 - module object
    spec = importlib.util.spec_from_file_location(
        "run_phase_h2_validation", PROJECT_ROOT / "build-tests" / "run_phase_h2_validation.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


H2 = _load_h2_runner()


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _service(work: Path) -> BuildService | None:
    tc = ToolchainConfig.discover(framework_dir=work / "framework")
    if tc.keytool is None:
        return None
    svc = BuildService(tc, ensure_dev_keystore(tc.keytool, work / "dev-key"), work_dir=work / "ws")
    return svc if svc.check_toolchain().valid else None


def _row(
    scenario: str,
    description: str,
    res: TransformationApplicationResult,
    expected: tuple[ApplicationStatus, ApplicationReason | None],
    extra_failures: list[str],
    seconds: float,
) -> dict[str, Any]:
    failures = list(extra_failures)
    code = res.failure.code if res.failure else None
    if (res.status, code) != expected:
        failures.append(
            f"got {res.status.value}/{code.value if code else None}, expected "
            f"{expected[0].value}/{expected[1].value if expected[1] else None}"
        )
    if res.original_unchanged is not True or res.source_apk_sha256 != res.source_apk_sha256_after:
        failures.append("source APK changed")
    if res.status is not AS.VERIFIED and res.output_apk is not None:
        failures.append("an output was published without verification")
    return {
        "scenario": scenario,
        "description": description,
        "expected_status": expected[0].value,
        "expected_code": expected[1].value if expected[1] else None,
        "status": res.status.value,
        "code": code.value if code else None,
        "stage": res.failure.stage.value if res.failure else None,
        "message": res.failure.message if res.failure else None,
        "status_history": [s.value for s in res.status_history],
        "mutation_count": res.mutation.count if res.mutation else 0,
        "source_sha256": res.source_apk_sha256,
        "source_unchanged": res.original_unchanged,
        "output_published": res.output_apk is not None,
        "matrix": {r.check: r.status.value for r in res.verification},
        "seconds": round(seconds, 1),
        "result": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


# ---------------------------------------------------------------------------
# synthetic
# ---------------------------------------------------------------------------


class _DropTargetOnDecode(BuildService):
    """Simulated drift: the decoded workspace no longer defines the target."""

    def decode(
        self, input_apk: Path | str, workspace: BuildWorkspace, *, timeout: int | None = None
    ) -> StageResult:
        stage = super().decode(input_apk, workspace, timeout=timeout)
        (workspace.decoded_dir / "smali/com/example/h1/B.smali").unlink(missing_ok=True)
        return stage


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None or svc.toolchain.keytool is None:
        raise SystemExit(2)
    pub = publisher_key(svc.toolchain.keytool, work / "publisher-key")
    t0 = time.monotonic()
    apks = {fx.name: publish_fixture(svc, fx, work / "fixtures", pub) for fx in H3_FIXTURES}
    publish_seconds = round(time.monotonic() - t0, 1)
    shas = {k: _sha(v) for k, v in apks.items()}
    reference = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    planner = TransformationPlanningService(reference)
    executor = TransformationExecutor(svc, reference_service=reference)
    baselines: dict[str, NoopSemanticBaseline] = {}
    noise: dict[str, str] = {}
    for name in ("h3_isolated", "h3_isolated_alt"):
        bl = measure_noise_floor(svc, apks[name], work_dir=work / "noise" / name)
        baselines[name] = bl
        noise[name] = str(bl.entries[0].result)

    plans_dir = work / "plans"
    plans_dir.mkdir()
    eligible_plans: list[str] = []
    planning_rows: list[dict[str, Any]] = []

    def plan(fixture: str, target: str = TARGET) -> Path:
        res = planner.plan(
            apks[fixture], [TransformationRequest(transformation_id=C1, target=target)]
        )
        d = res.decisions[0]
        if d.plan is not None:
            eligible_plans.append(d.plan.plan_id)
        planning_rows.append(
            {
                "fixture": fixture,
                "target": target,
                "eligibility": d.eligibility.value,
                "reasons": sorted({r.code.value for r in d.reasons}),
                "plan_id": d.plan.plan_id if d.plan else None,
            }
        )
        path = plans_dir / f"{fixture}-{target.rsplit('.', 1)[-1]}-{len(planning_rows)}.json"
        path.write_text(res.to_json() + "\n")
        return path

    rows: list[dict[str, Any]] = []
    results: dict[str, TransformationApplicationResult] = {}

    def scenario(
        name: str,
        description: str,
        fixture: str,
        plan_path: Path | dict[str, Any],
        expected: tuple[ApplicationStatus, ApplicationReason | None],
        *,
        apply: bool = True,
        ex: TransformationExecutor | None = None,
        check: Callable[[TransformationApplicationResult], list[str]] | None = None,
    ) -> TransformationApplicationResult:
        if isinstance(plan_path, dict):
            p = plans_dir / f"{name}.json"
            p.write_text(json.dumps(plan_path, indent=2))
            plan_path = p
        out = work / "out" / f"{name}.apk"
        t = time.monotonic()
        res = (ex or executor).run(
            apks[fixture],
            plan_path,
            apply=apply,
            output_apk=out,
            noop_baseline=baselines.get(fixture),
            work_dir=work / "h3" / name,
        )
        extra = check(res) if check else []
        if _sha(apks[fixture]) != shas[fixture]:
            extra.append("fixture SHA-256 changed on disk")
        if res.status is not AS.VERIFIED and out.exists():
            extra.append("output file exists for an unverified run")
        rows.append(_row(name, description, res, expected, extra, time.monotonic() - t))
        results[name] = res
        print(f"[synthetic] {name}: {res.status.value} {rows[-1]['code']} {rows[-1]['result']}")
        return res

    def positive_checks(res: TransformationApplicationResult) -> list[str]:
        f = []
        if any(r.status.value != "PASS" for r in res.verification):
            f.append("matrix row not PASS")
        if res.diff.get("unexpected") or res.diff.get("expected_missing"):
            f.append(f"diff: {res.diff.get('unexpected')} {res.diff.get('expected_missing')}")
        a = res.analysis
        if a is None or not a.sufficient or a.target_defined or a.other_classes_removed:
            f.append("post-analysis does not confirm the removal")
        return f

    good = plan("h3_isolated")
    a = scenario("A_positive", "isolated class B removed", "h3_isolated", good, (AS.VERIFIED, None),
                 check=positive_checks)  # fmt: skip
    scenario("A_dry_run", "--plan without --apply", "h3_isolated", good, (AS.PLANNED, None),
             apply=False)  # fmt: skip
    for name, fixture, target in (
        ("B_caller", "h3_caller", TARGET),
        ("C_reflection", "h3_reflection", TARGET),
        ("D_native_method", "h3_native", TARGET),
        ("D_native_code", "h3_native", f"{PKG}.C"),
        ("E_manifest", "h3_manifest", TARGET),
    ):
        scenario(name, f"{target} in {fixture}", fixture, plan(fixture, target),
                 (AS.REFUSED, AR.PLAN_NOT_ELIGIBLE))  # fmt: skip

    good_plan = json.loads(good.read_text())["decisions"][0]["plan"]
    for fixture in ("h3_caller", "h3_reflection", "h3_manifest"):
        forged = json.loads(json.dumps(good_plan))
        sha = shas[fixture]
        forged["apk"]["sha256"] = sha
        forged["plan_id"] = "plan-" + decision_id_for(
            sha, C1, TARGET, {}, forged["analysis_schema"]
        )
        scenario(f"E_forged_{fixture}", "ELIGIBLE plan rebound to an ineligible APK (valid id)",
                 fixture, forged, (AS.REFUSED, AR.PLAN_NOT_ELIGIBLE))  # fmt: skip

    drifting = _DropTargetOnDecode(svc.toolchain, svc.signing, work_dir=work / "ws-drift")
    scenario("F_target_missing", "decoded workspace lacks B", "h3_isolated", good,
             (AS.REFUSED, AR.TARGET_NOT_FOUND),
             ex=TransformationExecutor(drifting, reference_service=reference))  # fmt: skip
    scenario("G_source_sha", "plan for h3_isolated applied to h3_isolated_alt", "h3_isolated_alt",
             good, (AS.REFUSED, AR.SOURCE_SHA_MISMATCH))  # fmt: skip
    tampered = [
        ("H_target_edited", lambda p: p["target"].update(class_name=f"{PKG}.C", raw=f"{PKG}.C"),
         AR.PLAN_ID_MISMATCH),
        ("H_plan_id_edited", lambda p: p.update(plan_id="plan-00000000000000000000"),
         AR.PLAN_ID_MISMATCH),
        ("H_eligibility_edited", lambda p: p.update(eligibility="CONDITIONALLY_ELIGIBLE"),
         AR.PLAN_NOT_ELIGIBLE),
        ("H_expectation_edited", lambda p: p["expected_changes"].append("nothing else"),
         AR.PLAN_MISMATCH),
        ("H_schema_edited", lambda p: p.update(analysis_schema=1), AR.PLAN_INVALID),
        ("H_trans_002", lambda p: p.update(transformation_id="H-TRANS-002"), AR.PLAN_ID_MISMATCH),
    ]  # fmt: skip
    for name, mutate, code in tampered:
        p = json.loads(json.dumps(good_plan))
        mutate(p)
        scenario(name, "plan edited after creation", "h3_isolated", p, (AS.REFUSED, code))
    (plans_dir / "invalid.json").write_text("{not json")
    scenario("H_invalid_json", "unparseable plan", "h3_isolated", plans_dir / "invalid.json",
             (AS.REFUSED, AR.PLAN_INVALID))  # fmt: skip
    scenario("H_missing_plan", "plan file absent", "h3_isolated", plans_dir / "missing.json",
             (AS.REFUSED, AR.PLAN_NOT_FOUND))  # fmt: skip

    original_remove = RemoveIsolatedClassModifier._remove

    def remove_two(self: RemoveIsolatedClassModifier, path: Path) -> None:
        path.unlink()
        (path.parent / "C.smali").unlink()

    RemoveIsolatedClassModifier._remove = remove_two  # type: ignore[method-assign]
    try:
        scenario("I_unexpected_mutation", "faulty mutation also removes C", "h3_isolated", good,
                 (AS.FAILED, AR.UNEXPECTED_MUTATION))  # fmt: skip
    finally:
        RemoveIsolatedClassModifier._remove = original_remove  # type: ignore[method-assign]

    real_build = svc.build

    def broken(project: Path, out: Path, **kw: Any) -> StageResult:  # noqa: ANN401
        (project / "smali/com/example/h1/C.smali").write_text(".class public Lbroken\n")
        return real_build(project, out, **kw)

    svc.build = broken  # type: ignore[method-assign]
    try:
        scenario("J_build_failure", "corrupted smali at build time", "h3_isolated", good,
                 (AS.FAILED, AR.BUILD_FAILED))  # fmt: skip
    finally:
        svc.build = real_build  # type: ignore[method-assign]

    b = scenario("K_repeat", "second application of the A plan", "h3_isolated", good,
                 (AS.VERIFIED, None), check=positive_checks)  # fmt: skip
    repro = {
        "result_equal": a.comparable() == b.comparable(),
        "output_content_equal": a.output_content_sha256 == b.output_content_sha256,
        "output_bytes_equal": a.output_apk_sha256 == b.output_apk_sha256,
        "output_sha256": [a.output_apk_sha256, b.output_apk_sha256],
        "output_content_sha256": [a.output_content_sha256, b.output_content_sha256],
    }
    repro_ok = repro["result_equal"] and repro["output_content_equal"]
    rows.append(
        {
            "scenario": "K_reproducibility",
            "description": "A vs K_repeat: result, semantic diff, analysis, verification",
            "expected_status": "EQUAL",
            "status": "EQUAL" if repro_ok else "DIFFERENT",
            "result": "PASS" if repro_ok else "FAIL",
            "failures": [] if repro_ok else [json.dumps(repro)],
            **repro,
        }
    )
    unchanged = {k: _sha(v) == shas[k] for k, v in apks.items()}
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    applied = [r for r in rows if r.get("mutation_count")]
    status = (
        "PASS"
        if all(r["result"] == "PASS" for r in rows) and all(unchanged.values()) and not leftovers
        else "FAIL"
    )
    return {
        "fixtures": {fx.name: fx.description for fx in H3_FIXTURES},
        "fixture_sha256": shas,
        "fixtures_unchanged": unchanged,
        "noise_floor": noise,
        "publish_seconds": publish_seconds,
        "planning": planning_rows,
        "eligible_plans": sorted(set(eligible_plans)),
        "positive": {
            "expected_changes": [
                f"{e.category} {e.kind} {e.identifier}" for e in a.expected_changes
            ],
            "mutation": a.mutation.model_dump() if a.mutation else None,
            "analysis": a.analysis.model_dump() if a.analysis else None,
            "diff": a.diff,
            "build": {k: v for k, v in a.build.items() if k != "noise_floor"},
            "verification": [r.model_dump() for r in a.verification],
        },
        "cases": rows,
        "counts": {
            "scenarios": len(rows) - 1,
            "applied": len(applied),
            "verified": sum(1 for r in rows if r.get("status") == "VERIFIED"),
            "refused": sum(1 for r in rows if r.get("status") == "REFUSED"),
            "failed": sum(1 for r in rows if r.get("status") == "FAILED"),
            "planned": sum(1 for r in rows if r.get("status") == "PLANNED"),
        },
        "reproducibility": repro,
        "workspaces_left_behind": leftovers,
        "status": status,
    }


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------


def run_corpus(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    executor = TransformationExecutor(svc, reference_service=analyzer)
    baseline = (
        NoopSemanticBaseline.model_validate_json(PHASE_E_BASELINE.read_text())
        if PHASE_E_BASELINE.is_file()
        else None
    )
    names = sorted(p.name for p in CORPUS.glob("*.apk"))
    rows = []
    for name in names:
        apk = CORPUS / name
        before = _sha(apk)
        failures: list[str] = []
        t0 = time.monotonic()
        result = analyzer.analyze(apk)
        h1_seconds = round(time.monotonic() - t0, 1)
        if result.errors:
            failures.append(f"H.1 errors {result.errors}")
        targets = H2._select_targets(result)["class_targets"]
        planner = TransformationPlanner(result)
        states = {s.value: 0 for s in EligibilityState}
        h3_states: dict[str, int] = {}
        h3_codes: dict[str, int] = {}
        decisions = []
        applied = verified = 0
        t1 = time.monotonic()
        plan_dir = work / "plans" / name
        plan_dir.mkdir(parents=True)
        for i, target in enumerate(targets):
            planning = planner.plan([TransformationRequest(transformation_id=C1, target=target)])
            d = planning.decisions[0]
            states[d.eligibility.value] += 1
            path = plan_dir / f"{i:03d}.json"
            path.write_text(planning.to_json(indent=None) + "\n")
            out = work / "out" / name / f"{i:03d}.apk"
            res = executor.run(apk, path, apply=True, output_apk=out, noop_baseline=baseline,
                               work_dir=work / "h3")  # fmt: skip
            code = res.failure.code.value if res.failure else None
            h3_states[res.status.value] = h3_states.get(res.status.value, 0) + 1
            if code:
                h3_codes[code] = h3_codes.get(code, 0) + 1
            applied += 1 if res.mutation is not None else 0
            verified += 1 if res.status is AS.VERIFIED else 0
            if d.eligibility is not EligibilityState.ELIGIBLE and (
                res.status is not AS.REFUSED or code != AR.PLAN_NOT_ELIGIBLE.value
            ):
                failures.append(f"{target}: {d.eligibility.value} but H.3 {res.status.value}")
            if res.original_unchanged is not True:
                failures.append(f"{target}: source changed")
            if res.status is not AS.VERIFIED and out.exists():
                failures.append(f"{target}: output exists for an unverified run")
            decisions.append(
                {
                    "target": target,
                    "eligibility": d.eligibility.value,
                    "reasons": sorted({r.code.value for r in d.reasons}),
                    "h3_status": res.status.value,
                    "h3_code": code,
                    "h3_stage": res.failure.stage.value if res.failure else None,
                }
            )
        h3_seconds = round(time.monotonic() - t1, 1)
        unchanged = _sha(apk) == before
        if not unchanged:
            failures.append("APK changed")
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "sha256_after": _sha(apk),
                "package": result.apk.package_name,
                "analysis_state": result.analysis_state.value,
                "components": {k: v.value for k, v in result.component_states.items()},
                "defined_classes": len(result.defined_classes),
                "targets_attempted": len(targets),
                "eligibility": states,
                "h3_status": dict(sorted(h3_states.items())),
                "h3_codes": dict(sorted(h3_codes.items())),
                "applied": applied,
                "verified": verified,
                "decisions": decisions,
                "original_unchanged": unchanged,
                "h1_seconds": h1_seconds,
                "h3_seconds": h3_seconds,
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(f"[corpus] {name}: {states} H.3 {h3_states} applied={applied} {rows[-1]['result']}")
        del result, planner
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    outputs = (
        sorted(str(p) for p in (work / "out").rglob("*.apk")) if (work / "out").exists() else []
    )
    return {
        "apks": rows,
        "totals": {
            "targets": sum(r["targets_attempted"] for r in rows),
            "eligible": sum(r["eligibility"]["ELIGIBLE"] for r in rows),
            "applied": sum(r["applied"] for r in rows),
            "verified": sum(r["verified"] for r in rows),
            "refused": sum(r["h3_status"].get("REFUSED", 0) for r in rows),
            "failed": sum(r["h3_status"].get("FAILED", 0) for r in rows),
        },
        "outputs_published": outputs,
        "workspaces_left_behind": leftovers,
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
        "status": "PASS"
        if rows and all(r["result"] == "PASS" for r in rows) and not leftovers
        else "FAIL",
    }


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def _markdown(summary: dict[str, Any]) -> str:
    lines = ["# Phase H.3 validation summary (controlled transformation)", ""]
    lines += [f"- Overall: **{summary['status']}**", f"- Run: `{summary['run_id']}`", ""]
    lines += ["## Toolchain", ""] + [f"- {k}: `{v}`" for k, v in summary["toolchain"].items()]
    syn = summary.get("synthetic")
    if syn:
        c = syn["counts"]
        lines += ["", f"## Synthetic scenarios ({syn['status']})", ""]
        lines += [
            f"- Eligible synthetic plans: {len(syn['eligible_plans'])}; scenarios: "
            f"{c['scenarios']}; applied (mutated): {c['applied']}; verified: {c['verified']}; "
            f"refused: {c['refused']}; failed: {c['failed']}; dry run: {c['planned']}",
            f"- Noise floor of the positive fixtures: {syn['noise_floor']}",
            "",
            "| Scenario | Expected | Got | Stage | Mutated | Source unchanged | Result |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in syn["cases"]:
            if r["scenario"] == "K_reproducibility":
                continue
            exp = r["expected_status"] + (f" / {r['expected_code']}" if r["expected_code"] else "")
            got = r["status"] + (f" / {r['code']}" if r["code"] else "")
            lines.append(
                f"| {r['scenario']} | {exp} | {got} | {r['stage'] or '-'} | "
                f"{r['mutation_count']} | {r['source_unchanged']} | {r['result']} |"
            )
        rp = syn["reproducibility"]
        lines += [
            "",
            f"Reproducibility: result equal {rp['result_equal']}, entry content equal "
            f"{rp['output_content_equal']}, APK bytes equal {rp['output_bytes_equal']}.",
            "",
            "Positive transformation, declared and observed changes:",
            "",
        ]
        lines += [f"- {x}" for x in syn["positive"]["expected_changes"]]
        lines += ["", "| Check | Expected | Actual | Status |", "|---|---|---|---|"]
        for row in syn["positive"]["verification"]:
            lines.append(
                f"| {row['check']} | {row['expected']} | {row['actual']} | {row['status']} |"
            )
    cor = summary.get("corpus")
    if cor:
        t = cor["totals"]
        lines += ["", f"## Corpus ({cor['status']})", ""]
        lines += [
            f"- Targets attempted: {t['targets']}; ELIGIBLE: {t['eligible']}; applied: "
            f"{t['applied']}; verified: {t['verified']}; refused: {t['refused']}; "
            f"failed: {t['failed']}; outputs published: {len(cor['outputs_published'])}",
            "",
            "| APK | SHA-256 (12) | Targets | ELIGIBLE | REFUSED | UNSUPPORTED | UNDETERMINED "
            "| H.3 refused | Applied | Unchanged | Result |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in cor["apks"]:
            s = r["eligibility"]
            lines.append(
                f"| {r['apk']} | `{r['sha256'][:12]}` | {r['targets_attempted']} "
                f"| {s['ELIGIBLE']} | {s['REFUSED']} | {s['UNSUPPORTED']} | {s['UNDETERMINED']} "
                f"| {r['h3_status'].get('REFUSED', 0)} | {r['applied']} "
                f"| {r['original_unchanged']} | {r['result']} |"
            )
        lines += ["", f"Max RSS: {cor['max_rss_mb']} MB", ""]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["synthetic", "corpus", "all"])
    ap.add_argument("--write", action="store_true", help="publish under artifacts/phase-h/")
    args = ap.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = PROJECT_ROOT / "work" / "phase-h3" / run_id
    work.mkdir(parents=True)
    summary: dict[str, Any] = {"run_id": run_id, "toolchain": H2._toolchain()}
    if args.mode in ("synthetic", "all"):
        summary["synthetic"] = run_synthetic(work / "synthetic")
    if args.mode in ("corpus", "all"):
        summary["corpus"] = run_corpus(work / "corpus")
    parts = [summary[k]["status"] for k in ("synthetic", "corpus") if k in summary]
    summary["status"] = "PASS" if all(p == "PASS" for p in parts) else "FAIL"

    (work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (work / "summary.md").write_text(_markdown(summary))
    print(f"[h3] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        if "synthetic" in summary:
            (ARTIFACTS / "h3-synthetic-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "synthetic")}, indent=2) + "\n"
            )
        if "corpus" in summary:
            (ARTIFACTS / "h3-corpus-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "corpus")}, indent=2) + "\n"
            )
        (ARTIFACTS / "h3-validation-summary.md").write_text(_markdown(summary))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
