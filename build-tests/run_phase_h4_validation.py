#!/usr/bin/env python3
"""Phase H.4 validation: transformation verification hardening (H-TRANS-001 only).

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Publish the H.3 synthetic corpus plus an unpublished variant and run the
               H.4 control experiment (A original, B unmodified control rebuild, C H.3
               transformed rebuild) for cases 1-8: clean, repeated, natural build noise,
               unexpected mutation, resource / manifest / native / asset / class
               faults injected into the transformed build only, incomplete analysis,
               re-encoded resource table (VERIFIED_WITH_LIMITATIONS).
    corpus     For the 9 corpus APKs: H.1 analysis, the H.2 class targets of the H.2/H.3
               validation (expected: 0 ELIGIBLE -> 0 transformations; rules never
               relaxed), and the H.4 noise-floor experiment (two unmodified rebuilds,
               the second verified against the first as control).
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h4_validation.py all [--write]

Work files go to work/phase-h4/<run-id>/. ``--write`` publishes h4-*.json / .md under
artifacts/phase-h/ (H.1-H.3 artifacts there are not touched). Corpus APKs are never
modified; every input SHA-256 is compared before and after.
Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import resource
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from tests.fixtures.h4_apks import FAULTS, inject_at_build, unpublished_fixture  # noqa: E402

import apkforge.diff.strings as strings_mod  # noqa: E402
from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore  # noqa: E402
from apkforge.diff.native import NativeDiffer  # noqa: E402
from apkforge.reference import ReferenceAnalysisService  # noqa: E402
from apkforge.transformation import (  # noqa: E402
    ControlExperiment,
    EligibilityState,
    ExperimentResult,
    RemoveIsolatedClassModifier,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationResult,
    TransformationVerifier,
)

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
C1 = "H-TRANS-001"


def _load(name: str) -> Any:  # noqa: ANN401 - module object
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / "build-tests" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


H2 = _load("run_phase_h2_validation")


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


def _vsum(v: TransformationVerificationResult) -> dict[str, Any]:
    """Compact, report-friendly view of one H.4 result."""
    return {
        "status": v.status.value,
        "status_reason": v.status_reason,
        "completeness": v.completeness.value,
        "domains": {k: f"{d.completeness.value}/{d.status}" for k, d in v.domains.items()},
        "counts": {
            "expected": len(v.expected_changes),
            "noise": len(v.noise_changes),
            "unexpected": len(v.unexpected_changes),
            "unknown": len(v.unknown_changes),
        },
        "noise_rules": v.noise_floor.get("accepted_rule_counts", {}),
        "control_noop": v.control_rebuild.noop_result,
        "baseline_status": v.control_rebuild.baseline_status,
        "unexpected": [
            f"[{d.domain}] {d.observation.category} {d.observation.kind} "
            f"{d.observation.identifier} (control: {d.in_control})"
            for d in v.unexpected_changes
        ],
        "unknown": [
            f"[{d.domain}] {d.observation.category} {d.observation.kind} "
            f"{d.observation.identifier}: {d.reason[:120]}"
            for d in v.unknown_changes
        ],
        "invariants_failed": [i.name for i in v.invariants if i.status == "failed"],
        "invariants_open": [i.name for i in v.invariants if i.status == "undetermined"],
        "limitations": [x for x in v.limitations if x.startswith("[")],
        "original_unchanged": v.original_unchanged,
        "timings": v.timings,
    }


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None or svc.toolchain.keytool is None:
        raise SystemExit(2)
    pub = publisher_key(svc.toolchain.keytool, work / "publisher-key")
    fx = {f.name: f for f in H3_FIXTURES}
    t0 = time.monotonic()
    apks = {n: publish_fixture(svc, fx[n], work / "fixtures", pub)
            for n in ("h3_isolated", "h3_native")}  # fmt: skip
    apks["unpublished"] = unpublished_fixture(svc, fx["h3_isolated"], work / "fx-unpub", pub)
    publish_seconds = round(time.monotonic() - t0, 1)
    shas = {k: _sha(v) for k, v in apks.items()}
    reference = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    exp = ControlExperiment(svc, reference_service=reference)
    planner = TransformationPlanningService(reference)

    def plan(apk: Path, name: str) -> tuple[Path, str | None, str]:
        res = planner.plan(apk, [TransformationRequest(transformation_id=C1, target=TARGET)])
        d = res.decisions[0]
        path = work / "plans" / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(res.to_json())
        return path, d.plan.plan_id if d.plan else None, d.eligibility.value

    cases: list[dict[str, Any]] = []

    def record(
        case: str,
        description: str,
        expected: str,
        v: TransformationVerificationResult | None,
        *,
        h2: str | None = None,
        h3: str | None = None,
        extra: dict[str, Any] | None = None,
        failures: list[str] | None = None,
        seconds: float = 0.0,
    ) -> dict[str, Any]:
        fails = list(failures or [])
        got = v.status.value if v else "NOT_RUN"
        if got != expected:
            fails.append(f"H.4 {got}, expected {expected}")
        if v is not None and v.original_unchanged is not True:
            fails.append("original changed")
        for name, sha in shas.items():
            if _sha(apks[name]) != sha:
                fails.append(f"fixture {name} changed")
        row = {
            "case": case,
            "description": description,
            "h2": h2,
            "h3": h3,
            "expected": expected,
            "status": got,
            "verification": _vsum(v) if v else None,
            "seconds": seconds,
            "result": "PASS" if not fails else "FAIL",
            "failures": fails,
            **(extra or {}),
        }
        cases.append(row)
        print(f"[synthetic] {case}: {got} (expected {expected}) {row['result']}")
        return row

    def run(apk: Path, p: Path, name: str, **kw: Any) -> ExperimentResult:  # noqa: ANN401
        t = time.monotonic()
        res = exp.run(apk, p, work / "runs" / name, **kw)
        res.seconds["total"] = round(time.monotonic() - t, 3)
        return res

    apk = apks["h3_isolated"]
    p1, pid1, elig = plan(apk, "isolated")

    # 1 clean
    r1 = run(apk, p1, "1_clean")
    v1 = r1.verification
    f1 = []
    if v1.domains["dex"].facts.get("classes_removed") != [TARGET]:
        f1.append("not exactly the target removed")
    if r1.application is None or v1.declared_changes != r1.application.expected_changes:
        f1.append("declared changes differ from H.3's")
    record("1_clean", "eligible plan applied by H.3, verified by H.4", "VERIFIED", v1,
           h2=elig, h3=r1.application.status.value if r1.application else None,
           failures=f1, seconds=r1.seconds["total"],
           extra={"plan_id": pid1, "experiment_seconds": r1.seconds,
                  "expected_changes": [f"{d.observation.category} {d.observation.kind} "
                                       f"{d.observation.identifier}" for d in v1.expected_changes],
                  "noise_changes": [f"{d.leg}: {d.observation.category} {d.observation.kind} "
                                    f"{d.observation.identifier} [{d.rule}, control "
                                    f"{d.in_control}]" for d in v1.noise_changes],
                  "invariants": [{"name": i.name, "expected": i.expected, "actual": i.actual,
                                  "status": str(i.status)} for i in v1.invariants],
                  "legs": {k: {"observations": s.observations, "phase_e": s.phase_e_counts,
                               "raw": s.raw_counts, "metadata_only": s.metadata_only_changes,
                               "order_changed": s.entry_order_changed}
                           for k, s in v1.legs.items()}})  # fmt: skip

    # 2 repeated
    p2, pid2, _ = plan(apk, "isolated-repeat")
    r2 = run(apk, p2, "2_repeat")
    f2 = []
    if pid1 != pid2:
        f2.append("plan id differs")
    same = v1.comparable() == r2.verification.comparable()
    if not same:
        f2.append("verification results differ")
    content = (
        v1.transformed_rebuild.content_sha256 == r2.verification.transformed_rebuild.content_sha256
    )
    if not content:
        f2.append("transformed entry content differs")
    bytes_equal = v1.transformed_rebuild.sha256 == r2.verification.transformed_rebuild.sha256
    record("2_repeat", "same source and plan again", "VERIFIED", r2.verification,
           h2=elig, h3=r2.application.status.value if r2.application else None, failures=f2,
           seconds=r2.seconds["total"],
           extra={"plan_id_equal": pid1 == pid2, "verification_equal": same,
                  "transformed_content_equal": content,
                  "transformed_bytes_equal": bytes_equal})  # fmt: skip

    # 3 natural build noise
    t = time.monotonic()
    nf = exp.noise_floor(apk, work / "runs" / "3_noise")
    f3 = []
    if nf.entry_content_identical is not True or nf.fingerprints_identical is not True:
        f3.append("two unmodified rebuilds differ in content / accepted noise")
    record("3_noise", "two unmodified rebuilds; B2 verified against A with B1 as control",
           "VERIFIED", nf.verification, failures=f3, seconds=round(time.monotonic() - t, 1),
           extra={"apk_bytes_identical": nf.apk_bytes_identical,
                  "entry_content_identical": nf.entry_content_identical,
                  "fingerprints_identical": nf.fingerprints_identical,
                  "noop_results": nf.noop_results,
                  "rebuild_sha256": [r["sha256"] for r in nf.rebuilds],
                  "rebuild_content_sha256": [r["content_sha256"] for r in nf.rebuilds],
                  "control_to_candidate_observations": nf.verification.legs[
                      "control->transformed"].observations if nf.verification else None,
                  "metadata_only_entries": nf.verification.legs[
                      "control->transformed"].metadata_only_changes if nf.verification
                  else None})  # fmt: skip

    # 4a H.3 faulty mutation: caught before build
    real_remove = RemoveIsolatedClassModifier._remove

    def remove_two(self: Any, path: Path) -> None:  # noqa: ANN401
        path.unlink()
        (path.parent / "C.smali").unlink()

    RemoveIsolatedClassModifier._remove = remove_two  # type: ignore[method-assign]
    try:
        r = run(apk, p1, "4a_h3_faulty_mutation", verify_unpublished=True)
    finally:
        RemoveIsolatedClassModifier._remove = real_remove  # type: ignore[method-assign]
    code = r.application.failure.code.value if r.application and r.application.failure else None
    record("4a_h3_faulty_mutation", "H.3 removes B and C: detected before building; no C "
           "exists for H.4", "UNVERIFIED", r.verification, h3=f"{r.application.status.value}"
           f"/{code}" if r.application else None,
           failures=[] if code == "UNEXPECTED_MUTATION" and r.transformed is None
           else ["H.3 did not stop before building"], seconds=r.seconds["total"])  # fmt: skip

    # 4b-7 faults injected into the transformed build only
    for fault in sorted(FAULTS):
        edit, domain = FAULTS[fault]
        with inject_at_build(svc, edit):
            r = run(apk, p1, f"fault_{fault}", verify_unpublished=True)
        v = r.verification
        doms = {str(d.domain) for d in v.unexpected_changes}
        ff = []
        if doms != {domain}:
            ff.append(f"unexpected changes in {sorted(doms)}, expected only [{domain}]")
        if r.transformed_source != "unpublished":
            ff.append(f"transformed source {r.transformed_source}")
        if any(d.in_control == "same_content" for d in v.unexpected_changes):
            ff.append("an unexpected change was reproduced by the control")
        code = r.application.failure.code.value if r.application and r.application.failure else None
        record(f"fault_{fault}", f"build succeeds, {fault.replace('_', ' ')} in the output",
               "FAILED", v, h3=f"{r.application.status.value}/{code}" if r.application
               else None, failures=ff, seconds=r.seconds["total"],
               extra={"domain": domain})  # fmt: skip

    # 7b native modification without a plan
    nat = apks["h3_native"]
    nat_plan = planner.plan(nat, [TransformationRequest(transformation_id=C1, target=TARGET)])
    nat_elig = nat_plan.decisions[0].eligibility.value
    control, _ = exp.rebuild_control(nat, work / "runs" / "7b_native" / "control")
    real_build = svc.build

    def edit_so(project: Path, out: Path, **kw: Any) -> Any:  # noqa: ANN401
        (project / "lib/arm64-v8a/libh3native.so").write_bytes(
            b"\x7fELF\x02\x01\x01\x00synthetic-modified"
        )
        return real_build(project, out, **kw)

    svc.build = edit_so  # type: ignore[method-assign]
    try:
        changed, _ = exp.rebuild_control(nat, work / "runs" / "7b_native" / "changed")
    finally:
        svc.build = real_build  # type: ignore[method-assign]
    t = time.monotonic()
    v = TransformationVerifier(svc, reference_service=reference).verify_noop(nat, control, changed)
    doms = {str(d.domain) for d in v.unexpected_changes}
    record("7b_native_modified", "existing .so modified (no eligible plan exists for native "
           "APKs: plan-less control experiment)", "FAILED", v, h2=nat_elig,
           failures=[] if doms == {"native"} else [f"unexpected in {sorted(doms)}"],
           seconds=round(time.monotonic() - t, 1))  # fmt: skip

    # 8 incomplete analysis (re-verifying the clean A/B/C)
    def reverify() -> TransformationVerificationResult:
        assert r1.control and r1.transformed
        return TransformationVerifier(svc, reference_service=reference).verify(
            r1.original, r1.control, r1.transformed, p1
        )

    old_limit = strings_mod._SAMPLE_LIMIT
    strings_mod._SAMPLE_LIMIT = 2
    try:
        v = reverify()
    finally:
        strings_mod._SAMPLE_LIMIT = old_limit
    record("8a_strings_truncated", "string enumeration truncated", "UNKNOWN", v)
    real_native = NativeDiffer.diff

    def boom(self: Any, *a: Any, **k: Any) -> Any:  # noqa: ANN401
        raise RuntimeError("simulated native differ failure")

    NativeDiffer.diff = boom  # type: ignore[method-assign]
    try:
        v = reverify()
    finally:
        NativeDiffer.diff = real_native  # type: ignore[method-assign]
    record("8b_native_comparator_failed", "native comparator undetermined", "UNKNOWN", v)
    real_analyze = reference.analyze

    def analyze(a: Path, *args: Any, **kw: Any) -> Any:  # noqa: ANN401
        res = real_analyze(a, *args, **kw)
        if Path(a) == Path(r1.transformed or ""):
            res.errors.append("simulated: DEX analysis aborted")
        return res

    reference.analyze = analyze  # type: ignore[method-assign]
    try:
        v = reverify()
    finally:
        reference.analyze = real_analyze  # type: ignore[method-assign]
    record("8c_h1_insufficient", "H.1 re-analysis of the output incomplete", "UNKNOWN", v)

    # target removal cannot be established: a no-op rebuild presented as transformed
    assert r1.control is not None
    second, _ = exp.rebuild_control(apk, work / "runs" / "not_removed")
    v = TransformationVerifier(svc, reference_service=reference).verify(apk, r1.control, second, p1)
    record("negative_target_not_removed", "build succeeds, nothing removed", "FAILED", v)

    # re-encoded resource table: VERIFIED_WITH_LIMITATIONS
    up = apks["unpublished"]
    pu, _, eligu = plan(up, "unpublished")
    r = run(up, pu, "limitations_unpublished")
    record("limitations_resource_table", "fixture whose rebuild re-encodes resources.arsc",
           "VERIFIED_WITH_LIMITATIONS", r.verification, h2=eligu,
           h3=r.application.status.value if r.application else None,
           seconds=r.seconds["total"])  # fmt: skip

    # H-TRANS-002 stays unapplied / unverifiable
    v = TransformationVerifier(svc).verify(apk, r1.control, r1.transformed, _h2_002_plan(work))
    record("negative_h_trans_002", "an H-TRANS-002 plan is refused by H.4", "UNVERIFIED", v)

    leftovers = sorted(p.name for p in (work / "ws").iterdir()) if (work / "ws").exists() else []
    return {
        "fixtures": {k: {"sha256": v, "unchanged": _sha(apks[k]) == v} for k, v in shas.items()},
        "publish_seconds": publish_seconds,
        "cases": cases,
        "workspaces_left_behind": leftovers,
        "status": "PASS" if all(c["result"] == "PASS" for c in cases) else "FAIL",
    }


def _h2_002_plan(work: Path) -> Path:
    """An ELIGIBLE H-TRANS-002 plan (planning-only) from the H.2 fixture project."""
    from tests.fixtures.h1_apks import FIXTURES, write_project
    from tests.fixtures.h2_apks import H2_FIXTURES

    from apkforge.reference import ApkIdentity

    fx = {f.name: f for f in (*FIXTURES, *H2_FIXTURES)}["g01_methods"]
    project = write_project(fx, work / "projects" / "g01_methods")
    res = ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name="g01.apk", sha256="0" * 64)
    )
    req = TransformationRequest(transformation_id="H-TRANS-002", target=f"{PKG}.D->helper()V")
    planning = TransformationPlanningService.plan_from_result(res, [req])
    path = work / "plans" / "h-trans-002.json"
    path.write_text(planning.to_json())
    return path


def run_corpus(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    exp = ControlExperiment(svc, reference_service=analyzer)
    names = sorted(p.name for p in CORPUS.glob("*.apk"))
    before_all = {n: _sha(CORPUS / n) for n in names}
    rows = []
    for name in names:
        apk = CORPUS / name
        before = before_all[name]
        failures: list[str] = []
        t0 = time.monotonic()
        result = analyzer.analyze(apk)
        h1_seconds = round(time.monotonic() - t0, 1)
        targets = H2._select_targets(result)["class_targets"]
        planner = TransformationPlanner(result)
        states = {s.value: 0 for s in EligibilityState}
        for target in targets:
            d = planner.plan([TransformationRequest(transformation_id=C1, target=target)])
            states[d.decisions[0].eligibility.value] += 1
        del result, planner
        t1 = time.monotonic()
        nf = exp.noise_floor(apk, work / "noise" / name)
        nf_seconds = round(time.monotonic() - t1, 1)
        v = nf.verification
        assert v is not None
        for i in (1, 2):
            with contextlib.suppress(OSError):
                for p in (work / "noise" / name / f"control-{i}").glob("*.apk"):
                    p.unlink()  # large; the hashes are recorded
        unchanged = _sha(apk) == before
        if not unchanged:
            failures.append("APK changed")
        if states["ELIGIBLE"]:
            failures.append(f"{states['ELIGIBLE']} ELIGIBLE target(s): unexpected")
        if v.status.value == "VERIFIED" and v.completeness.value != "COMPLETE":
            failures.append("VERIFIED with an incomplete domain")
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "sha256_after": _sha(apk),
                "original_unchanged": unchanged,
                "targets_attempted": len(targets),
                "eligibility": states,
                "transformations": 0,
                "noise_floor": {
                    "noop_results": nf.noop_results,
                    "apk_bytes_identical": nf.apk_bytes_identical,
                    "entry_content_identical": nf.entry_content_identical,
                    "fingerprints_identical": nf.fingerprints_identical,
                    "rebuild_seconds": [nf.seconds.get("rebuild_1"), nf.seconds.get("rebuild_2")],
                },
                "verification": _vsum(v),
                "h1_seconds": h1_seconds,
                "h4_noise_seconds": nf_seconds,
                "h4_verify_seconds": nf.seconds.get("h4"),
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(f"[corpus] {name}: eligible={states['ELIGIBLE']} noise-floor H.4 {v.status.value} "
              f"({v.completeness.value}) {rows[-1]['result']}")  # fmt: skip
    after_all = {n: _sha(CORPUS / n) for n in names}
    return {
        "apks": rows,
        "corpus_sha256_unchanged": before_all == after_all,
        "totals": {
            "targets": sum(r["targets_attempted"] for r in rows),
            "eligible": sum(r["eligibility"]["ELIGIBLE"] for r in rows),
            "transformations": 0,
            "noise_status": {
                s: sum(1 for r in rows if r["verification"]["status"] == s)
                for s in sorted({r["verification"]["status"] for r in rows})
            },
        },
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
        "status": "PASS"
        if rows and before_all == after_all and all(r["result"] == "PASS" for r in rows)
        else "FAIL",
    }


def _markdown(summary: dict[str, Any]) -> str:
    lines = ["# Phase H.4 validation summary (transformation verification hardening)", ""]
    lines += [f"- Overall: **{summary['status']}**", f"- Run: `{summary['run_id']}`", ""]
    lines += ["## Toolchain", ""] + [f"- {k}: `{v}`" for k, v in summary["toolchain"].items()]
    syn = summary.get("synthetic")
    if syn:
        lines += ["", f"## Synthetic cases ({syn['status']})", ""]
        lines += [
            "| Case | H.2 | H.3 | Expected H.4 | H.4 | Completeness | Unexpected | Unknown "
            "| Seconds | Result |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for c in syn["cases"]:
            v = c["verification"] or {}
            n = v.get("counts", {})
            lines.append(
                f"| {c['case']} | {c['h2'] or '-'} | {c['h3'] or '-'} | {c['expected']} | "
                f"{c['status']} | {v.get('completeness', '-')} | {n.get('unexpected', '-')} | "
                f"{n.get('unknown', '-')} | {c['seconds']} | {c['result']} |"
            )
        lines.append("")
        for c in syn["cases"]:
            v = c["verification"] or {}
            for u in v.get("unexpected", [])[:6]:
                lines.append(f"- {c['case']}: UNEXPECTED_CHANGE {u}")
            for u in v.get("unknown", [])[:3]:
                lines.append(f"- {c['case']}: UNKNOWN {u}")
            for x in v.get("limitations", []):
                lines.append(f"- {c['case']}: limitation {x[:200]}")
    cor = summary.get("corpus")
    if cor:
        t = cor["totals"]
        lines += ["", f"## Corpus ({cor['status']})", ""]
        lines += [
            f"- Targets planned: {t['targets']}; ELIGIBLE: {t['eligible']}; transformations: "
            f"{t['transformations']}; noise-floor H.4 results: {t['noise_status']}",
            f"- Corpus SHA-256 unchanged: {cor['corpus_sha256_unchanged']}; max RSS "
            f"{cor['max_rss_mb']} MB",
            "",
            "| APK | SHA-256 (12) | Targets | ELIGIBLE | Control no-op | Bytes equal "
            "| Content equal | H.4 (B2 vs B1) | Completeness | Non-complete domains | H.1 s "
            "| H.4 s | Result |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in cor["apks"]:
            nf, v = r["noise_floor"], r["verification"]
            weak = ", ".join(f"{k} {s}" for k, s in v["domains"].items()
                             if not s.startswith("COMPLETE")) or "-"  # fmt: skip
            lines.append(
                f"| {r['apk']} | `{r['sha256'][:12]}` | {r['targets_attempted']} | "
                f"{r['eligibility']['ELIGIBLE']} | {'/'.join(nf['noop_results'])} | "
                f"{nf['apk_bytes_identical']} | {nf['entry_content_identical']} | "
                f"{v['status']} | {v['completeness']} | {weak} | {r['h1_seconds']} | "
                f"{r['h4_noise_seconds']} | {r['result']} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["synthetic", "corpus", "all"])
    ap.add_argument("--write", action="store_true", help="publish under artifacts/phase-h/")
    args = ap.parse_args()
    with contextlib.suppress(ImportError):
        from loguru import logger

        logger.disable("androguard")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = PROJECT_ROOT / "work" / "phase-h4" / run_id
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
    print(f"[h4] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        for key in ("synthetic", "corpus"):
            if key in summary:
                (ARTIFACTS / f"h4-{key}-summary.json").write_text(
                    json.dumps({k: summary[k] for k in ("run_id", "toolchain", key)}, indent=2)
                    + "\n"
                )
        (ARTIFACTS / "h4-validation-summary.md").write_text(_markdown(summary))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
