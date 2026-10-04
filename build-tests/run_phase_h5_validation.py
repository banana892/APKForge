#!/usr/bin/env python3
"""Phase H.5 validation: controlled isolated method transformation (H-TRANS-002).

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Publish the H.5 synthetic corpus and, for the isolated and overloaded
               positive fixtures, run the control experiment (A original, B unmodified
               control rebuild, C H.5 transformed rebuild): expect H.3-style VERIFIED and
               H.4 VERIFIED/COMPLETE. Confirm every negative fixture is refused by H.2 and
               that each fault injected into the transformed build only (other method,
               resource, manifest, native, asset, left reference) is rejected by H.4.
    corpus     For the 9 corpus APKs: H.1 analysis, H-TRANS-002 planning over the sampled
               method targets (expected: 0 ELIGIBLE -> 0 transformations; H.2 rules never
               relaxed), every input SHA-256 recorded and compared before and after.
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h5_validation.py all [--write]

Work files go to work/phase-h5/<run-id>/. ``--write`` publishes h5-*.json / .md under
artifacts/phase-h/ (H.1-H.4 artifacts there are not touched). Corpus APKs are never
modified. Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
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

from tests.fixtures.h5_apks import (  # noqa: E402
    FAULTS,
    OVERLOAD_TARGET,
    PKG,
    TARGET,
    build_corpus,
    inject_at_build,
    publisher_key,
)

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore  # noqa: E402
from apkforge.reference import ReferenceAnalysisService  # noqa: E402
from apkforge.transformation import (  # noqa: E402
    ApplicationStatus,
    ControlExperiment,
    EligibilityState,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationResult,
    TransformationVerificationStatus,
)

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
C2 = "H-TRANS-002"
AS = ApplicationStatus
S = TransformationVerificationStatus
ES = EligibilityState


def _load(name: str) -> Any:  # noqa: ANN401 - module object
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / "build-tests" / f"{name}.py")
    assert spec and spec.loader
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
    return {
        "status": v.status.value,
        "completeness": v.completeness.value,
        "counts": {
            "expected": len(v.expected_changes),
            "noise": len(v.noise_changes),
            "unexpected": len(v.unexpected_changes),
            "unknown": len(v.unknown_changes),
        },
        "unexpected": [
            f"[{d.domain}] {d.observation.category} {d.observation.kind} {d.observation.identifier}"
            for d in v.unexpected_changes
        ],
        "invariants_failed": [i.name for i in v.invariants if i.status.value == "failed"],
        "method_post_analysis": (
            None
            if v.method_post_analysis is None
            else {
                "class_defined": v.method_post_analysis.class_defined,
                "target_method_present": v.method_post_analysis.target_method_present,
                "methods": f"{v.method_post_analysis.methods_before} -> "
                f"{v.method_post_analysis.methods_after}",
                "references": v.method_post_analysis.definitive_references
                + v.method_post_analysis.indirect_references,
            }
        ),
    }


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    assert svc.toolchain.keytool is not None
    pub = publisher_key(svc.toolchain.keytool, work / "publisher-key")
    apks = build_corpus(svc, work / "fixtures", pub)
    before = {n: _sha(p) for n, p in apks.items()}
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    exp = ControlExperiment(svc, reference_service=analyzer)
    failures: list[str] = []
    out: dict[str, Any] = {"positive": {}, "negative": [], "faults": []}

    # positive: isolated + overload (full control experiment)
    for name, target, applied_method in (
        ("h5_isolated", TARGET, "isolatedStamp()java.lang.String"),
        ("h5_overloads", OVERLOAD_TARGET, "foo(int)V"),
    ):
        planning = TransformationPlanningService(analyzer).plan(
            apks[name], [TransformationRequest(transformation_id=C2, target=target)]
        )
        d = planning.decisions[0]
        res = exp.run(apks[name], planning, work / "exp" / name)
        app = res.application
        v = res.verification
        ok = (
            d.eligibility is ES.ELIGIBLE
            and app is not None
            and app.status is AS.VERIFIED
            and v.status is S.VERIFIED
            and v.completeness.value == "COMPLETE"
            and app.mutation is not None
            and app.mutation.method_key == applied_method
        )
        if not ok:
            failures.append(f"{name}: positive not VERIFIED ({v.status.value})")
        out["positive"][name] = {
            "target": target,
            "eligibility": d.eligibility.value,
            "h3_status": app.status.value if app else None,
            "method_key": app.mutation.method_key if app and app.mutation else None,
            "verification": _vsum(v),
        }
        print(f"[synthetic] {name}: H.3 {app.status.value if app else '-'} / "
              f"H.4 {v.status.value} ({v.completeness.value})")  # fmt: skip

    # negatives: H.2 must refuse
    negatives = [
        ("h5_caller", f"{PKG}.B->callee()V", ES.REFUSED),
        ("h5_reflection", TARGET, ES.UNDETERMINED),
        ("h5_native", TARGET, ES.UNDETERMINED),
        ("h5_override", f"{PKG}.B->run()V", ES.UNSUPPORTED),
        ("h5_override", f"{PKG}.A->run()V", ES.UNSUPPORTED),
        ("h5_interface", f"{PKG}.B->handle()V", ES.UNSUPPORTED),
        ("h5_interface", f"{PKG}.Iface->handle()V", ES.UNSUPPORTED),
        ("h5_isolated", f"{PKG}.B-><init>()V", ES.UNSUPPORTED),
        ("h5_isolated", f"{PKG}.B->doesNotExist()V", ES.REFUSED),
        ("h5_overloads", f"{PKG}.B->foo", ES.REFUSED),
    ]
    for name, target, want in negatives:
        planning = TransformationPlanningService(analyzer).plan(
            apks[name], [TransformationRequest(transformation_id=C2, target=target)]
        )
        d = planning.decisions[0]
        ok = d.eligibility is want and d.plan is None
        if not ok:
            failures.append(f"{name} {target}: {d.eligibility.value} != {want.value}")
        out["negative"].append(
            {
                "apk": name,
                "target": target,
                "expected": want.value,
                "eligibility": d.eligibility.value,
                "reasons": sorted({r.code.value for r in d.reasons}),
                "plan": d.plan is not None,
            }
        )
    print(f"[synthetic] negatives: {sum(1 for n in out['negative'] if not n['plan'])}/"
          f"{len(out['negative'])} refused")  # fmt: skip

    # fault injection into the transformed build only
    for fault in sorted(FAULTS):
        edit, domain = FAULTS[fault]
        planning = TransformationPlanningService(analyzer).plan(
            apks["h5_isolated"], [TransformationRequest(transformation_id=C2, target=TARGET)]
        )
        with inject_at_build(svc, edit):
            res = exp.run(apks["h5_isolated"], planning, work / "fault" / fault,
                          verify_unpublished=True)  # fmt: skip
        v = res.verification
        app = res.application
        domains = {d.domain.value for d in v.unexpected_changes}
        ok = (
            app is not None
            and app.status is AS.FAILED
            and v.status is S.FAILED
            and domain in domains
        )
        if not ok:
            failures.append(
                f"fault {fault}: not rejected (H.4 {v.status.value}; domains {domains})"
            )
        out["faults"].append(
            {
                "fault": fault,
                "domain": domain,
                "h3_status": app.status.value if app else None,
                "h4_status": v.status.value,
                "unexpected_domains": sorted(domains),
            }
        )
        print(f"[synthetic] fault {fault}: H.4 {v.status.value} (domain {domain})")

    after = {n: _sha(p) for n, p in apks.items()}
    if before != after:
        failures.append("a synthetic input APK changed")
    out["inputs_unchanged"] = before == after
    out["status"] = "PASS" if not failures else "FAIL"
    out["failures"] = failures
    return out


def run_corpus(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
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
        targets = H2._select_targets(result)["method_targets"]
        planner = TransformationPlanner(result)
        states = {s.value: 0 for s in EligibilityState}
        for target in targets:
            d = planner.plan([TransformationRequest(transformation_id=C2, target=target)])
            states[d.decisions[0].eligibility.value] += 1
        del result, planner
        unchanged = _sha(apk) == before
        if not unchanged:
            failures.append("APK changed")
        if states["ELIGIBLE"]:
            failures.append(f"{states['ELIGIBLE']} ELIGIBLE method target(s): unexpected")
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "sha256_after": _sha(apk),
                "original_unchanged": unchanged,
                "method_targets_attempted": len(targets),
                "eligibility": states,
                "transformations": 0,
                "h1_seconds": h1_seconds,
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(f"[corpus] {name}: method targets={len(targets)} eligible={states['ELIGIBLE']} "
              f"{rows[-1]['result']}")  # fmt: skip
    after_all = {n: _sha(CORPUS / n) for n in names}
    return {
        "apks": rows,
        "corpus_sha256_unchanged": before_all == after_all,
        "totals": {
            "method_targets": sum(r["method_targets_attempted"] for r in rows),
            "eligible": sum(r["eligibility"]["ELIGIBLE"] for r in rows),
            "transformations": 0,
        },
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
        "status": "PASS"
        if all(r["result"] == "PASS" for r in rows) and before_all == after_all
        else "FAIL",
    }


def _markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Phase H.5 validation (H-TRANS-002 remove isolated method)",
        "",
        f"- Run: `{summary['run_id']}`",
        f"- Overall: **{summary['status']}**",
        "",
    ]
    syn = summary.get("synthetic")
    if syn:
        lines += ["## Synthetic", "", f"- Status: **{syn['status']}**",
                  f"- Inputs unchanged: {syn['inputs_unchanged']}", ""]  # fmt: skip
        lines += ["| Fixture | Target | H.3 | H.4 | Completeness |", "|---|---|---|---|---|"]
        for name, p in syn["positive"].items():
            v = p["verification"]
            lines.append(f"| {name} | `{p['target']}` | {p['h3_status']} | {v['status']} "
                         f"| {v['completeness']} |")  # fmt: skip
        lines += ["", "| Negative | Target | Expected | Decision |", "|---|---|---|---|"]
        for n in syn["negative"]:
            lines.append(f"| {n['apk']} | `{n['target']}` | {n['expected']} | {n['eligibility']} |")
        lines += ["", "| Fault | Domain | H.3 | H.4 |", "|---|---|---|---|"]
        for fa in syn["faults"]:
            lines.append(
                f"| {fa['fault']} | {fa['domain']} | {fa['h3_status']} | {fa['h4_status']} |"
            )
        if syn["failures"]:
            lines += ["", "Failures:", *[f"- {x}" for x in syn["failures"]]]
        lines.append("")
    corp = summary.get("corpus")
    if corp:
        t = corp["totals"]
        lines += ["## Corpus (read-only; eligibility never relaxed)", ""]
        lines.append(
            f"- Status: **{corp['status']}**; SHA-256 unchanged: {corp['corpus_sha256_unchanged']}"
        )
        lines.append(
            f"- {t['method_targets']} method targets, {t['eligible']} ELIGIBLE, "
            f"{t['transformations']} applied"
        )
        lines += ["", "| APK | Method targets | ELIGIBLE | Unchanged |", "|---|---|---|---|"]
        for r in corp["apks"]:
            lines.append(
                f"| {r['apk']} | {r['method_targets_attempted']} | "
                f"{r['eligibility']['ELIGIBLE']} | {r['original_unchanged']} |"
            )
        lines.append("")
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
    work = PROJECT_ROOT / "work" / "phase-h5" / run_id
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
    print(f"[h5] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        for key in ("synthetic", "corpus"):
            if key in summary:
                (ARTIFACTS / f"h5-{key}-summary.json").write_text(
                    json.dumps({k: summary[k] for k in ("run_id", "toolchain", key)}, indent=2)
                    + "\n"
                )
        (ARTIFACTS / "h5-validation-summary.md").write_text(_markdown(summary))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
