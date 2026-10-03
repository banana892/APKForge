#!/usr/bin/env python3
"""Phase H.2 validation: transformation eligibility & planning on real APKs (planning only).

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Build the H.1 + H.2 synthetic fixtures into real APKs with BuildService,
               run H.1 -> H.2 on each and check every expected decision, plan
               determinism (two full runs, identical JSON) and that no APK changed.
    corpus     Plan against the 9 corpus APKs (read-only). Targets per APK, chosen
               deterministically: up to 5 manifest component classes, up to 10 classes
               matching a Phase F tracker-rule package signature, 20 evenly spaced
               defined classes (H-TRANS-001) and the first ordinary method of each
               sampled class (H-TRANS-002), plus one deliberate conflicting pair.
               Eligibility rules are never relaxed; UNDETERMINED is a valid outcome.
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h2_validation.py all [--write]

Work files go to work/phase-h2/<run-id>/. ``--write`` publishes h2-*.json / .md under
artifacts/phase-h/ (the H.1 artifacts there are not touched). No APK is modified,
rebuilt from the corpus, signed or installed.
Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
"""

# ruff: noqa: E501 - the expectation table keeps one case per line

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import resource
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.h1_apks import FIXTURES, PKG, build_fixture  # noqa: E402
from tests.fixtures.h2_apks import H2_FIXTURES  # noqa: E402

from apkforge.builders import BuildService, ToolchainConfig  # noqa: E402
from apkforge.privacy.rules import RuleEngine  # noqa: E402
from apkforge.reference import (  # noqa: E402
    AnalysisState,
    Component,
    ReferenceAnalysisResult,
    ReferenceAnalysisService,
)
from apkforge.transformation import (  # noqa: E402
    DecisionReason,
    EligibilityState,
    PlanningResult,
    RequirementStatus,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
)

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
ES = EligibilityState
R = DecisionReason
C1, C2 = "H-TRANS-001", "H-TRANS-002"
#: components that must be COMPLETE for any plan of the transformation to exist
_NEEDED = {
    C1: list(Component),
    C2: [Component.DEX, Component.REFLECTION, Component.NATIVE_INDICATORS, Component.NATIVE_CODE],
}

#: fixture -> [(transformation, target, expected state, required reason codes)]
EXPECTED: dict[str, list[tuple[str, str, ES, set[R]]]] = {
    "f01_isolated": [(C1, "B", ES.ELIGIBLE, set()), (C1, "Missing", ES.REFUSED, {R.TARGET_NOT_FOUND})],
    "f02_class_ref": [(C1, "B", ES.REFUSED, {R.CLASS_CALLER_PRESENT, R.TYPE_REFERENCE_PRESENT})],
    "f03_multiple_callers": [(C1, "B", ES.REFUSED, {R.CLASS_CALLER_PRESENT}), (C1, "C", ES.ELIGIBLE, set())],
    "f04_method_ref": [(C1, "B", ES.REFUSED, {R.METHOD_CALLER_PRESENT})],
    "f05_field_ref": [(C1, "B", ES.REFUSED, {R.FIELD_REFERENCE_PRESENT})],
    "f06_constructor": [(C1, "B", ES.REFUSED, {R.CONSTRUCTOR_REFERENCE_PRESENT})],
    "f07_const_class": [(C1, "B", ES.REFUSED, {R.CONST_CLASS_REFERENCE_PRESENT})],
    "f08_string": [(C1, "B", ES.UNDETERMINED, {R.STRING_REFERENCE_UNRESOLVED})],
    "f09_reflection": [
        (C1, "B", ES.REFUSED, {R.REFLECTION_TARGET_PRESENT}),
        (C1, "C", ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
        (C2, "C->bar()V", ES.UNDETERMINED, {R.REFLECTION_TARGET_UNKNOWN}),
    ],
    "f10_native_method": [
        (C1, "B", ES.UNSUPPORTED, {R.NATIVE_METHOD_DECLARED}),
        (C2, "B->nativeCall(I)I", ES.UNSUPPORTED, {R.NATIVE_METHOD}),
    ],
    "f11_load_library": [(C1, "B", ES.UNDETERMINED, {R.NATIVE_DEPENDENCY_UNKNOWN})],
    "f12_manifest": [
        (C1, "B", ES.REFUSED, {R.MANIFEST_COMPONENT_REFERENCE}),
        (C1, "C", ES.REFUSED, {R.MANIFEST_COMPONENT_REFERENCE}),
    ],
    "f13_resource": [
        (C1, "B", ES.REFUSED, {R.RESOURCE_REFERENCE_PRESENT}),
        (C1, "C", ES.UNDETERMINED, {R.RESOURCE_TEXTUAL_MATCH}),
    ],
    "f14_incomplete": [(C1, "B", ES.UNDETERMINED, {R.RESOURCE_ANALYSIS_INCOMPLETE})],
    "g01_methods": [
        (C2, "D->helper()V", ES.ELIGIBLE, set()),
        (C2, "E->own()V", ES.ELIGIBLE, set()),
        (C2, "D->used()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        (C2, "D->shared()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        (C2, "D->sutil()V", ES.REFUSED, {R.METHOD_CALLER_PRESENT}),
        (C2, "I->run()V", ES.UNSUPPORTED, {R.INTERFACE_METHOD}),
        (C2, "E->run()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDES}),
        (C2, "D->helper2()V", ES.UNSUPPORTED, {R.METHOD_OVERRIDDEN}),
        (C2, "N->values()[Lcom/example/h1/N;", ES.UNSUPPORTED, {R.ENUM_IMPLICIT_METHOD}),
        (C2, "D->readResolve()Ljava/lang/Object;", ES.UNSUPPORTED, {R.SERIALIZATION_HOOK_METHOD}),
        (C2, "H->handle()V", ES.UNDETERMINED, {R.OVERRIDE_RELATIONSHIP_UNRESOLVED}),
        (C2, "J->js()V", ES.UNDETERMINED, {R.ANNOTATION_DRIVEN_ACCESS_POSSIBLE}),
        (C2, "K->k()V", ES.CONDITIONALLY_ELIGIBLE, {R.KOTLIN_METADATA_UPDATE_REQUIRED}),
        (C2, "D->over", ES.REFUSED, {R.TARGET_AMBIGUOUS}),
    ],
    "g02_method_reflection": [(C2, "D->secret()V", ES.REFUSED, {R.REFLECTION_TARGET_PRESENT})],
    "g03_duplicate_class": [(C1, "C", ES.REFUSED, {R.TARGET_AMBIGUOUS})],
}  # fmt: skip


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _service(work: Path) -> BuildService | None:
    svc = BuildService(ToolchainConfig.discover(framework_dir=work / "framework"), work_dir=work)
    return svc if svc.check_toolchain().valid else None


def _requests(items: list[tuple[str, str]]) -> list[TransformationRequest]:
    return [TransformationRequest(transformation_id=t, target=x) for t, x in items]


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    planner = TransformationPlanningService(
        ReferenceAnalysisService(svc, work_dir=work / "analysis")
    )
    rows = []
    fixtures = {fx.name: fx for fx in (*FIXTURES, *H2_FIXTURES)}
    for name, cases in EXPECTED.items():
        apk = build_fixture(svc, fixtures[name], work)
        before = _sha(apk)
        failures: list[str] = []
        for tid, target, state, codes in cases:
            reqs = _requests([(tid, f"{PKG}.{target}")])
            a = planner.plan(apk, reqs)
            b = planner.plan(apk, reqs)
            d = a.decisions[0]
            got = {r.code for r in d.reasons}
            if d.eligibility is not state or not codes <= got:
                failures.append(
                    f"{tid} {target}: {d.eligibility.value} {sorted(got)} "
                    f"(expected {state.value} {sorted(codes)})"
                )
            if (d.plan is not None) != state.plannable:
                failures.append(f"{tid} {target}: plan presence wrong")
            if a.to_json() != b.to_json():
                failures.append(f"{tid} {target}: non-deterministic plan JSON")
            if a.errors or not a.original_unchanged:
                failures.append(f"{tid} {target}: errors {a.errors} / input changed")
            rows.append(
                {
                    "fixture": name,
                    "transformation": tid,
                    "target": target,
                    "expected": state.value,
                    "eligibility": d.eligibility.value,
                    "reasons": sorted(c.value for c in got),
                    "plan_id": d.plan.plan_id if d.plan else None,
                    "apk_sha256": before,
                }
            )
        unchanged = _sha(apk) == before
        if not unchanged:
            failures.append("APK changed")
        for row in rows:
            if row["fixture"] == name:
                row["original_unchanged"] = unchanged
                row["result"] = "PASS" if not failures else "FAIL"
                row["failures"] = failures
        print(f"[synthetic] {name}: {failures or 'PASS'}")
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    return {
        "cases": rows,
        "workspaces_left_behind": leftovers,
        "status": "PASS" if all(r["result"] == "PASS" for r in rows) and not leftovers else "FAIL",
    }


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------


def _tracker_targets(result: ReferenceAnalysisResult, limit: int = 10) -> list[tuple[str, str]]:
    """Defined classes inside a Phase F tracker-rule package (signature match only)."""
    engine = RuleEngine()
    engine.load_builtins()
    names = [c.name for c in result.defined_classes]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for rule in sorted(engine.rules, key=lambda r: r.id):
        for pkg in sorted(rule.packages):
            hits = [n for n in names if n.startswith(pkg + ".")][:2]
            for h in hits:
                if h not in seen:
                    seen.add(h)
                    out.append((rule.id, h))
    return out[:limit]


def _select_targets(result: ReferenceAnalysisResult) -> dict[str, Any]:
    defined = {c.name: c for c in result.defined_classes}
    components = sorted(
        {
            e.target_class
            for e in result.manifest
            if e.target_class in defined
            and e.instruction in ("activity", "service", "receiver", "provider")
        }
    )[:5]
    trackers = _tracker_targets(result)
    classes = result.defined_classes
    step = max(1, len(classes) // 20)
    sample = [c.name for c in classes[::step]][:20]
    methods = []
    for name in sample:
        m = next((m for m in defined[name].methods if m.name not in ("<init>", "<clinit>")), None)
        if m is not None:
            methods.append(f"{name}->{m.signature}")
    class_targets = list(dict.fromkeys([*components, *(t for _, t in trackers), *sample]))
    return {
        "manifest_components": components,
        "tracker_rule_matches": [{"rule": r, "class": c} for r, c in trackers],
        "sampled_classes": sample,
        "class_targets": class_targets,
        "method_targets": methods,
    }


def _hist(results: list[PlanningResult]) -> tuple[dict[str, int], dict[str, int]]:
    states = {s.value: 0 for s in ES}
    reasons: dict[str, int] = {}
    for pr in results:
        for d in pr.decisions:
            states[d.eligibility.value] += 1
            for code in sorted({r.code.value for r in d.reasons}):
                reasons[code] = reasons.get(code, 0) + 1
    return states, dict(sorted(reasons.items()))


def run_corpus(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
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
        targets = _select_targets(result)

        t1 = time.monotonic()
        planner = TransformationPlanner(result)
        selector_seconds = round(time.monotonic() - t1, 2)
        t2 = time.monotonic()
        class_run = planner.plan(_requests([(C1, c) for c in targets["class_targets"]]))
        method_run = planner.plan(_requests([(C2, m) for m in targets["method_targets"]]))
        planning_seconds = round(time.monotonic() - t2, 2)
        conflict_reqs: list[tuple[str, str]] = []
        if targets["method_targets"]:
            m = targets["method_targets"][0]
            conflict_reqs = [(C1, m.split("->", 1)[0]), (C2, m)]
        conflict_run = planner.plan(_requests(conflict_reqs))

        # invariants (rules are never relaxed to produce eligibility): a plan exists only
        # when every requirement is answered from COMPLETE components
        runs = [class_run, method_run]
        for pr in runs:
            for d in pr.decisions:
                if d.eligibility.plannable != (d.plan is not None):
                    failures.append(f"plan presence mismatch: {d.decision_id}")
                if d.eligibility is not ES.ELIGIBLE and not d.reasons:
                    failures.append(f"non-eligible decision without reasons: {d.decision_id}")
                if not d.eligibility.plannable:
                    continue
                needed = _NEEDED[d.transformation_id]
                weak = [
                    c for c in needed if result.component_state(c) is not AnalysisState.COMPLETE
                ]
                open_reqs = [
                    c.id
                    for c in d.requirements
                    if c.status not in (RequirementStatus.SATISFIED, RequirementStatus.CONDITIONAL)
                ]
                if weak or open_reqs:
                    failures.append(f"plan for {d.target} with {weak} / {open_reqs}")
        if conflict_reqs and not all(
            d.eligibility is ES.REFUSED
            and R.CONFLICTING_TRANSFORMATION in {r.code for r in d.reasons}
            for d in conflict_run.decisions
        ):
            failures.append("conflicting pair not refused")
        component = targets["manifest_components"]
        for d in class_run.decisions:
            if d.target and d.target.class_name in component and d.eligibility.plannable:
                failures.append(f"manifest component planned for removal: {d.target}")
        # determinism: same result + same requests -> identical JSON
        again = TransformationPlanner(result).plan(
            _requests([(C1, c) for c in targets["class_targets"]])
        )
        deterministic = again.to_json() == class_run.to_json()
        if not deterministic:
            failures.append("non-deterministic planning JSON")
        deterministic_full = None
        if name.startswith("de.audioattack.openlink"):
            full = TransformationPlanningService(analyzer).plan(
                apk, _requests([(C1, c) for c in targets["class_targets"]])
            )
            deterministic_full = full.to_json() == class_run.to_json()
            if not deterministic_full:
                failures.append("non-deterministic H.1 -> H.2 JSON (OpenLink)")
        unchanged = _sha(apk) == before and result.original_unchanged is True
        if not unchanged:
            failures.append("APK changed")

        states, reasons = _hist(runs)
        sizes = [len(p.model_dump_json()) for pr in runs for p in pr.plans]
        decision_sizes = [len(d.model_dump_json()) for pr in runs for d in pr.decisions]
        examples = [
            {
                "transformation": d.transformation_id,
                "target": d.target.canonical if d.target else None,
                "eligibility": d.eligibility.value,
                "reasons": sorted({r.code.value for r in d.reasons}),
                "plan_id": d.plan.plan_id if d.plan else None,
            }
            for pr in runs
            for d in pr.decisions
        ]
        (work / "decisions").mkdir(parents=True, exist_ok=True)
        (work / "decisions" / f"{name}.json").write_text(
            json.dumps(
                {
                    "class_run": json.loads(class_run.to_json(indent=None)),
                    "method_run": json.loads(method_run.to_json(indent=None)),
                    "conflict_run": json.loads(conflict_run.to_json(indent=None)),
                },
                indent=1,
            )
            + "\n"
        )
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "package": result.apk.package_name,
                "analysis_state": result.analysis_state.value,
                "components": {k: v.value for k, v in result.component_states.items()},
                "defined_classes": len(result.defined_classes),
                "evidence_records": sum(result.summary().values()),
                "targets": targets,
                "targets_considered": len(targets["class_targets"])
                + len(targets["method_targets"]),
                "plans_generated": sum(len(pr.plans) for pr in runs),
                "states": states,
                "reason_counts": reasons,
                "conflict_check": [d.eligibility.value for d in conflict_run.decisions],
                "decisions": examples,
                "max_plan_json_bytes": max(sizes, default=0),
                "max_decision_json_bytes": max(decision_sizes, default=0),
                "deterministic": deterministic,
                "deterministic_full_pipeline": deterministic_full,
                "original_unchanged": unchanged,
                "h1_seconds": h1_seconds,
                "selector_seconds": selector_seconds,
                "planning_seconds": planning_seconds,
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(
            f"[corpus] {name}: {states} plans={rows[-1]['plans_generated']} "
            f"h1={h1_seconds}s plan={planning_seconds}s {rows[-1]['result']} {failures or ''}"
        )
        del result, planner
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    return {
        "apks": rows,
        "workspaces_left_behind": leftovers,
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
        "status": "PASS"
        if rows and all(r["result"] == "PASS" for r in rows) and not leftovers
        else "FAIL",
    }


def _toolchain() -> dict[str, str]:
    def out(cmd: list[str]) -> str:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
            return (res.stdout or res.stderr).strip().splitlines()[0]
        except (OSError, IndexError, subprocess.SubprocessError):
            return "unavailable"

    tc = ToolchainConfig.discover()
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "apktool": out([*tc.apktool_command(), "--version"]) if tc.apktool else "unavailable",
        "java": out([str(tc.java), "-version"]) if tc.java else "unavailable",
        "git_head": out(["git", "-C", str(PROJECT_ROOT), "rev-parse", "--short", "HEAD"]),
    }


def _markdown(summary: dict[str, Any]) -> str:
    lines = ["# Phase H.2 validation summary (planning only)", ""]
    lines += [f"- Overall: **{summary['status']}**", f"- Run: `{summary['run_id']}`", ""]
    lines += ["## Toolchain", ""] + [f"- {k}: `{v}`" for k, v in summary["toolchain"].items()]
    syn = summary.get("synthetic")
    if syn:
        lines += ["", f"## Synthetic decisions ({syn['status']})", ""]
        lines += ["| Fixture | Transformation | Target | Expected | Got | Reasons | Result |"]
        lines += ["|---|---|---|---|---|---|---|"]
        for r in syn["cases"]:
            lines.append(
                f"| {r['fixture']} | {r['transformation']} | `{r['target']}` | {r['expected']} "
                f"| {r['eligibility']} | {', '.join(r['reasons']) or '-'} | {r['result']} |"
            )
    cor = summary.get("corpus")
    if cor:
        lines += ["", f"## Corpus planning, read-only ({cor['status']})", ""]
        lines += [
            "| APK | SHA-256 (12) | H.1 state | Targets | Plans | ELIGIBLE | COND. | REFUSED "
            "| UNSUPPORTED | UNDETERMINED | Unchanged | Plan s | Result |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in cor["apks"]:
            s = r["states"]
            lines.append(
                f"| {r['apk']} | `{r['sha256'][:12]}` | {r['analysis_state']} "
                f"| {r['targets_considered']} | {r['plans_generated']} | {s['ELIGIBLE']} "
                f"| {s['CONDITIONALLY_ELIGIBLE']} | {s['REFUSED']} | {s['UNSUPPORTED']} "
                f"| {s['UNDETERMINED']} | {r['original_unchanged']} | {r['planning_seconds']} "
                f"| {r['result']} |"
            )
        lines += ["", f"Max RSS: {cor['max_rss_mb']} MB", ""]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["synthetic", "corpus", "all"])
    ap.add_argument("--write", action="store_true", help="publish under artifacts/phase-h/")
    args = ap.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = PROJECT_ROOT / "work" / "phase-h2" / run_id
    work.mkdir(parents=True)
    summary: dict[str, Any] = {"run_id": run_id, "toolchain": _toolchain()}
    if args.mode in ("synthetic", "all"):
        summary["synthetic"] = run_synthetic(work / "synthetic")
    if args.mode in ("corpus", "all"):
        summary["corpus"] = run_corpus(work / "corpus")
    parts = [summary[k]["status"] for k in ("synthetic", "corpus") if k in summary]
    summary["status"] = "PASS" if all(p == "PASS" for p in parts) else "FAIL"

    (work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (work / "summary.md").write_text(_markdown(summary))
    print(f"[h2] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        if "synthetic" in summary:
            (ARTIFACTS / "h2-synthetic-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "synthetic")}, indent=2) + "\n"
            )
        if "corpus" in summary:
            (ARTIFACTS / "h2-corpus-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "corpus")}, indent=2) + "\n"
            )
        (ARTIFACTS / "h2-validation-summary.md").write_text(_markdown(summary))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
