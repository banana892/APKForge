#!/usr/bin/env python3
"""Phase H.1 validation: read-only reference analysis on real APKs.

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Build the 14 synthetic fixtures (tests/fixtures/h1_apks.py) into real APKs
               with BuildService (Apktool 3.0.3), analyse each twice, check the expected
               evidence, determinism (identical JSON) and that no APK changed.
    corpus     Analyse the 9 corpus APKs read-only: component states, evidence counts,
               SHA-256 unchanged, no proof of absence from incomplete analysis
               (sampled), determinism on OpenLink.
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h1_validation.py all [--write]

Work files go to work/phase-h/<run-id>/. ``--write`` publishes the summaries under
artifacts/phase-h/. No APK is modified, rebuilt from the corpus, signed or installed.
Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.h1_apks import FIXTURES, PKG, build_fixture  # noqa: E402

from apkforge.builders import BuildService, ToolchainConfig  # noqa: E402
from apkforge.reference import (  # noqa: E402
    AbsenceConclusion,
    AnalysisState,
    Component,
    MatchBasis,
    NativeResolution,
    ReferenceAnalysisResult,
    ReferenceAnalysisService,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
)

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
A, B, C = f"{PKG}.A", f"{PKG}.B", f"{PKG}.C"

Check = Callable[[ReferenceAnalysisResult], list[str]]


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _expect(cond: bool, msg: str, out: list[str]) -> None:
    if not cond:
        out.append(msg)


# ---------------------------------------------------------------------------
# Synthetic expectations (one per fixture; the pytest suite checks more detail)
# ---------------------------------------------------------------------------


def _f01(r: ReferenceAnalysisResult) -> list[str]:
    f: list[str] = []
    ix = r.index()
    q = ix.find_class_references(B)
    _expect(q.evidence == [], "B has callers", f)
    _expect(q.analysis_state is AnalysisState.COMPLETE, f"class refs {q.analysis_state}", f)
    aa = ix.assess_absence(B)
    _expect(aa.conclusion is AbsenceConclusion.NO_REFERENCES_WITHIN_SCOPE, aa.conclusion, f)
    return f


def _callers(expected: list[str], instr: str | None = None) -> Check:
    def check(r: ReferenceAnalysisResult) -> list[str]:
        f: list[str] = []
        ix = r.index()
        _expect(ix.callers_of(B) == expected, f"callers {ix.callers_of(B)}", f)
        if instr:
            got = {e.instruction for e in ix.find_class_references(B).evidence}
            _expect(instr in got, f"instructions {got}", f)
        return f

    return check


def _f04(r: ReferenceAnalysisResult) -> list[str]:
    q = r.index().find_method_references(B, "bar", "()V")
    ok = [(e.source_class, e.source_method, e.invoke_kind) for e in q.evidence] == [
        (A, "foo()V", "invoke-static")
    ]
    return [] if ok else [f"method refs {q.evidence}"]


def _f05(r: ReferenceAnalysisResult) -> list[str]:
    q = r.index().find_field_references(B, "counter", "I")
    got = sorted(str(e.access_kind) for e in q.evidence)
    return [] if got == ["sget", "sput"] else [f"field access {got}"]


def _f06(r: ReferenceAnalysisResult) -> list[str]:
    q = r.index().find_constructor_references(B, "()V")
    kinds = [(e.kind, e.invoke_kind) for e in q.evidence]
    instrs = {e.instruction for e in r.index().find_class_references(B).evidence}
    f: list[str] = []
    _expect(kinds == [(ReferenceKind.CONSTRUCTOR_REFERENCE, "invoke-direct")], str(kinds), f)
    _expect("new-instance" in instrs, f"instructions {instrs}", f)
    return f


def _f07(r: ReferenceAnalysisResult) -> list[str]:
    q = r.index().find_const_class_references(B)
    return [] if [e.source_class for e in q.evidence] == [A] else [f"{q.evidence}"]


def _f08(r: ReferenceAnalysisResult) -> list[str]:
    ix = r.index()
    f: list[str] = []
    s = ix.find_string_references(B).evidence
    _expect(len(s) == 1 and s[0].string_use is StringUse.POSSIBLE_CLASS_NAME, f"{s}", f)
    _expect(ix.find_class_references(B).evidence == [], "string became a class reference", f)
    aa = ix.assess_absence(B)
    _expect(aa.conclusion is AbsenceConclusion.ONLY_INDIRECT_EVIDENCE, aa.conclusion, f)
    return f


def _f09(r: ReferenceAnalysisResult) -> list[str]:
    ix = r.index()
    f: list[str] = []
    hits = [
        e
        for e in ix.find_reflection_evidence(B).evidence
        if e.reflection_api == "java.lang.Class.forName"
    ]
    _expect(
        len(hits) == 1 and hits[0].resolution is ResolutionStatus.TARGET_IDENTIFIED,
        f"forName {hits}",
        f,
    )
    _expect(r.component_state(Component.DEX) is AnalysisState.COMPLETE, "dex", f)
    _expect(r.component_state(Component.REFLECTION) is AnalysisState.PARTIAL, "reflection", f)
    aa = ix.assess_absence(C)
    _expect(aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED, aa.conclusion, f)
    return f


def _f10(r: ReferenceAnalysisResult) -> list[str]:
    q = r.index().find_native_dependencies(B)
    f: list[str] = []
    _expect([e.member_name for e in q.evidence] == ["nativeCall"], f"{q.evidence}", f)
    _expect(r.component_state(Component.NATIVE_CODE) is AnalysisState.NOT_ANALYZED, "native", f)
    return f


def _f11(r: ReferenceAnalysisResult) -> list[str]:
    loads = [e for e in r.native if e.kind is ReferenceKind.NATIVE_LIBRARY_LOAD]
    ok = [(e.library_name, e.native_resolution) for e in loads] == [
        ("h1native", NativeResolution.IDENTIFIED)
    ]
    return [] if ok else [f"loads {loads}"]


def _f12(r: ReferenceAnalysisResult) -> list[str]:
    ix = r.index()
    got = [(e.instruction, e.match_basis) for e in ix.find_manifest_references(B).evidence]
    return [] if got == [("service", MatchBasis.CLASS_ATTRIBUTE)] else [f"manifest {got}"]


def _f13(r: ReferenceAnalysisResult) -> list[str]:
    ix = r.index()
    f: list[str] = []
    b = [(e.source_file, e.match_basis) for e in ix.find_resource_references(B).evidence]
    _expect(b == [("res/layout/main.xml", MatchBasis.XML_ELEMENT_NAME)], f"B {b}", f)
    aa = ix.assess_absence(C)
    _expect(aa.conclusion is AbsenceConclusion.ONLY_INDIRECT_EVIDENCE, aa.conclusion, f)
    return f


def _f14(r: ReferenceAnalysisResult) -> list[str]:
    f: list[str] = []
    _expect(r.component_state(Component.ASSETS) is AnalysisState.PARTIAL, "assets", f)
    _expect(r.analysis_state is AnalysisState.PARTIAL, f"overall {r.analysis_state}", f)
    aa = r.index().assess_absence(B)
    _expect(aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED, aa.conclusion, f)
    _expect(not aa.absence_established, "absence established on PARTIAL analysis", f)
    return f


CHECKS: dict[str, Check] = {
    "f01_isolated": _f01,
    "f02_class_ref": _callers([A], "instance-of"),
    "f03_multiple_callers": _callers([A, C], "check-cast"),
    "f04_method_ref": _f04,
    "f05_field_ref": _f05,
    "f06_constructor": _f06,
    "f07_const_class": _f07,
    "f08_string": _f08,
    "f09_reflection": _f09,
    "f10_native_method": _f10,
    "f11_load_library": _f11,
    "f12_manifest": _f12,
    "f13_resource": _f13,
    "f14_incomplete": _f14,
}


def _service(work: Path) -> BuildService | None:
    svc = BuildService(ToolchainConfig.discover(framework_dir=work / "framework"), work_dir=work)
    return svc if svc.check_toolchain().valid else None


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    rows = []
    for fx in FIXTURES:
        apk = build_fixture(svc, fx, work)
        before = _sha(apk)
        r1 = analyzer.analyze(apk)
        r2 = analyzer.analyze(apk)
        failures = CHECKS[fx.name](r1)
        deterministic = r1.to_json() == r2.to_json()
        unchanged = _sha(apk) == before and bool(r1.original_unchanged and r2.original_unchanged)
        if not deterministic:
            failures.append("non-deterministic JSON")
        if not unchanged:
            failures.append("APK changed")
        if r1.errors:
            failures.append(f"errors {r1.errors}")
        (work / "fixtures").mkdir(exist_ok=True)
        (work / "fixtures" / f"{fx.name}.json").write_text(r1.to_json() + "\n")
        rows.append(
            {
                "fixture": fx.name,
                "description": fx.description,
                "apk_sha256": before,
                "analysis_state": r1.analysis_state.value,
                "components": {k: v.value for k, v in r1.component_states.items()},
                "evidence_counts": {k: v for k, v in r1.summary().items() if v},
                "deterministic": deterministic,
                "original_unchanged": unchanged,
                "result": "PASS" if not failures else "FAIL",
                "failures": [str(x) for x in failures],
            }
        )
        print(f"[synthetic] {fx.name}: {rows[-1]['result']} {rows[-1]['failures'] or ''}")
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    return {
        "fixtures": rows,
        "workspaces_left_behind": leftovers,
        "status": "PASS" if all(r["result"] == "PASS" for r in rows) and not leftovers else "FAIL",
    }


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
        t0 = time.monotonic()
        r = analyzer.analyze(apk)
        duration = round(time.monotonic() - t0, 1)
        failures: list[str] = []
        unchanged = _sha(apk) == before and r.original_unchanged is True
        _expect(unchanged, "APK changed", failures)
        _expect(not r.errors, f"errors {r.errors}", failures)
        # invariant: no proof of absence unless every component is COMPLETE
        ix = r.index()
        sample = [c.name for c in r.defined_classes[:: max(1, len(r.defined_classes) // 25)]]
        established = [c for c in sample if ix.assess_absence(c).absence_established]
        if r.analysis_state is not AnalysisState.COMPLETE:
            _expect(not established, f"absence established on {established}", failures)
        launcher = next((e.target for e in r.manifest if e.instruction == "activity"), None)
        launcher_conclusion = ix.assess_absence(launcher).conclusion.value if launcher else None
        if launcher:
            _expect(
                launcher_conclusion == AbsenceConclusion.REFERENCES_OBSERVED.value,
                f"declared activity {launcher}: {launcher_conclusion}",
                failures,
            )
        deterministic = None
        if name.startswith("de.audioattack.openlink"):
            deterministic = analyzer.analyze(apk).to_json() == r.to_json()
            _expect(deterministic, "non-deterministic JSON", failures)
        comps = {}
        for c in r.components:
            comps[c.component] = {
                "state": c.state.value,
                "issues": c.issue_count,
                "analysed": c.inputs_analyzed,
                "total": c.inputs_total,
            }
            for s in c.subcomponents:
                comps[s.component] = {
                    "state": s.state.value,
                    "issues": s.issue_count,
                    "analysed": s.inputs_analyzed,
                    "total": s.inputs_total,
                }
        issue_codes: dict[str, int] = {}
        for c in r.components:
            for s in [c, *c.subcomponents]:
                for i in s.issues:
                    issue_codes[i.code] = issue_codes.get(i.code, 0) + 1
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "package": r.apk.package_name,
                "analysis_state": r.analysis_state.value,
                "components": comps,
                "issue_codes_sampled": dict(sorted(issue_codes.items())),
                "defined_classes": len(r.defined_classes),
                "evidence_counts": r.summary(),
                "unresolved_reflection": sum(
                    1
                    for e in r.reflection
                    if e.resolution is not ResolutionStatus.TARGET_IDENTIFIED
                ),
                "bundled_native_libraries": len(r.bundled_native_libraries),
                "declared_activity_checked": launcher,
                "declared_activity_conclusion": launcher_conclusion,
                "absence_sample_size": len(sample),
                "absence_established_in_sample": len(established),
                "deterministic": deterministic,
                "original_unchanged": unchanged,
                "duration_seconds": duration,
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(f"[corpus] {name}: {r.analysis_state.value} {duration}s {rows[-1]['result']}")
        del r, ix
    leftovers = sorted(p.name for p in (work / "analysis").iterdir())
    return {
        "apks": rows,
        "workspaces_left_behind": leftovers,
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
    lines = ["# Phase H.1 validation summary", ""]
    lines += [f"- Overall: **{summary['status']}**", f"- Run: `{summary['run_id']}`", ""]
    lines += ["## Toolchain", ""] + [f"- {k}: `{v}`" for k, v in summary["toolchain"].items()]
    syn = summary.get("synthetic")
    if syn:
        lines += ["", f"## Synthetic fixtures ({syn['status']})", ""]
        lines += ["| Fixture | Result | State | Deterministic | APK unchanged | Notes |"]
        lines += ["|---|---|---|---|---|---|"]
        for r in syn["fixtures"]:
            lines.append(
                f"| {r['fixture']} | {r['result']} | {r['analysis_state']} | "
                f"{r['deterministic']} | {r['original_unchanged']} | "
                f"{'; '.join(r['failures']) or r['description']} |"
            )
    cor = summary.get("corpus")
    if cor:
        lines += ["", f"## Corpus, read-only ({cor['status']})", ""]
        lines += [
            "| APK | Result | Overall | dex | reflection | native_code | manifest | resources "
            "| assets | Classes | Unresolved reflection | Absence proven (sample) | Seconds |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in cor["apks"]:
            c = r["components"]
            lines.append(
                f"| {r['apk']} | {r['result']} | {r['analysis_state']} | {c['dex']['state']} "
                f"| {c['reflection']['state']} | {c['native_code']['state']} "
                f"| {c['manifest']['state']} | {c['resources']['state']} "
                f"| {c['assets']['state']} | {r['defined_classes']} "
                f"| {r['unresolved_reflection']} "
                f"| {r['absence_established_in_sample']}/{r['absence_sample_size']} "
                f"| {r['duration_seconds']} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["synthetic", "corpus", "all"])
    ap.add_argument("--write", action="store_true", help="publish under artifacts/phase-h/")
    args = ap.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = PROJECT_ROOT / "work" / "phase-h" / run_id
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
    print(f"[h1] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        if "synthetic" in summary:
            dest = ARTIFACTS / "fixtures"
            shutil.rmtree(dest, ignore_errors=True)
            shutil.copytree(work / "synthetic" / "fixtures", dest)
            (ARTIFACTS / "synthetic-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "synthetic")}, indent=2) + "\n"
            )
        if "corpus" in summary:
            (ARTIFACTS / "corpus-summary.json").write_text(
                json.dumps({k: summary[k] for k in ("toolchain", "corpus")}, indent=2) + "\n"
            )
        (ARTIFACTS / "validation-summary.md").write_text(_markdown(summary))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
