#!/usr/bin/env python3
"""Phase H.7 validation: the generic third-party ModKit integration framework.

Subcommands:

    framework  Reference ``test-modkit`` (a real external process) on a synthetic APK:
               every scenario -> expected status/failure, original SHA-256 unchanged and
               nothing published on failure; timeout; no retry; environment isolation;
               secret masking across logs/metadata/result; shell-injection literalness;
               reproducibility (two runs -> identical output bytes and provenance modulo
               ids/timestamps/workspace paths); discovery/availability states.
    pipeline   Real toolchain (``source tools/env.sh`` first): published H.3 fixture A,
               test-modkit output, BuildService rebuild C of that output and control
               rebuild B of A; Phase E diff, Phase F/B before/after deltas, H.4
               verify_external with the change undeclared (expected FAILED) and declared
               (expected VERIFIED/VERIFIED_WITH_LIMITATIONS).
    corpus     test-modkit ``success`` on each corpus APK: output validated and published,
               marker present, every corpus SHA-256 unchanged.
    all        All three.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h7_validation.py all [--write]

Work files go to work/phase-h7/<run-id>/. ``--write`` publishes h7-*.json / .md under
artifacts/phase-h/ (earlier phase artifacts are not touched). Exit 0: every check as
expected; 1: a deviation; 2: toolchain unavailable (pipeline).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import shutil
import sys
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures import create_synthetic_apk  # noqa: E402

from apkforge.modkit import (  # noqa: E402
    AvailabilityStatus,
    ExecutionRequest,
    ModKitConfig,
    ModKitExecutionResult,
    ModKitManager,
    ModKitPostAnalysis,
    ModKitResultStatus,
)
from apkforge.modkit.masking import MASK  # noqa: E402
from apkforge.modkit.testing import (  # noqa: E402
    MARKER_ENTRY,
    SCENARIOS,
    TEST_MODKIT_ID,
    TestModKitAdapter,
)

ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
CORPUS = PROJECT_ROOT / "tests" / "corpus"
R = ModKitResultStatus
SECRET = "h7-validation-secret-7c1e"  # noqa: S105 - dummy value for masking checks

EXPECTED: dict[str, tuple[str, str | None]] = {
    "success": ("SUCCESS", None),
    "noop": ("NO_OP", None),
    "noop-empty": ("NO_OP", None),
    "noop-undeclared": ("OUTPUT_INVALID", "OUTPUT_UNCHANGED"),
    "missing-output": ("OUTPUT_MISSING", "OUTPUT_MISSING"),
    "no-declaration": ("OUTPUT_INVALID", "UNEXPECTED_ARTIFACT"),
    "invalid-apk": ("OUTPUT_INVALID", "OUTPUT_MALFORMED"),
    "truncated-apk": ("OUTPUT_INVALID", "OUTPUT_MALFORMED"),
    "nonzero-exit": ("EXECUTION_FAILED", "NON_ZERO_EXIT"),
    "timeout": ("TIMEOUT", "TIMEOUT"),
    "crash": ("EXECUTION_FAILED", "PROCESS_CRASH"),
    "multiple-outputs": ("OUTPUT_INVALID", "OUTPUT_AMBIGUOUS"),
    "extra-artifact": ("OUTPUT_INVALID", "UNEXPECTED_ARTIFACT"),
    "outside-workspace": ("OUTPUT_INVALID", "OUTPUT_OUTSIDE_WORKSPACE"),
    "outside-undeclared": ("OUTPUT_INVALID", "OUTPUT_OUTSIDE_WORKSPACE"),
    "symlink-escape": ("OUTPUT_INVALID", "OUTPUT_OUTSIDE_WORKSPACE"),
    "malicious-filename": ("OUTPUT_INVALID", "UNSAFE_FILENAME"),
    "traversal-entry": ("OUTPUT_INVALID", "OUTPUT_MALFORMED"),
    "directory-output": ("OUTPUT_INVALID", "OUTPUT_NOT_REGULAR_FILE"),
    "mutate-input": ("EXECUTION_FAILED", "INPUT_MUTATED"),
    "noisy": ("SUCCESS", None),
    "echo-env": ("SUCCESS", None),
    "echo-args": ("SUCCESS", None),
    "replace-output-dir": ("OUTPUT_INVALID", "OUTPUT_OUTSIDE_WORKSPACE"),
}


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manager(config: ModKitConfig | None = None) -> ModKitManager:
    m = ModKitManager()
    m.register(TEST_MODKIT_ID, lambda cfg: TestModKitAdapter(config or cfg))
    return m


def _execute(
    m: ModKitManager,
    apk: Path,
    out: Path,
    ws: Path,
    scenario: str = "success",
    **kw: Any,  # noqa: ANN401
) -> ModKitExecutionResult:
    params = {"scenario": scenario, **kw.pop("parameters", {})}
    return m.execute(
        TEST_MODKIT_ID,
        ExecutionRequest(
            input_apk=apk,
            output_dir=out,
            operation="transform",
            parameters=params,
            workspace_base=ws,
            **kw,
        ),
    )


def _check(failures: list[str], ok: bool, message: str) -> None:
    if not ok:
        failures.append(message)


# ---------------------------------------------------------------------------
# framework
# ---------------------------------------------------------------------------


def run_framework(work: Path) -> dict[str, Any]:
    failures: list[str] = []
    apk = create_synthetic_apk(work / "input" / "app.apk")
    sha = _sha(apk)
    m = _manager()
    rows = []
    for scenario in SCENARIOS:
        t0 = time.monotonic()
        kw: dict[str, Any] = {"timeout_seconds": 2} if scenario == "timeout" else {}
        res = _execute(m, apk, work / "out" / scenario, work / "ws", scenario, **kw)
        got = (str(res.status), str(res.failure) if res.failure else None)
        published = res.published is not None
        row = {
            "scenario": scenario,
            "status": got[0],
            "failure": got[1],
            "expected": list(EXPECTED[scenario]),
            "published": published,
            "original_unchanged": _sha(apk) == sha,
            "seconds": round(time.monotonic() - t0, 2),
            "reason": res.reason,
        }
        rows.append(row)
        _check(failures, got == EXPECTED[scenario], f"{scenario}: {got} != {EXPECTED[scenario]}")
        _check(failures, row["original_unchanged"], f"{scenario}: original changed")
        _check(failures, published == (got[0] == "SUCCESS"), f"{scenario}: publish mismatch")
        print(f"[framework] {scenario:20} {got[0]:17} {got[1] or ''}")

    # security: environment isolation + masking + literal arguments
    os.environ["H7_PARENT_TOKEN"] = "leak-me-parent-token"  # noqa: S105 - dummy
    try:
        env_res = _execute(m, apk, work / "sec-env", work / "ws", "echo-env", keep_workspace=True)
    finally:
        del os.environ["H7_PARENT_TOKEN"]
    env_ws = Path(env_res.workspace_path or "")
    child_env = json.loads((env_ws / "logs" / "stdout.log").read_text())
    env_leak = "leak-me" in json.dumps(child_env)
    _check(failures, not env_leak, "parent environment leaked into the ModKit")
    injection = "$(touch PWNED_A); `touch PWNED_B` && touch PWNED_C"
    sec = _execute(
        m,
        apk,
        work / "sec-args",
        work / "ws",
        "echo-args",
        keep_workspace=True,
        parameters={"api_token": SECRET + injection},
    )
    sec_ws = Path(sec.workspace_path or "")
    texts = [
        p.read_text(errors="replace")
        for p in sec_ws.rglob("*")
        if p.is_file() and p.suffix in (".log", ".json")
    ]
    secret_leaks = sum(SECRET in t for t in [*texts, sec.to_json()])
    pwned = sorted(str(p) for p in work.rglob("PWNED_*"))
    _check(failures, secret_leaks == 0, f"secret found in {secret_leaks} records")
    _check(failures, not pwned, f"shell metacharacters were interpreted: {pwned}")
    _check(failures, MASK in (sec_ws / "logs" / "stdout.log").read_text(), "echo not masked")

    # reproducibility
    a = _execute(m, apk, work / "repro-a", work / "ws")
    b = _execute(m, apk, work / "repro-b", work / "ws")

    def norm(res: ModKitExecutionResult) -> dict[str, Any]:
        assert res.provenance is not None
        d = res.provenance.model_dump(mode="json")
        root = d["workspace_path"]
        for k in ("execution_id", "workspace_id", "workspace_path", "start_time", "end_time"):
            d.pop(k)
        return json.loads(json.dumps(d, sort_keys=True).replace(root, "<WS>"))  # type: ignore[no-any-return]

    same_bytes = (
        a.published is not None
        and b.published is not None
        and (a.published.sha256 == b.published.sha256)
    )
    same_prov = norm(a) == norm(b)
    _check(failures, same_bytes, "two runs produced different output bytes")
    _check(failures, same_prov, "two runs produced different provenance")

    # availability states
    tool = work / "fake" / "tool.py"
    tool.parent.mkdir(parents=True)
    tool.write_text("print('test-modkit 0.5.0')\n")
    states = {
        "default": TestModKitAdapter().availability().status,
        "not_installed": TestModKitAdapter(
            ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=work / "missing.py")
        )
        .availability()
        .status,
        "dependency_missing": TestModKitAdapter(
            ModKitConfig(modkit_id=TEST_MODKIT_ID, options={"dependency_path": "/nonexistent"})
        )
        .availability()
        .status,
        "version_unsupported": TestModKitAdapter(
            ModKitConfig(modkit_id=TEST_MODKIT_ID, executable_path=tool)
        )
        .availability()
        .status,
        "disabled": TestModKitAdapter(ModKitConfig(modkit_id=TEST_MODKIT_ID, enabled=False))
        .availability()
        .status,
    }
    A = AvailabilityStatus
    want = {
        "default": A.AVAILABLE,
        "not_installed": A.NOT_INSTALLED,
        "dependency_missing": A.DEPENDENCY_MISSING,
        "version_unsupported": A.VERSION_UNSUPPORTED,
        "disabled": A.EXECUTION_UNAVAILABLE,
    }
    for k, v in want.items():
        _check(failures, states[k] is v, f"availability {k}: {states[k]} != {v}")

    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "input_sha256": sha,
        "scenarios": rows,
        "security": {
            "parent_env_leaked": env_leak,
            "child_env_keys": sorted(child_env),
            "secret_occurrences": secret_leaks,
            "shell_interpretation": pwned,
            "masked_arguments": sec.outcome.command.masked_arguments  # type: ignore[union-attr]
            if sec.outcome and sec.outcome.command
            else None,
        },
        "reproducibility": {
            "output_sha256": [
                a.published.sha256 if a.published else None,
                b.published.sha256 if b.published else None,
            ],
            "identical_output_bytes": same_bytes,
            "identical_provenance_modulo_ids": same_prov,
        },
        "availability": {k: str(v) for k, v in states.items()},
    }


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------


def run_pipeline(work: Path) -> dict[str, Any]:
    from tests.fixtures.h3_apks import H3_FIXTURES, publish_fixture, publisher_key

    from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
    from apkforge.builders.semantic_baseline import current_toolchain_identity, run_semantic_noop
    from apkforge.diff.expectations import ExpectedChange
    from apkforge.transformation import TransformationVerifier

    tc = ToolchainConfig.discover(framework_dir=work / "framework")
    if tc.keytool is None:
        raise SystemExit(2)
    svc = BuildService(tc, ensure_dev_keystore(tc.keytool, work / "dev-key"), work_dir=work / "ws")
    if not svc.check_toolchain().valid:
        raise SystemExit(2)
    failures: list[str] = []
    fx = {f.name: f for f in H3_FIXTURES}
    a = publish_fixture(
        svc, fx["h3_isolated"], work / "fixtures", publisher_key(tc.keytool, work / "publisher-key")
    )
    sha_a = _sha(a)
    res = _execute(_manager(), a, work / "modkit-out", work / "modkit-ws")
    _check(failures, res.status is R.SUCCESS, f"modkit: {res.status} {res.reason}")
    assert res.published is not None
    mk = Path(res.published.path)
    with zipfile.ZipFile(mk) as zf:
        _check(failures, MARKER_ENTRY in zf.namelist(), "marker missing")

    report = ModKitPostAnalysis().run(res)
    _check(failures, (report.diff_summary or {}).get("files_added") == 1, "diff: files_added")
    for d in (report.privacy, report.security):
        _check(
            failures,
            d is not None and not d.introduced and not d.removed,
            f"{d.source if d else '?'}: findings changed",
        )

    ctl = run_semantic_noop(svc, a, entry_id="control", work_dir=work / "control")
    cand = run_semantic_noop(svc, mk, entry_id="modkit", work_dir=work / "candidate")
    _check(failures, ctl.build_success and cand.build_success, "BuildService rebuild failed")
    b = work / "control" / f"{a.stem}.noop.apk"
    c = work / "candidate" / f"{mk.stem}.noop.apk"
    tid = current_toolchain_identity(svc)
    verifier = TransformationVerifier(svc)
    undeclared = verifier.verify_external(a, b, c, toolchain=tid)
    _check(failures, str(undeclared.status) == "FAILED", f"undeclared: {undeclared.status}")
    unexpected = [d.observation.identifier for d in undeclared.unexpected_changes]
    _check(failures, unexpected == [MARKER_ENTRY], f"unexpected changes: {unexpected}")
    obs = undeclared.unexpected_changes[0].observation
    declared = verifier.verify_external(
        a,
        b,
        c,
        toolchain=tid,
        expected=[
            ExpectedChange(
                category=obs.category, kind=obs.kind, identifier=obs.identifier, detail=obs.detail
            )
        ],
    )
    _check(
        failures,
        str(declared.status) in ("VERIFIED", "VERIFIED_WITH_LIMITATIONS"),
        f"declared: {declared.status} {declared.status_reason}",
    )
    _check(failures, _sha(a) == sha_a, "original changed")
    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "original_sha256": sha_a,
        "modkit_output_sha256": res.published.sha256,
        "analysis": report.model_dump(mode="json"),
        "buildservice": {"control": ctl.build_success, "modkit_output": cand.build_success},
        "h4_undeclared": {
            "status": str(undeclared.status),
            "reason": undeclared.status_reason,
            "unexpected": unexpected,
        },
        "h4_declared": {
            "status": str(declared.status),
            "reason": declared.status_reason,
            "expected": [d.observation.identifier for d in declared.expected_changes],
            "noise": len(declared.noise_changes),
        },
        "original_unchanged": _sha(a) == sha_a,
    }


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------


def run_corpus(work: Path) -> dict[str, Any]:
    failures: list[str] = []
    names = sorted(p.name for p in CORPUS.glob("*.apk"))
    before = {n: _sha(CORPUS / n) for n in names}
    m = _manager()
    rows = []
    for name in names:
        t0 = time.monotonic()
        res = _execute(m, CORPUS / name, work / "out" / name, work / "ws")
        marker = False
        if res.published is not None:
            with zipfile.ZipFile(res.published.path) as zf:
                marker = MARKER_ENTRY in zf.namelist()
            Path(res.published.path).unlink()  # large; the record is the evidence
        rows.append(
            {
                "apk": name,
                "status": str(res.status),
                "failure": str(res.failure) if res.failure else None,
                "input_sha256": before[name],
                "output_sha256": res.published.sha256 if res.published else None,
                "marker_present": marker,
                "checks": [c.id for c in res.validation],
                "seconds": round(time.monotonic() - t0, 1),
            }
        )
        _check(failures, res.status is R.SUCCESS and marker, f"{name}: {res.status} {res.reason}")
        print(f"[corpus] {name}: {res.status} ({rows[-1]['seconds']} s)")
    after = {n: _sha(CORPUS / n) for n in names}
    _check(failures, before == after, "a corpus APK changed")
    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "corpus_sha256_unchanged": before == after,
        "apks": rows,
    }


# ---------------------------------------------------------------------------


def _markdown(s: dict[str, Any]) -> str:
    out = [f"# Phase H.7 validation summary ({s['run_id']})", "", f"Overall: **{s['status']}**", ""]
    fw = s.get("framework")
    if fw:
        out += [
            "## Framework (reference test-modkit, synthetic APK)",
            "",
            f"- Status: **{fw['status']}**",
            "",
            "| Scenario | Status | Failure | Expected | Published | Original unchanged |",
            "|---|---|---|---|---|---|",
        ]
        for r in fw["scenarios"]:
            exp = " / ".join(x for x in r["expected"] if x)
            out.append(
                f"| {r['scenario']} | {r['status']} | {r['failure'] or '-'} | {exp} | "
                f"{r['published']} | {r['original_unchanged']} |"
            )
        sec, rep = fw["security"], fw["reproducibility"]
        out += [
            "",
            f"- Parent environment leaked: {sec['parent_env_leaked']} "
            f"(child env keys: {', '.join(sec['child_env_keys'])})",
            f"- Secret occurrences in logs/metadata/result: {sec['secret_occurrences']}",
            f"- Shell metacharacters interpreted: {bool(sec['shell_interpretation'])}",
            f"- Reproducible output bytes: {rep['identical_output_bytes']}; provenance "
            f"identical modulo ids/timestamps/paths: {rep['identical_provenance_modulo_ids']}",
            f"- Availability states: {fw['availability']}",
            "",
        ]
    pl = s.get("pipeline")
    if pl:
        an = pl["analysis"]
        out += [
            "## Pipeline (published fixture, BuildService, H.4)",
            "",
            f"- Status: **{pl['status']}**",
            f"- Diff files added: {an['diff_summary']['files_added']}",
            f"- Privacy delta: +{len(an['privacy']['introduced'])} "
            f"-{len(an['privacy']['removed'])} ={len(an['privacy']['retained'])}",
            f"- Security delta: +{len(an['security']['introduced'])} "
            f"-{len(an['security']['removed'])} ={len(an['security']['retained'])}",
            f"- BuildService rebuilds: {pl['buildservice']}",
            f"- H.4 undeclared: {pl['h4_undeclared']['status']} "
            f"(unexpected: {pl['h4_undeclared']['unexpected']})",
            f"- H.4 declared: {pl['h4_declared']['status']} "
            f"(expected: {pl['h4_declared']['expected']}, noise: {pl['h4_declared']['noise']})",
            f"- Original unchanged: {pl['original_unchanged']}",
            "",
        ]
    co = s.get("corpus")
    if co:
        out += [
            "## Corpus (test-modkit success)",
            "",
            f"- Status: **{co['status']}**; SHA-256 unchanged: {co['corpus_sha256_unchanged']}",
            "",
            "| APK | Status | Marker | Seconds |",
            "|---|---|---|---|",
        ]
        out += [
            f"| {r['apk']} | {r['status']} | {r['marker_present']} | {r['seconds']} |"
            for r in co["apks"]
        ]
        out.append("")
    for k in ("framework", "pipeline", "corpus"):
        if s.get(k, {}).get("failures"):
            out += [f"### {k} failures", "", *[f"- {f}" for f in s[k]["failures"]], ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["framework", "pipeline", "corpus", "all"])
    ap.add_argument("--write", action="store_true", help="publish under artifacts/phase-h/")
    args = ap.parse_args()
    logging.disable(logging.INFO)
    with contextlib.suppress(ImportError):
        from loguru import logger

        logger.disable("androguard")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = PROJECT_ROOT / "work" / "phase-h7" / run_id
    work.mkdir(parents=True)
    summary: dict[str, Any] = {"run_id": run_id}
    modes = ["framework", "pipeline", "corpus"] if args.mode == "all" else [args.mode]
    runners = {"framework": run_framework, "pipeline": run_pipeline, "corpus": run_corpus}
    for mode in modes:
        t0 = time.monotonic()
        summary[mode] = runners[mode](work / mode)
        summary[mode]["seconds"] = round(time.monotonic() - t0, 1)
    summary["status"] = "PASS" if all(summary[m]["status"] == "PASS" for m in modes) else "FAIL"
    (work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (work / "summary.md").write_text(_markdown(summary))
    print(f"[h7] {summary['status']} -> {work}")
    if args.write:
        for mode in modes:
            (ARTIFACTS / f"h7-{mode}-summary.json").write_text(
                json.dumps({"run_id": run_id, mode: summary[mode]}, indent=2) + "\n"
            )
        (ARTIFACTS / "h7-validation-summary.md").write_text(_markdown(summary))
    for mode in modes:
        shutil.rmtree(work / mode / "ws", ignore_errors=True)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
