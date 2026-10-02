#!/usr/bin/env python3
"""Phase C.2 corpus run: no-op rebuild of every corpus APK through BuildService.

    original APK -> BuildService.build() (decode/build/align/sign/verify)
                 -> no-op integrity baseline -> build-tests/c2_results.json

The corpus is read-only input. Workspaces and rebuilt APKs go to work/c2/<run-id>/;
stage logs are copied to build-tests/logs/c2/<apk>/ for review.

Usage: .venv/bin/python build-tests/run_c2_corpus.py [--corpus DIR]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from apkforge.builders import (  # noqa: E402
    BuildOptions,
    BuildService,
    SigningConfig,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.noop_integrity import compare_noop_rebuild  # noqa: E402

RESULTS_FILE = PROJECT_ROOT / "build-tests" / "c2_results.json"
LOG_EXPORT = PROJECT_ROOT / "build-tests" / "logs" / "c2"
STAGES = ("decode", "build", "align", "sign", "verify")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=PROJECT_ROOT / "samples")
    args = ap.parse_args()

    run_id = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = PROJECT_ROOT / "work" / "c2" / run_id
    out_dir = run_dir / "outputs"

    toolchain = ToolchainConfig.discover()
    signing = SigningConfig.from_env()
    if signing is None:
        assert toolchain.keytool is not None, "keytool not found"
        signing = ensure_dev_keystore(toolchain.keytool)
    service = BuildService(toolchain, signing, work_dir=run_dir / "workspaces")

    check = service.check_toolchain()
    print(f"Toolchain valid: {check.valid}")
    for name, d in check.tools.items():
        print(f"  {name:18} {d.status:13} {d.version or '':10} {d.path}")
    for w in check.warnings:
        print(f"  warning: {w}")
    if not check.valid:
        print(f"Toolchain invalid: {check.errors}")
        return 2

    apks = sorted(args.corpus.glob("*.apk"))
    print(f"\nCorpus: {len(apks)} APKs from {args.corpus}\n")
    records = []
    t_run = time.monotonic()

    for i, apk in enumerate(apks, 1):
        print(f"[{i}/{len(apks)}] {apk.name} ({apk.stat().st_size:,} B) ...", flush=True)
        before = sha256(apk)
        res = service.build(
            apk,
            BuildOptions(
                output_apk=out_dir / f"{apk.stem}.rebuilt.apk",
                overwrite_output=True,
                keep_workspace_on_failure=True,
            ),
        )
        after = sha256(apk)
        stage_status = {str(s.stage): str(s.status) for s in res.stages}
        rec = {
            "apk": apk.name,
            "original_size": apk.stat().st_size,
            "original_sha256": before,
            "original_unchanged_after_build": before == after and bool(res.input_unchanged),
            "success": res.success,
            "stages": {k: stage_status.get(k, "NOT_RUN") for k in ("prepare", *STAGES)},
            "stage_durations_seconds": {
                str(s.stage): round(s.duration_seconds, 2) for s in res.stages
            },
            "failure_stage": str(res.failure_stage) if res.failure_stage else None,
            "failure_category": str(res.failure_category),
            "failure_cause": res.failure_cause,
            "failure_evidence": res.failure_evidence,
            "duration_seconds": round(res.duration_seconds, 2),
            "output_apk": str(res.output_apk) if res.output_apk else None,
            "rebuilt_size": res.output_apk.stat().st_size if res.output_apk else None,
            "workspace": str(res.workspace) if res.workspace else None,
            "verification": res.verification.to_dict() if res.verification else None,
            "warnings": res.warnings,
            "integrity": compare_noop_rebuild(apk, res.output_apk)
            if res.success and res.output_apk
            else None,
        }
        records.append(rec)

        if res.workspace and (res.workspace / "logs").is_dir():
            dest = LOG_EXPORT / apk.stem
            shutil.rmtree(dest, ignore_errors=True)
            shutil.copytree(res.workspace / "logs", dest)
            (dest / "result.json").write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
            rec["exported_logs"] = str(dest.relative_to(PROJECT_ROOT))

        row = " ".join(f"{k}={rec['stages'][k]}" for k in STAGES)
        print(f"    {'PASS' if res.success else 'FAIL'} {res.duration_seconds:6.1f}s  {row}")
        if not res.success:
            print(f"    {res.failure_stage} / {res.failure_category}: {res.failure_cause}")
            print(f"    evidence: {res.failure_evidence}\n    workspace: {res.workspace}")

    passed = sum(r["success"] for r in records)
    results = {
        "metadata": {
            "phase": "C.2",
            "title": "BuildService no-op rebuild corpus validation",
            "run_id": run_id,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "host": f"{platform.system()} {platform.release()} {platform.machine()}",
            "python": platform.python_version(),
            "corpus_dir": str(args.corpus),
            "total": len(records),
            "passed": passed,
            "failed": len(records) - passed,
            "total_duration_seconds": round(time.monotonic() - t_run, 1),
        },
        "toolchain": {"config": toolchain.to_dict(), "check": check.to_dict()},
        "signing": {
            "description": signing.describe(),
            "development_key": signing.development_key,
        },
        "results": records,
    }
    RESULTS_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"\n{passed}/{len(records)} passed in {results['metadata']['total_duration_seconds']}s")
    print(f"Results: {RESULTS_FILE}")
    print("\n| APK | Decode | Build | Align | Sign | Verify | Overall | Failure |")
    print("|---|---|---|---|---|---|---|---|")
    for r in records:
        st = r["stages"]
        fail = "-" if r["success"] else f"{r['failure_stage']}: {r['failure_category']}"
        print(
            f"| {r['apk']} | "
            + " | ".join(st[k] for k in STAGES)
            + f" | {'PASS' if r['success'] else 'FAIL'} | {fail} |"
        )
    return 0 if passed == len(records) else 1


if __name__ == "__main__":
    sys.exit(main())
