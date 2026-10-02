#!/usr/bin/env python3
"""Phase C.4 corpus validation: real-toolchain BuildService run against the baseline.

    tests/corpus/manifest.json -> resolve APKs by SHA-256 -> BuildService.build_pipeline()
        -> compare with documented expectations (and optionally a previous run)
        -> results.json + report.md

Commands:

    run       build every corpus APK (default: twice, to check consistency)
    check     validate the manifest and APK hashes only (no build)
    describe  print manifest metadata for APKs (for adding corpus entries)

Usage:
    .venv-validation/bin/python build-tests/run_corpus_validation.py run [--repeat N]
        [--only ID ...] [--previous RESULTS.json] [--write-baseline]
    .venv-validation/bin/python build-tests/run_corpus_validation.py check
    .venv-validation/bin/python build-tests/run_corpus_validation.py describe APK...

Outputs go to work/corpus/<run-id>/ (results.json, report.md, workspaces/); the
corpus is read-only. ``--write-baseline`` also copies the results and report to
tests/corpus/results/. Exit code: 0 baseline check passed, 1 regression / new
failure / corpus error / inconsistency, 2 manifest invalid or toolchain unavailable.

Signing uses ``APKFORGE_SIGNING_*`` if set, otherwise the APKForge development key.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from apkforge.builders import (  # noqa: E402
    BuildService,
    SigningConfig,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.corpus import (  # noqa: E402
    CorpusManifest,
    CorpusManifestError,
    compare_with_previous,
    describe_apk,
    new_run_id,
    render_report,
    resolve_entries,
    run_corpus,
)

CORPUS_DIR = PROJECT_ROOT / "tests" / "corpus"
MANIFEST = CORPUS_DIR / "manifest.json"
BASELINE_DIR = CORPUS_DIR / "results"


def _load(manifest: Path) -> CorpusManifest | None:
    try:
        return CorpusManifest.load(manifest)
    except CorpusManifestError as exc:
        print(exc, file=sys.stderr)
        return None


def cmd_check(args: argparse.Namespace) -> int:
    manifest = _load(args.manifest)
    if manifest is None:
        return 2
    resolved, unlisted = resolve_entries(manifest, args.corpus)
    bad = 0
    for r in resolved:
        print(f"{r.identity:14} {r.entry.id:45} {r.entry.filename}")
        if r.problem:
            bad += 1
            print(f"               {r.problem}")
    for name in unlisted:
        print(f"{'UNLISTED':14} {'-':45} {name}")
    print(f"\n{len(resolved)} entries, {bad} problem(s), {len(unlisted)} unlisted APK(s)")
    return 1 if bad else 0


def cmd_describe(args: argparse.Namespace) -> int:
    print(json.dumps([describe_apk(p.resolve()) for p in args.apks], indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    manifest = _load(args.manifest)
    if manifest is None:
        return 2

    toolchain = ToolchainConfig.discover()
    signing = SigningConfig.from_env()
    if signing is None:
        if toolchain.keytool is None:
            print("keytool not found; cannot provision the development key", file=sys.stderr)
            return 2
        signing = ensure_dev_keystore(toolchain.keytool)

    run_dir = PROJECT_ROOT / "work" / "corpus"
    run_dir.mkdir(parents=True, exist_ok=True)
    # Every corpus build passes its own work_dir; the service default is never used.
    service = BuildService(toolchain, signing, work_dir=run_dir / "default")
    check = service.check_toolchain()
    for name, d in check.tools.items():
        print(f"  {name:18} {d.status:13} {d.version or '':10} {d.path}")
    if not check.valid:
        print(f"BLOCKED: toolchain unavailable: {check.errors}", file=sys.stderr)
        return 2

    previous = json.loads(args.previous.read_text()) if args.previous else None
    run_id = new_run_id()
    out = run_dir / run_id
    out.mkdir(exist_ok=False)
    run = run_corpus(
        service,
        manifest,
        args.corpus,
        out / "workspaces",
        repeat=args.repeat,
        stage_timeout=args.stage_timeout,
        only=args.only,
        repo_dir=PROJECT_ROOT,
        run_id=run_id,
        progress=lambda msg: print(msg, flush=True),
    )
    if previous is not None:
        compare_with_previous(run, previous)

    (out / "results.json").write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    report = render_report(run)
    (out / "report.md").write_text(report, encoding="utf-8")
    print("\n" + report)
    print(f"Results: {out / 'results.json'}\nReport:  {out / 'report.md'}")

    if args.write_baseline:
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / "results.json", BASELINE_DIR / "baseline.json")
        shutil.copyfile(out / "report.md", BASELINE_DIR / "baseline-report.md")
        print(f"Baseline written to {BASELINE_DIR}")
    return 0 if run.summary()["passed"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=MANIFEST)
    ap.add_argument("--corpus", type=Path, default=CORPUS_DIR)
    sub = ap.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="build every corpus APK and compare with the baseline")
    run.add_argument("--repeat", type=int, default=2, help="attempts per APK (default 2)")
    run.add_argument("--only", nargs="+", metavar="ID", help="restrict to these corpus ids")
    run.add_argument("--previous", type=Path, help="previous results.json to compare against")
    run.add_argument("--stage-timeout", type=int, default=900)
    run.add_argument("--write-baseline", action="store_true", help="copy into tests/corpus/results")
    run.set_defaults(func=cmd_run)

    sub.add_parser("check", help="validate manifest and APK hashes").set_defaults(func=cmd_check)

    desc = sub.add_parser("describe", help="print manifest metadata for APKs")
    desc.add_argument("apks", nargs="+", type=Path)
    desc.set_defaults(func=cmd_describe)

    args = ap.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
