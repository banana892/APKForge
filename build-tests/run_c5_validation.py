#!/usr/bin/env python3
"""Phase C.5 validation: semantic no-op baseline, toolchain comparison, OpenLink modification.

Commands:

    noop          no-op round trip of every corpus APK through BuildService, then
                  DiffEngine + noise classification (the semantic no-op baseline)
    compare-old   the same no-op round trip with the Phase B pinned Docker toolchain
                  (Apktool 2.10.0, build-tools 34.0.0, JDK 17) for a few APKs, compared
                  with the current-toolchain semantic baseline
    modify        C.5: disable OpenLink's boot receiver through the controlled pipeline
                  and verify expected vs actual changes

Usage:
    .venv-validation/bin/python build-tests/run_c5_validation.py noop [--only ID ...] [--write]
    .venv-validation/bin/python build-tests/run_c5_validation.py compare-old --only ID ... [--write]
    .venv-validation/bin/python build-tests/run_c5_validation.py modify [--write]

Outputs go to work/c5/<run-id>/. ``--write`` also copies the JSON + Markdown result into
tests/corpus/results/ (c5-semantic-noop-baseline.*, c5-toolchain-comparison.*,
c5-openlink-result.*). The C.4 baseline files there are never written.
Exit code: 0 success, 1 check failed, 2 toolchain/corpus unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from apkforge.builders import (  # noqa: E402
    BuildService,
    CommandRunner,
    SigningConfig,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.corpus import (  # noqa: E402
    CorpusManifest,
    EntryIdentity,
    _apkforge_revision,
    new_run_id,
    resolve_entries,
    sha256_file,
    toolchain_versions,
)
from apkforge.builders.semantic_baseline import (  # noqa: E402
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
    classify_noop_diff,
    run_semantic_noop,
)
from apkforge.diff.engine import DiffEngine  # noqa: E402
from apkforge.diff.expectations import ObservationClass  # noqa: E402
from apkforge.modification.controlled import (  # noqa: E402
    ControlledModificationResult,
    ModificationStatus,
    run_disable_boot_receiver,
)

CORPUS_DIR = PROJECT_ROOT / "tests" / "corpus"
MANIFEST = CORPUS_DIR / "manifest.json"
RESULTS_DIR = CORPUS_DIR / "results"
NOOP_BASELINE = RESULTS_DIR / "c5-semantic-noop-baseline.json"
PHASE_E_BASELINE = RESULTS_DIR / "phase-e-noise-baseline.json"
OPENLINK_ID = "de.audioattack.openlink@28"
OLD_IMAGE = "apkforge-toolchain:pinned"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _service(run_dir: Path) -> BuildService | None:
    toolchain = ToolchainConfig.discover()
    signing = SigningConfig.from_env()
    if signing is None:
        if toolchain.keytool is None:
            print("keytool not found; cannot provision the development key", file=sys.stderr)
            return None
        signing = ensure_dev_keystore(toolchain.keytool)
    service = BuildService(toolchain, signing, work_dir=run_dir / "default")
    check = service.check_toolchain()
    if not check.valid:
        print(f"BLOCKED: toolchain unavailable: {check.errors}", file=sys.stderr)
        return None
    return service


def _toolchain_record(service: BuildService) -> dict[str, Any]:
    check = service.check_toolchain().to_dict()
    return {
        "versions": toolchain_versions(check),
        "android_platform": service.toolchain.android_platform,
        "signing_mode": str(service.signing.mode) if service.signing else None,
        "apkforge": _apkforge_revision(CommandRunner(), PROJECT_ROOT),
    }


def _entries(only: list[str] | None) -> list[tuple[str, Path]]:
    manifest = CorpusManifest.load(MANIFEST)
    resolved, _ = resolve_entries(manifest, CORPUS_DIR)
    out = []
    for r in resolved:
        if only and r.entry.id not in only:
            continue
        if r.identity not in (EntryIdentity.OK, EntryIdentity.RENAMED) or r.path is None:
            raise SystemExit(f"corpus entry unusable: {r.entry.id}: {r.problem}")
        out.append((r.entry.id, r.path))
    return out


def _run_dir(kind: str) -> Path:
    d = PROJECT_ROOT / "work" / "c5" / f"{new_run_id()}-{kind}"
    d.mkdir(parents=True)
    return d


def _write(out: Path, stem: str, data: dict[str, Any], report: str, publish: bool) -> None:
    (out / f"{stem}.json").write_text(json.dumps(data, indent=2, default=str) + "\n")
    (out / f"{stem}.md").write_text(report)
    print(report)
    print(f"Results: {out / (stem + '.json')}")
    if publish:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / f"{stem}.json", RESULTS_DIR / f"{stem}.json")
        shutil.copyfile(out / f"{stem}.md", RESULTS_DIR / f"{stem}.md")
        print(f"Written to {RESULTS_DIR}")


# ---------------------------------------------------------------------------
# noop
# ---------------------------------------------------------------------------


def cmd_noop(args: argparse.Namespace) -> int:
    out = _run_dir("noop")
    service = _service(out)
    if service is None:
        return 2
    baseline = NoopSemanticBaseline(toolchain=_toolchain_record(service))
    for entry_id, apk in _entries(args.only):
        print(f"[noop] {entry_id} ...", flush=True)
        before = sha256_file(apk)
        e = run_semantic_noop(service, apk, entry_id=entry_id, work_dir=out / "builds" / entry_id)
        if sha256_file(apk) != before:
            e.notes.append("ORIGINAL APK CHANGED")
            e.result = SemanticResult.NOT_EQUIVALENT
        print(f"        -> {e.result}", flush=True)
        baseline.entries.append(e)
    data = baseline.model_dump(mode="json")
    _write(out, "c5-semantic-noop-baseline", data, render_noop(baseline), args.write)
    bad = [e for e in baseline.entries if e.result in ("NOT_EQUIVALENT", "BUILD_FAILED")]
    return 1 if bad else 0


def render_noop(b: NoopSemanticBaseline) -> str:
    t = b.toolchain.get("versions", {})
    lines = [
        "# C.5 precondition: semantic no-op baseline",
        "",
        f"Generated {b.generated_at}. Toolchain: "
        + ", ".join(f"{k} {v}" for k, v in t.items())
        + f", platform {b.toolchain.get('android_platform')}; APKForge "
        f"{(b.toolchain.get('apkforge') or {}).get('git_commit')}.",
        "",
        "Original APK -> `BuildService.build_pipeline` (no modification) -> rebuilt APK; "
        "`DiffEngine.diff(original, rebuilt)`; every observation classified by "
        "`apkforge.diff.expectations` with no expected changes. Separate from the C.4 build "
        "baseline (`baseline.json`), which it does not change.",
        "",
        "| APK | SHA-256 | result | noise | residue | unexpected | unknown | diff |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for e in b.entries:
        noise = sum(e.noise_rule_counts.values())
        lines.append(
            f"| {e.id} | `{e.sha256[:16]}…` | **{e.result}** | {noise} | {len(e.residue)} | "
            f"{len(e.unexpected)} | {len(e.unknown)} | {e.diff_status or '-'} |"
        )
    lines += ["", "## Noise rules hit (observations per rule)", ""]
    rules = sorted({r for e in b.entries for r in e.noise_rule_counts})
    lines.append("| APK | " + " | ".join(rules) + " |")
    lines.append("|---|" + "---:|" * len(rules))
    for e in b.entries:
        lines.append(
            f"| {e.id} | " + " | ".join(str(e.noise_rule_counts.get(r, 0)) for r in rules) + " |"
        )
    lines += ["", "Rule definitions:", ""]
    lines += [f"- `{k}`: {v}" for k, v in b.noise_rules.items()]
    lines += ["", "## Per-APK details", ""]
    for e in b.entries:
        lines.append(f"### {e.id}")
        lines.append("")
        lines.append(
            f"- build: {'SUCCESS' if e.build_success else e.build_failure}; "
            f"input unchanged: {e.input_unchanged}; rebuilt `{e.rebuilt_sha256}`"
        )
        for o in e.residue:
            lines.append(f"- residue: {o.kind} `{o.identifier}` ({o.detail.get('size')} bytes)")
        for o in e.unexpected:
            lines.append(f"- UNEXPECTED: {o.category} {o.kind} `{o.identifier}` {o.detail}")
        for o in e.unknown:
            lines.append(f"- UNKNOWN: {o.category} {o.kind} `{o.identifier}` {o.detail}")
        for f in e.diff_failures:
            lines.append(f"- diff: {f}")
        for n in e.notes:
            lines.append(f"- note: {n}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# compare-old
# ---------------------------------------------------------------------------

_OLD_SCRIPT = r"""
set -euo pipefail
cd /w
apktool --version > apktool.version
apktool d -f -o decoded -p fw in.apk > decode.log 2>&1
apktool b decoded -o unaligned.apk -p fw > build.log 2>&1
zipalign -p -f 4 unaligned.apk aligned.apk > zipalign.log 2>&1
zipalign -c -p 4 aligned.apk >> zipalign.log 2>&1
keytool -genkeypair -keystore k.p12 -storetype PKCS12 -alias c5 -keyalg RSA -keysize 2048 \
  -validity 2 -dname "CN=APKForge C5 throwaway, O=NOT FOR RELEASE" \
  -storepass "$KS_PASS" -keypass "$KS_PASS" > keytool.log 2>&1
apksigner sign --ks k.p12 --ks-pass env:KS_PASS --out signed.apk aligned.apk > sign.log 2>&1
apksigner verify --verbose signed.apk > verify.log 2>&1
rm -f k.p12
"""


def _old_toolchain_noop(apk: Path, work: Path) -> tuple[bool, str, Path | None]:
    work.mkdir(parents=True)
    shutil.copyfile(apk, work / "in.apk")  # the corpus is never mounted
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "JAVA_TOOL_OPTIONS=-Duser.home=/tmp",
        "-e",
        "KS_PASS",
        "-v",
        f"{work}:/w",
        OLD_IMAGE,
        "bash",
        "-c",
        _OLD_SCRIPT,
    ]
    env = {**os.environ, "KS_PASS": os.urandom(12).hex()}
    # Fixed argv (no shell); docker is resolved from PATH like in the Phase B evidence runs.
    proc = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, env=env, timeout=3600, check=False
    )
    (work / "docker.log").write_text(proc.stdout + proc.stderr)
    (work / "k.p12").unlink(missing_ok=True)
    signed = work / "signed.apk"
    ok = proc.returncode == 0 and signed.is_file()
    return ok, f"exit {proc.returncode}", signed if ok else None


def _docker_image_id() -> str | None:
    argv = ["docker", "image", "inspect", "--format", "{{.Id}}", OLD_IMAGE]
    proc = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or None


def cmd_compare_old(args: argparse.Namespace) -> int:
    if not NOOP_BASELINE.is_file():
        print(f"{NOOP_BASELINE} missing: run `noop --write` first", file=sys.stderr)
        return 2
    current = NoopSemanticBaseline.model_validate_json(NOOP_BASELINE.read_text())
    image = _docker_image_id()
    if image is None:
        print(f"BLOCKED: docker image {OLD_IMAGE} unavailable", file=sys.stderr)
        return 2
    out = _run_dir("compare-old")
    rows: list[dict[str, Any]] = []
    engine = DiffEngine()
    for entry_id, apk in _entries(args.only):
        print(f"[old toolchain] {entry_id} ...", flush=True)
        before = sha256_file(apk)
        ok, how, signed = _old_toolchain_noop(apk, out / entry_id)
        cur = current.entry_for(before)
        row: dict[str, Any] = {
            "id": entry_id,
            "sha256": before,
            "old_build": "SUCCESS" if ok else how,
        }
        if ok and signed is not None:
            result, detail = classify_noop_diff(engine.diff(apk, signed))
            old = NoopSemanticEntry(
                id=entry_id,
                filename=apk.name,
                sha256=before,
                build_success=True,
                result=result,
                **detail,
            )
            row["old"] = old.model_dump(mode="json")
            row["apktool_version"] = (out / entry_id / "apktool.version").read_text().strip()
        row["current"] = cur.model_dump(mode="json") if cur else None
        row["original_unchanged"] = sha256_file(apk) == before
        row["classification"], row["conclusion"] = _compare(row)
        rows.append(row)
        print(f"        -> {row['classification']}", flush=True)
    data = {
        "name": "C.5 toolchain comparison (no-op, old vs current)",
        "generated_at": _now(),
        "old_toolchain": {
            "image": OLD_IMAGE,
            "image_id": image,
            "apktool": "2.10.0",
            "build_tools": "34.0.0",
            "java": "OpenJDK 17.0.20.1 (Temurin)",
            "signing": "throwaway PKCS12 key generated per APK, deleted after signing",
        },
        "current_toolchain": current.toolchain,
        "rows": rows,
    }
    _write(out, "c5-toolchain-comparison", data, render_compare(data), args.write)
    return 0


def _obs_keys(entry: dict[str, Any] | None, field: str) -> set[str]:
    if not entry:
        return set()
    return {f"{o['category']} {o['kind']} {o['identifier']}" for o in entry.get(field, [])}


def _compare(row: dict[str, Any]) -> tuple[str, str]:
    old, cur = row.get("old"), row.get("current")
    if old is None or cur is None:
        return "INCOMPLETE", "Comparison not possible (a build failed or no current baseline)."
    rules_old, rules_cur = set(old["noise_rule_counts"]), set(cur["noise_rule_counts"])
    unexp_old, unexp_cur = _obs_keys(old, "unexpected"), _obs_keys(cur, "unexpected")
    if old["result"] == cur["result"] and rules_old == rules_cur and unexp_old == unexp_cur:
        return (
            "SAME_CLASSIFICATION",
            "Both toolchains produce the same semantic no-op classification.",
        )
    parts = []
    if old["result"] != cur["result"]:
        parts.append(f"result {old['result']} (old) vs {cur['result']} (current)")
    if rules_old != rules_cur:
        parts.append(
            f"noise rules only old: {sorted(rules_old - rules_cur)}, "
            f"only current: {sorted(rules_cur - rules_old)}"
        )
    if unexp_old - unexp_cur:
        sample = sorted(unexp_old - unexp_cur)
        parts.append(f"{len(sample)} unexplained only with old toolchain, e.g. {sample[:5]}")
    if unexp_cur - unexp_old:
        parts.append(f"unexplained only with current toolchain: {sorted(unexp_cur - unexp_old)}")
    return "DIFFERENT", "; ".join(parts)


def render_compare(d: dict[str, Any]) -> str:
    o = d["old_toolchain"]
    lines = [
        "# C.5 toolchain comparison: no-op round trip, Phase B toolchain vs current",
        "",
        f"Generated {d['generated_at']}.",
        "",
        f"- **old**: `{o['image']}` (`{o['image_id']}`): Apktool {o['apktool']}, build-tools "
        f"{o['build_tools']}, {o['java']}; signed with {o['signing']}.",
        "- **current**: "
        + ", ".join(f"{k} {v}" for k, v in d["current_toolchain"]["versions"].items())
        + " (BuildService), from `c5-semantic-noop-baseline.json`.",
        "",
        "Both outputs are compared with the same original by the same `DiffEngine` and "
        "classified by the same noise rules. The two toolchains are not treated as "
        "interchangeable; this records whether their no-op output differs materially.",
        "",
        "| APK | old result | current result | classification |",
        "|---|---|---|---|",
    ]
    for r in d["rows"]:
        old = (r.get("old") or {}).get("result", r.get("old_build"))
        cur = (r.get("current") or {}).get("result", "-")
        lines.append(f"| {r['id']} | {old} | {cur} | **{r['classification']}** |")
    lines += ["", "## Conclusions per APK", ""]
    for r in d["rows"]:
        lines.append(f"### {r['id']}")
        lines.append("")
        lines.append(f"- {r['conclusion']}")
        old = r.get("old") or {}
        cur = r.get("current") or {}
        lines.append(f"- old noise rules: {old.get('noise_rule_counts')}")
        lines.append(f"- current noise rules: {cur.get('noise_rule_counts')}")
        lines.append(
            f"- old unexplained: {len(old.get('unexpected', []))}, "
            f"current unexplained: {len(cur.get('unexpected', []))}"
        )
        lines.append(f"- original unchanged: {r['original_unchanged']}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# modify
# ---------------------------------------------------------------------------


def cmd_modify(args: argparse.Namespace) -> int:
    # Since Phase E the modification is verified against the content-aware (schema 2)
    # baseline; the schema-1 C.5 baseline can no longer produce VERIFIED.
    source = PHASE_E_BASELINE if PHASE_E_BASELINE.is_file() else NOOP_BASELINE
    if not source.is_file():
        print(f"{NOOP_BASELINE} missing: run `noop --write` first", file=sys.stderr)
        return 2
    baseline = NoopSemanticBaseline.model_validate_json(source.read_text())
    out = _run_dir("modify")
    service = _service(out)
    if service is None:
        return 2
    ((entry_id, apk),) = _entries([args.entry])
    res = run_disable_boot_receiver(
        service,
        apk,
        noop_baseline=baseline,
        work_dir=out / "builds",
        output_apk=out / "openlink-c5-modified.apk",
        keep_workspace=True,  # evidence: decoded project + stage logs stay in work/
    )
    data = {
        "name": "C.5 OpenLink controlled modification",
        "generated_at": _now(),
        "corpus_id": entry_id,
        "toolchain": _toolchain_record(service),
        "result": res.model_dump(mode="json"),
    }
    _write(out, "c5-openlink-result", data, render_modify(data, res), args.write)
    return 0 if res.status == ModificationStatus.VERIFIED else 1


def render_modify(d: dict[str, Any], r: ControlledModificationResult) -> str:
    v = r.verdict
    tc = d["toolchain"]
    lines = [
        f"# C.5 result: {r.status}",
        "",
        f"Generated {d['generated_at']}. Corpus entry `{d['corpus_id']}`.",
        "",
        "## Identity and toolchain (observed)",
        "",
        f"- APK: `{Path(r.apk).name}`, package `{r.baseline.get('package')}` "
        f"{r.baseline.get('version_name')} ({r.baseline.get('version_code')})",
        f"- original SHA-256: `{r.original_sha256_before}`",
        "- toolchain: "
        + ", ".join(f"{k} {v}" for k, v in tc["versions"].items())
        + f", platform {tc['android_platform']}; signing: {tc['signing_mode']}",
        f"- APKForge commit: `{tc['apkforge'].get('git_commit')}` "
        f"(dirty: {tc['apkforge'].get('git_dirty')})",
        "",
        "## Modification plan (declared before applying)",
        "",
    ]
    if r.plan:
        p = r.plan
        lines += [
            f"- operation: {p.operation}",
            f"- status: {p.status}",
            f"- permission: `{p.permission}`",
            f"- target receiver (derived from the decoded manifest): `{p.receiver}`",
            "- preconditions:",
            *[f"  - [{'x' if c.satisfied else ' '}] {c.name}: {c.detail}" for c in p.preconditions],
            "- planned source edits:",
            *[
                f"  - {e.kind} `{e.element}`"
                + (f" {e.attribute}: {e.before!r} -> {e.after!r}" if e.attribute else "")
                for e in p.source_edits
            ],
            "- expected semantic changes (DiffEngine terms):",
            *[
                f"  - {e.category} {e.kind} `{e.identifier}` {e.detail or ''}"
                for e in p.expected_changes
            ],
            "- declared consequences:",
            *[f"  - {c}" for c in p.consequences],
            "- problems:" if p.problems else "",
            *[f"  - {x}" for x in p.problems],
        ]
    lines += ["", "## Changes actually applied (observed, decoded manifest)", ""]
    if r.apply:
        lines.append(
            f"- applied: {r.apply.applied}; observed edits == planned edits: {r.apply.matches_plan}"
        )
        lines += [
            f"  - {e.kind} `{e.element}`"
            + (f" {e.attribute}: {e.before!r} -> {e.after!r}" if e.attribute else "")
            for e in r.apply.observed_edits
        ]
    lines += [
        "",
        "## Pipeline stages (BuildService)",
        "",
        "| stage | status | failure |",
        "|---|---|---|",
    ]
    lines += [
        f"| {s.stage} | {s.status} | {s.failure_category or ''} {s.failure_cause or ''} |"
        for s in r.stages
    ]
    if r.verification:
        ver = r.verification
        cert = ver.get("certificate") or {}
        lines += [
            "",
            f"- verification: valid={ver.get('valid')}, zipalign={ver.get('zipalign_verified')}, "
            f"signature={ver.get('signature_verified')}, expected signer="
            f"{ver.get('expected_signer_matched')}, "
            f"zip integrity={ver.get('zip_integrity_verified')}",
            f"- signer: `{cert.get('subject_dn')}` sha256 `{cert.get('sha256_digest')}`; schemes "
            f"v1={cert.get('v1_scheme')} v2={cert.get('v2_scheme')} v3={cert.get('v3_scheme')}",
            f"- modified APK SHA-256: `{r.output_sha256}`",
        ]
    lines += ["", "## Expected vs actual (DiffEngine, original vs modified)", ""]
    if v:
        lines += [
            f"- noise floor: {r.noise_floor.get('source')}; allowed rules "
            f"{r.noise_floor.get('allowed_noise_rules')}; "
            f"residue {r.noise_floor.get('allowed_residue')}",
            f"- classification counts: {v.counts}",
            f"- noise per rule: {v.noise_rule_counts}",
            f"- expected changes observed: {len(v.expected_observed)}/"
            f"{len(v.expected_observed) + len(v.expected_missing)}",
            "",
            "Expected modifications observed:",
            "",
            *[
                f"- {c.observation.category} {c.observation.kind} `{c.observation.identifier}` "
                f"{c.observation.detail}"
                for c in v.of(ObservationClass.EXPECTED_MODIFICATION)
            ],
            "",
            "Unexpected / unknown:",
            "",
            *(
                [
                    f"- **{c.classification}**: {c.observation.category} {c.observation.kind} "
                    f"`{c.observation.identifier}` {c.observation.detail} ({c.reason})"
                    for c in v.of(ObservationClass.UNEXPECTED) + v.of(ObservationClass.UNKNOWN)
                ]
                or ["- none"]
            ),
            "",
            f"- verdict: {'PASS' if v.passed else 'FAIL'} {v.failures or ''}",
        ]
    lines += [
        "",
        "## Original preservation (observed)",
        "",
        f"- before `{r.original_sha256_before}`",
        f"- after  `{r.original_sha256_after}`",
        f"- preserved: **{r.original_preserved}**",
        "",
        "## Failures",
        "",
        *([f"- {f}" for f in r.failures] or ["- none"]),
        "",
        "## Limitations (what this does NOT show)",
        "",
        *[f"- {x}" for x in (r.plan.limitations if r.plan else [])],
        "- The modified APK is not shown to be behaviourally equivalent apart from the intended "
        "change, malware-free, spyware-free, safe to install, or runnable on a device.",
        "- DiffEngine compares a subset of the manifest (5 application attributes, SDK levels, "
        "permissions, component exported/permission/enabled/process, and the actions, "
        "categories and data of activity/service/receiver intent filters); other manifest "
        "content (e.g. `<queries>`, `<meta-data>`, `<activity-alias>`) is covered only by the "
        "source-level edit check above (see docs/known-limitations.md).",
        "- resources.arsc and recompiled res/ files are accepted as rebuild noise without "
        "semantic comparison.",
    ]
    return "\n".join(x for x in lines if x is not None) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    n = sub.add_parser("noop", help="semantic no-op baseline (current toolchain)")
    n.add_argument("--only", nargs="+", metavar="ID")
    n.add_argument("--write", action="store_true")
    n.set_defaults(func=cmd_noop)
    c = sub.add_parser("compare-old", help="no-op with the Phase B Docker toolchain")
    c.add_argument("--only", nargs="+", metavar="ID", required=True)
    c.add_argument("--write", action="store_true")
    c.set_defaults(func=cmd_compare_old)
    m = sub.add_parser("modify", help="C.5 OpenLink boot-receiver modification")
    m.add_argument("--entry", default=OPENLINK_ID)
    m.add_argument("--write", action="store_true")
    m.set_defaults(func=cmd_modify)
    args = ap.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
