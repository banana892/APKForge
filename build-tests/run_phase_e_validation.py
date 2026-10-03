#!/usr/bin/env python3
"""Phase E validation: diff + verification hardening on the real corpus.

Subcommands (real toolchain; ``source tools/env.sh`` first):

    baseline   For every C.4 corpus APK: no-op rebuild #1 -> schema-2 content-aware
               baseline entry (fingerprint); no-op rebuild #2 -> reproducibility (same
               fingerprint, per-entry content determinism) and pair verification of the
               rebuild against the new baseline; comparison with the C.5 (schema 1)
               baseline, every drift explained.
    openlink   Verification scenarios on OpenLink through the modification pipeline and
               ``verify_pair``: no-op, C.5 modification, undeclared/declared manifest
               change, marker, combined, undeclared file, missing expectation,
               content-hash protection, invalid APK, invalid signature, cross-toolchain.

Usage:
    .venv-validation/bin/python build-tests/run_phase_e_validation.py baseline [--write]
    .venv-validation/bin/python build-tests/run_phase_e_validation.py openlink [--write]

Work files go to work/phase-e/<run-id>/. ``--write`` publishes the evidence under
artifacts/phase-e/ and (baseline only) tests/corpus/results/phase-e-noise-baseline.json.
Phase C/D evidence is never written. Exit 0: every check as expected; 1: a deviation;
2: toolchain or corpus unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.integration.phase_d_modifiers import UndeclaredChangeModifier  # noqa: E402
from tests.integration.phase_e_modifiers import (  # noqa: E402
    DeclaredMetaDataModifier,
    MissingExpectationModifier,
    UndeclaredMetaDataModifier,
)
from tests.integration.phase_e_support import rezip, tamper_first  # noqa: E402

from apkforge.builders import (  # noqa: E402
    BuildService,
    CommandRunner,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.corpus import (  # noqa: E402
    CorpusManifest,
    EntryIdentity,
    _apkforge_revision,
    new_run_id,
    resolve_entries,
)
from apkforge.builders.models import BuildOptions  # noqa: E402
from apkforge.builders.semantic_baseline import (  # noqa: E402
    NoopSemanticBaseline,
    classify_noop_diff,
    current_toolchain_identity,
    run_semantic_noop,
)
from apkforge.diff.archive import ArchiveInventory, raw_diff  # noqa: E402
from apkforge.diff.expectations import ObservationClass  # noqa: E402
from apkforge.diff.normalization import (  # noqa: E402
    NORMALIZATION_SCHEMA_VERSION,
    RULE_POLICIES,
    SEMANTIC_SCHEMA_VERSION,
    ToolchainIdentity,
)
from apkforge.modification.builtin import BootReceiverModifier, MarkerAssetModifier  # noqa: E402
from apkforge.modification.catalog import ModifierCatalog  # noqa: E402
from apkforge.modification.pipeline import (  # noqa: E402
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
)
from apkforge.verification import render_markdown, verify_pair  # noqa: E402

CORPUS_DIR = PROJECT_ROOT / "tests" / "corpus"
RESULTS_DIR = CORPUS_DIR / "results"
LEGACY_BASELINE = RESULTS_DIR / "c5-semantic-noop-baseline.json"
PHASE_E_BASELINE = RESULTS_DIR / "phase-e-noise-baseline.json"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-e"
OPENLINK = CORPUS_DIR / "de.audioattack.openlink_28.apk"
OLD_TOOLCHAIN = ToolchainIdentity(  # Phase B pinned Docker image (apkforge-toolchain:pinned)
    java="17",
    apktool="2.10.0",
    zipalign="34.0.0",
    apksigner="34.0.0",
    build_tools="34.0.0",
    android_platform="android-34",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _service(run_dir: Path) -> BuildService | None:
    toolchain = ToolchainConfig.discover()
    if toolchain.keytool is None:
        print("keytool not found", file=sys.stderr)
        return None
    service = BuildService(
        toolchain, ensure_dev_keystore(toolchain.keytool), work_dir=run_dir / "builds"
    )
    check = service.check_toolchain()
    if not check.valid:
        print(f"BLOCKED: toolchain unavailable: {check.errors}", file=sys.stderr)
        return None
    return service


def _entries(only: list[str] | None) -> list[tuple[str, Path]]:
    manifest = CorpusManifest.load(CORPUS_DIR / "manifest.json")
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
    d = PROJECT_ROOT / "work" / "phase-e" / f"{new_run_id()}-{kind}"
    d.mkdir(parents=True)
    return d


def _dump(path: Path, data: Any) -> None:  # noqa: ANN401
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")


def _revision() -> dict[str, Any]:
    return _apkforge_revision(CommandRunner(), PROJECT_ROOT)


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------


#: Noise rules introduced in Phase E (not in the C.5 schema-1 rule set).
PHASE_E_RULES = {"manifest_reference_inlined"}


def _drift(new: Any, old: Any) -> list[str]:  # noqa: ANN401 - NoopSemanticEntry
    """Differences between the schema-2 and schema-1 entry of one APK, with a reason."""
    if old is None:
        return ["no C.5 (schema 1) entry"]
    out = []
    if str(new.result) != str(old.result):
        out.append(f"result {old.result} -> {new.result} (reason: unexplained)")
    if new.noise_rule_counts != old.noise_rule_counts:
        added = {k: v for k, v in new.noise_rule_counts.items() if k not in old.noise_rule_counts}
        same = {k: v for k, v in new.noise_rule_counts.items() if k in old.noise_rule_counts}
        if set(added) <= PHASE_E_RULES and same == old.noise_rule_counts:
            out.append(
                f"new noise rule(s) {added} (reason: semantic extractor extension — the Phase "
                "E full manifest tree comparison observes a difference C.5 could not see)"
            )
        else:
            out.append(
                f"noise rules {old.noise_rule_counts} -> {new.noise_rule_counts} "
                "(reason: unexplained)"
            )

    def keys(e: Any) -> list[tuple[str, str, str]]:  # noqa: ANN401
        return sorted((o.category, o.kind, o.identifier) for o in e.residue)

    if keys(new) != keys(old):
        out.append("residue differs (reason: unexplained)")
    if new.diff_status != old.diff_status:
        out.append(f"diff status {old.diff_status} -> {new.diff_status} (reason: unexplained)")
    return out


def cmd_baseline(args: argparse.Namespace) -> int:
    out = _run_dir("baseline")
    service = _service(out)
    if service is None:
        return 2
    identity = current_toolchain_identity(service)
    assert identity is not None
    legacy = NoopSemanticBaseline.model_validate_json(LEGACY_BASELINE.read_text())
    baseline = NoopSemanticBaseline(
        name="Phase E content-aware semantic no-op baseline",
        purpose=(
            "Per-APK rebuild-noise fingerprint (accepted differences with content hashes) "
            "for one exact toolchain identity. Separate from the C.4 build baseline and the "
            "C.5 schema-1 baseline, which it does not change."
        ),
        toolchain={"versions": identity.model_dump(), "apkforge": _revision()},
        toolchain_identity=identity,
    )
    rows: list[dict[str, Any]] = []
    for entry_id, apk in _entries(args.only):
        print(f"[baseline] {entry_id}: no-op #1 ...", flush=True)
        before = _sha(apk)
        work = out / "builds" / entry_id
        e1 = run_semantic_noop(service, apk, entry_id=entry_id, work_dir=work / "r1")
        baseline.entries.append(e1)
        row: dict[str, Any] = {
            "id": entry_id,
            "sha256": e1.sha256,
            "result": str(e1.result),
            "fingerprint_by_rule": e1.fingerprint.rule_counts() if e1.fingerprint else {},
            "fingerprint_by_policy": _by_policy(e1),
            "comparisons": e1.comparisons,
            "raw_counts": e1.raw_counts,
            "residue": [o.identifier for o in e1.residue],
            "unexpected": [f"{o.category} {o.kind} {o.identifier}" for o in e1.unexpected],
            "unknown": [f"{o.category} {o.kind} {o.identifier}" for o in e1.unknown],
            "diff_failures": e1.diff_failures,
            "drift_vs_c5": _drift(e1, legacy.entry_for(e1.sha256)),
        }
        if e1.build_success:
            r1 = work / "r1" / f"{apk.stem}.noop.apk"
            print(f"[baseline] {entry_id}: no-op #2 + pair verification ...", flush=True)
            r2 = work / f"{apk.stem}.noop2.apk"
            res = service.build_pipeline(
                apk, BuildOptions(output_apk=r2, overwrite_output=True, work_dir=work / "r2")
            )
            if res.success:
                det = raw_diff(ArchiveInventory.from_apk(r1), ArchiveInventory.from_apk(r2))
                one = NoopSemanticBaseline(toolchain_identity=identity, entries=[e1])
                report, diff = verify_pair(
                    apk,
                    r2,
                    baseline=one,
                    service=service,
                    build_toolchain=identity,
                    expected_signer=e1.signer_sha256,
                )
                _, detail2 = classify_noop_diff(diff) if diff else (None, {})
                fp2 = detail2.get("fingerprint")
                row.update(
                    rebuild_determinism={
                        "content_changes_between_rebuilds": det.counts["added"]
                        + det.counts["removed"]
                        + det.counts["modified"],
                        "metadata_only_changes": det.metadata_only_changes,
                        "rebuild1_sha256": det.sha256_before,
                        "rebuild2_sha256": det.sha256_after,
                    },
                    fingerprint_reproducible=bool(
                        fp2 is not None
                        and e1.fingerprint is not None
                        and fp2.model_dump() == e1.fingerprint.model_dump()
                    ),
                    pair_verification=str(report.verification.overall),
                    pair_reason=report.verification.overall_reason,
                    pair_checks={k: str(c.status) for k, c in report.verification.checks.items()},
                    security_changes=report.security.counts() if report.security else None,
                    normalized=report.normalized.get("counts"),
                )
                (out / "reports").mkdir(exist_ok=True)
                (out / "reports" / f"{entry_id}.md").write_text(render_markdown(report))
            else:
                row["rebuild2_failure"] = f"{res.failure_stage}: {res.failure_cause}"
        if _sha(apk) != before:
            row["ORIGINAL_CHANGED"] = True
        rows.append(row)
        print(
            f"        -> {row['result']}; pair {row.get('pair_verification')}; reproducible "
            f"{row.get('fingerprint_reproducible')}; drift {row['drift_vs_c5']}",
            flush=True,
        )

    data = baseline.model_dump(mode="json")
    _dump(out / "phase-e-noise-baseline.json", data)
    validation = {
        "generated_at": _now(),
        "toolchain": identity.model_dump(),
        "apkforge": _revision(),
        "normalization_schema": NORMALIZATION_SCHEMA_VERSION,
        "semantic_schema": SEMANTIC_SCHEMA_VERSION,
        "rule_policies": {k: str(v) for k, v in RULE_POLICIES.items()},
        "entries": rows,
    }
    _dump(out / "corpus-validation.json", validation)
    md = render_baseline(validation)
    (out / "corpus-validation.md").write_text(md)
    print(md)
    if args.write:
        dest = ARTIFACTS / "corpus"
        dest.mkdir(parents=True, exist_ok=True)
        # The baseline itself is published once, in tests/corpus/results (6 MB).
        for name in ("corpus-validation.json", "corpus-validation.md"):
            shutil.copyfile(out / name, dest / name)
        shutil.copytree(out / "reports", dest / "pair-reports", dirs_exist_ok=True)
        shutil.copyfile(out / "phase-e-noise-baseline.json", PHASE_E_BASELINE)
        print(f"Written to {dest} and {PHASE_E_BASELINE}")
    bad = [
        r
        for r in rows
        if r["result"] in ("NOT_EQUIVALENT", "BUILD_FAILED")
        or r.get("ORIGINAL_CHANGED")
        or r.get("fingerprint_reproducible") is False
    ]
    return 1 if bad else 0


def _by_policy(e: Any) -> dict[str, int]:  # noqa: ANN401
    out: dict[str, int] = {}
    for a in e.fingerprint.accepted if e.fingerprint else []:
        out[str(a.policy)] = out.get(str(a.policy), 0) + 1
    return dict(sorted(out.items()))


def render_baseline(v: dict[str, Any]) -> str:
    t = v["toolchain"]
    lines = [
        "# Phase E: content-aware no-op baseline and corpus validation",
        "",
        f"Generated {v['generated_at']}. Toolchain: apktool {t['apktool']}, build-tools "
        f"{t['build_tools']}, java {t['java']}, zipalign {t['zipalign']}, apksigner "
        f"{t['apksigner']}, {t['android_platform']}; normalization schema "
        f"{v['normalization_schema']}, semantic schema {v['semantic_schema']}; APKForge "
        f"{v['apkforge'].get('git_commit')} (dirty: {v['apkforge'].get('git_dirty')}).",
        "",
        "Per APK: no-op rebuild #1 establishes the fingerprint; no-op rebuild #2 checks "
        "per-entry determinism, fingerprint reproducibility and is verified against the "
        "fingerprint with `verify_pair` (structural, apksigner, normalized/semantic/security "
        "diff).",
        "",
        "| APK | result | fingerprint (exact / path_only / signer) | rebuild #2 content diffs "
        "| reproducible | pair verification | drift vs C.5 |",
        "|---|---|---|---:|---|---|---|",
    ]
    for r in v["entries"]:
        pol = r["fingerprint_by_policy"]
        det = r.get("rebuild_determinism") or {}
        lines.append(
            f"| {r['id']} | {r['result']} | {pol.get('exact', 0)} / {pol.get('path_only', 0)} / "
            f"{pol.get('signer', 0)} | {det.get('content_changes_between_rebuilds', '-')} | "
            f"{r.get('fingerprint_reproducible')} | {r.get('pair_verification')} | "
            f"{'; '.join(r['drift_vs_c5']) or 'none'} |"
        )
    lines += ["", "## Incomplete comparators (no-op diff)", ""]
    for r in v["entries"]:
        bad = {
            k: s
            for k, s in r["comparisons"].items()
            if s not in ("unchanged", "modified", "added", "removed")
        }
        lines.append(f"- {r['id']}: {bad or 'none'}")
    lines += ["", "## Pair verification details", ""]
    for r in v["entries"]:
        lines.append(f"- {r['id']}: {r.get('pair_verification')} — {r.get('pair_reason')}")
        if r.get("unexpected") or r.get("unknown") or r.get("diff_failures"):
            lines.append(
                f"  - unexpected {r['unexpected']}; unknown {r['unknown']}; "
                f"diff {r['diff_failures']}"
            )
    lines += ["", "## Rule policies", ""]
    lines += [f"- `{k}`: {p}" for k, p in v["rule_policies"].items()]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# openlink
# ---------------------------------------------------------------------------


def _catalog() -> ModifierCatalog:
    return ModifierCatalog(
        [
            BootReceiverModifier(),
            MarkerAssetModifier(),
            UndeclaredChangeModifier(),
            UndeclaredMetaDataModifier(),
            DeclaredMetaDataModifier(),
            MissingExpectationModifier(),
        ]
    )


def _pipeline_summary(res: PipelineResult) -> dict[str, Any]:
    v = res.verdict
    m = res.verification_matrix
    fp_entries = None
    return {
        "status": str(res.status),
        "order": res.order,
        "counts": res.counts(),
        "baseline_status": str(res.baseline_check.status) if res.baseline_check else None,
        "classification": v.counts if v else None,
        "mode": v.mode if v else None,
        "noise_by_rule": v.noise_rule_counts if v else None,
        "expected_declared": sum(len(r.plan.expected_changes) for r in res.modifiers if r.plan),
        "expected_observed": [
            f"{e.category} {e.kind} {e.identifier}" for e in (v.expected_observed if v else [])
        ],
        "expected_missing": [
            f"{e.category} {e.kind} {e.identifier}" for e in (v.expected_missing if v else [])
        ],
        "planned_entries": [
            c.observation.identifier for c in (v.of(ObservationClass.PLANNED_ENTRY) if v else [])
        ],
        "unexpected": [
            f"{c.observation.category} {c.observation.kind} {c.observation.identifier}: {c.reason}"
            for c in (v.of(ObservationClass.UNEXPECTED) if v else [])
        ],
        "unknown": [
            f"{c.observation.category} {c.observation.kind} {c.observation.identifier}: {c.reason}"
            for c in (v.of(ObservationClass.UNKNOWN) if v else [])
        ],
        "matrix": {k: str(c.status) for k, c in m.checks.items()} if m else None,
        "overall": str(m.overall) if m else None,
        "overall_reason": m.overall_reason if m else None,
        "security": {
            k: [f"{i.change} {i.subject} [{i.classification}]" for i in s.items]
            for k, s in (
                res.report.security.sections.items() if res.report and res.report.security else []
            )
            if s.items
        },
        "original_preserved": res.original_preserved,
        "failures": res.failures,
        "warnings": res.warnings,
        "fingerprint": fp_entries,
    }


def _report_summary(report: Any) -> dict[str, Any]:  # noqa: ANN401
    v = report.verification
    return {
        "overall": str(v.overall),
        "overall_reason": v.overall_reason,
        "matrix": {k: str(c.status) for k, c in v.checks.items()},
        "baseline_status": str(report.baseline.status) if report.baseline else None,
        "classification": report.normalized.get("counts"),
        "unexpected": [
            f"{u['category']} {u['kind']} {u['identifier']}: {u['reason']}"
            for u in report.unexpected
        ],
        "unknown_count": len(report.unknown),
        "unknown_sample": [
            f"{u['category']} {u['kind']} {u['identifier']}" for u in report.unknown[:5]
        ],
        "signature": v.checks["signature"].summary,
        "structural": v.checks["structural"].summary,
    }


def _old_toolchain_noop(apk: Path, work: Path) -> Path | None:
    spec = importlib.util.spec_from_file_location(
        "c5runner", PROJECT_ROOT / "build-tests" / "run_c5_validation.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if mod._docker_image_id() is None:
        return None
    ok, _, signed = mod._old_toolchain_noop(apk, work)
    return signed if ok else None


def cmd_openlink(args: argparse.Namespace) -> int:
    out = _run_dir("openlink")
    service = _service(out)
    if service is None:
        return 2
    if not PHASE_E_BASELINE.is_file():
        print(f"{PHASE_E_BASELINE} missing: run `baseline --write` first", file=sys.stderr)
        return 2
    baseline = NoopSemanticBaseline.model_validate_json(PHASE_E_BASELINE.read_text())
    legacy = NoopSemanticBaseline.model_validate_json(LEGACY_BASELINE.read_text())
    identity = current_toolchain_identity(service)
    original_sha = _sha(OPENLINK)
    entry = baseline.entry_for(original_sha)
    assert entry is not None and entry.fingerprint is not None
    fp = entry.fingerprint
    pipeline = ModificationPipeline(service, _catalog())
    results: dict[str, Any] = {}
    problems: list[str] = []
    reports = out / "reports"
    reports.mkdir()

    def run(sid: str, mods: list[str], expect: str, **checks: object) -> PipelineResult:
        print(f"[openlink] {sid}: {' + '.join(mods)} ...", flush=True)
        res = pipeline.run(
            OPENLINK,
            [ModifierRequest(modifier_id=m) for m in mods],
            noop_baseline=baseline,
            work_dir=out / "ws" / sid,
        )
        s = _pipeline_summary(res)
        s["expect"] = expect
        bad = [] if s["status"] == expect else [f"status {s['status']} != {expect}"]
        if not s["original_preserved"]:
            bad.append("original changed")
        for key, val in checks.items():
            if s.get(key) != val and not (callable(val) and val(s)):
                bad.append(f"{key}: {s.get(key)!r} (expected {val!r})")
        s["problems"] = bad
        problems.extend(f"{sid}: {b}" for b in bad)
        results[sid] = s
        if res.report is not None:
            (reports / f"{sid}.md").write_text(render_markdown(res.report))
            _dump(reports / f"{sid}.json", res.report.model_dump(mode="json"))
        print(f"        -> {s['status']} / {s['overall']} {bad or ''}", flush=True)
        return res

    def pair(
        sid: str,
        apk: Path,
        expect: str,
        *,
        base: NoopSemanticBaseline = baseline,
        toolchain: ToolchainIdentity | None = identity,
        signer: str | None = None,
        **checks: object,
    ) -> dict[str, Any]:
        print(f"[openlink] {sid}: verify_pair ...", flush=True)
        report, _ = verify_pair(
            OPENLINK,
            apk,
            baseline=base,
            service=service,
            build_toolchain=toolchain,
            expected_signer=signer,
        )
        s = _report_summary(report)
        s["expect"] = expect
        allowed = expect.split("|")  # "FAILED|UNDETERMINED": any of these
        bad = [] if s["overall"] in allowed else [f"overall {s['overall']} != {expect}"]
        for key, val in checks.items():
            got = s["matrix"].get(key) if key in s["matrix"] else s.get(key)
            if got != val:
                bad.append(f"{key}: {got!r} (expected {val!r})")
        s["problems"] = bad
        problems.extend(f"{sid}: {b}" for b in bad)
        results[sid] = s
        (reports / f"{sid}.md").write_text(render_markdown(report))
        _dump(reports / f"{sid}.json", report.model_dump(mode="json"))
        print(f"        -> {s['overall']} {bad or ''}", flush=True)
        return s

    # A: no-op rebuild, verified against the fingerprint
    noop = out / "openlink.noop.apk"
    r = service.build_pipeline(
        OPENLINK, BuildOptions(output_apk=noop, overwrite_output=True, work_dir=out / "noop")
    )
    assert r.success, r.failure_cause
    pair("A_noop", noop, "VERIFIED", unexpected_changes="passed", noise_baseline="passed")

    # B: the C.5 modification; numbers derived from the baseline, not hard-coded
    c5 = run("B_c5", ["c5.disable_boot_receiver"], "verified")
    planned = set(results["B_c5"]["planned_entries"])
    derived_noise = sum(
        1 for a in fp.accepted if not (a.category == "file" and a.identifier in planned)
    )
    s = results["B_c5"]
    declared = s["expected_declared"]
    got_noise = (s["classification"] or {}).get("rebuild_noise")
    s["derived"] = {
        "declared_expected": declared,
        "baseline_fingerprint_entries": len(fp.accepted),
        "planned_entries": sorted(planned),
        "derived_noise": derived_noise,
    }
    for cond, msg in (
        (len(s["expected_observed"]) == declared, "expected observed != declared"),
        (got_noise == derived_noise, f"noise {got_noise} != derived {derived_noise}"),
        ((s["classification"] or {}).get("unexpected") == 0, "unexpected != 0"),
        ((s["classification"] or {}).get("unknown") == 0, "unknown != 0"),
        (s["overall"] == "VERIFIED", "matrix not VERIFIED"),
        (
            bool(s["security"].get("permissions")) and bool(s["security"].get("components")),
            "permission/component change missing from the security diff",
        ),
    ):
        if not cond:
            s["problems"].append(msg)
            problems.append(f"B_c5: {msg}")
    _ = c5

    run("C_undeclared_manifest", ["test.undeclared_meta_data"], "failed", overall="FAILED")
    if not any(
        "manifest_element added" in u for u in results["C_undeclared_manifest"]["unexpected"]
    ):
        problems.append("C: undeclared <meta-data> not reported as unexpected manifest_element")
    # The test modifier has no verify(): the run is correctly "unverified" (Phase D
    # semantics); what matters here is that the declared manifest_element change matched.
    run(
        "C2_declared_manifest",
        ["test.declared_meta_data"],
        "unverified",
        matrix=lambda s: (
            s["matrix"]["expected_changes"] == "passed"
            and s["matrix"]["unexpected_changes"] == "passed"
        ),
    )
    run("D_marker", ["test.marker_asset"], "verified", overall="VERIFIED")
    run(
        "E_combined",
        ["c5.disable_boot_receiver", "test.marker_asset"],
        "verified",
        overall="VERIFIED",
    )
    run("F_undeclared_file", ["test.undeclared"], "failed", overall="FAILED")
    run("G_missing_expectation", ["test.missing_expectation"], "failed", overall="FAILED")
    if not results["G_missing_expectation"]["expected_missing"]:
        problems.append("G: missing expectation not reported")

    # H: content-hash protection. Change the content of a res/ entry whose *path* the
    # baseline accepts as rebuild noise, re-align and re-sign: the path rule would accept
    # it, the content fingerprint must not.
    candidates = [
        a.identifier
        for a in fp.accepted
        if a.category == "file" and a.kind == "renamed" and a.identifier.endswith(".xml")
    ]
    target_path, tampered_bytes = tamper_first(noop, candidates)
    target = next(a for a in fp.accepted if a.identifier == target_path)
    tampered = out / "tampered-unsigned.apk"
    rezip(noop, tampered, {target.identifier: tampered_bytes})
    aligned, signed = out / "tampered-aligned.apk", out / "tampered-signed.apk"
    assert service.align(tampered, aligned).passed
    assert service.sign(aligned, signed).passed
    h = pair("H_content_hash_v2", signed, "FAILED", unexpected_changes="failed", signature="passed")
    h["tampered_entry"] = target.identifier
    if not any(target.identifier in u for u in h["unexpected"]):
        problems.append("H: tampered entry not reported as unexpected")
    hl = pair("H_content_hash_legacy", signed, "UNDETERMINED", base=legacy)
    hl["tampered_entry"] = target.identifier
    hl["note"] = (
        "schema-1 path rules accept the tampered entry as resource_path_canonicalized "
        "noise (the blind spot Phase E closes); the matrix is UNDETERMINED only "
        "because legacy noise is path-rule assured"
    )
    if any(target.identifier in u for u in hl["unexpected"]):
        hl["note"] = "legacy path rules flagged the entry (unexpected)"

    # I: invalid APK (truncated archive)
    broken = out / "truncated.apk"
    data = noop.read_bytes()
    broken.write_bytes(data[: len(data) // 2])
    pair("I_invalid_apk", broken, "FAILED", structural="failed")

    # J: invalid signature (entry content changed after signing, not re-signed)
    unsigned_change = out / "signature-broken.apk"
    rezip(noop, unsigned_change, {target.identifier: tampered_bytes})
    pair("J_invalid_signature", unsigned_change, "FAILED", signature="failed")

    # K: cross-toolchain protection
    pair(
        "K1_declared_other_toolchain",
        noop,
        "UNDETERMINED",
        toolchain=OLD_TOOLCHAIN,
        noise_baseline="undetermined",
        baseline_status="BASELINE_INCOMPATIBLE",
    )
    old = _old_toolchain_noop(OPENLINK, out / "old-toolchain")
    if old is None:
        results["K2_real_old_toolchain"] = {"skipped": "docker image unavailable"}
    else:
        k2 = pair(
            "K2_real_old_toolchain_undeclared",
            old,
            # Never VERIFIED. Observed: Apktool 2.10.0 drops non-signature META-INF
            # entries, which are real removals (unexpected) -> FAILED.
            "FAILED|UNDETERMINED",
            toolchain=None,
            baseline_status="TOOLCHAIN_UNKNOWN",
        )
        if k2["overall"] == "VERIFIED":
            problems.append("K2: other-toolchain rebuild verified against this toolchain")
        if not k2["unknown_count"]:
            problems.append("K2: content mismatches with an unknown build toolchain not UNKNOWN")
        pair(
            "K3_real_old_toolchain_declared",
            old,
            "FAILED|UNDETERMINED",
            toolchain=OLD_TOOLCHAIN,
            baseline_status="BASELINE_INCOMPATIBLE",
        )
        if (results["K3_real_old_toolchain_declared"]["classification"] or {}).get("rebuild_noise"):
            problems.append("K3: noise accepted from an incompatible baseline")

    summary = {
        "generated_at": _now(),
        "apk": OPENLINK.name,
        "original_sha256": original_sha,
        "original_unchanged": _sha(OPENLINK) == original_sha,
        "toolchain": identity.model_dump() if identity else None,
        "apkforge": _revision(),
        "baseline": PHASE_E_BASELINE.relative_to(PROJECT_ROOT).as_posix(),
        "scenarios": results,
        "problems": problems,
    }
    if not summary["original_unchanged"]:
        problems.append("ORIGINAL CHANGED")
    _dump(out / "openlink-scenarios.json", summary)
    md = render_openlink(summary)
    (out / "openlink-scenarios.md").write_text(md)
    print(md)
    if args.write:
        dest = ARTIFACTS / "openlink"
        dest.mkdir(parents=True, exist_ok=True)
        for name in ("openlink-scenarios.json", "openlink-scenarios.md"):
            shutil.copyfile(out / name, dest / name)
        shutil.copytree(reports, dest / "reports", dirs_exist_ok=True)
        print(f"Written to {dest}")
    return 1 if problems else 0


def render_openlink(s: dict[str, Any]) -> str:
    lines = [
        f"# Phase E: OpenLink verification scenarios — {'PASS' if not s['problems'] else 'FAIL'}",
        "",
        f"Generated {s['generated_at']}. APK `{s['apk']}` sha256 `{s['original_sha256']}` "
        f"(unchanged after the run: {s['original_unchanged']}). Baseline `{s['baseline']}`. "
        f"APKForge {s['apkforge'].get('git_commit')} (dirty: {s['apkforge'].get('git_dirty')}).",
        "",
        "| scenario | expected | result | matrix overall | classification | problems |",
        "|---|---|---|---|---|---|",
    ]
    for sid, r in s["scenarios"].items():
        if "skipped" in r:
            lines.append(f"| {sid} | - | skipped | - | - | {r['skipped']} |")
            continue
        lines.append(
            f"| {sid} | {r['expect']} | {r.get('status', r.get('overall'))} | {r.get('overall')} "
            f"| {r.get('classification')} | {'; '.join(r['problems']) or 'none'} |"
        )
    lines += ["", "## Details", ""]
    for sid, r in s["scenarios"].items():
        lines.append(f"### {sid}")
        lines.append("")
        for k in (
            "overall_reason",
            "baseline_status",
            "derived",
            "expected_observed",
            "expected_missing",
            "planned_entries",
            "unexpected",
            "unknown_sample",
            "matrix",
            "security",
            "tampered_entry",
            "note",
            "signature",
            "structural",
        ):
            if r.get(k):
                lines.append(f"- {k}: {r[k]}")
        lines.append("")
    lines.append(
        "Modified APKs are not installed or run. VERIFIED means structurally valid, "
        "correctly signed and changed only as planned within the comparator coverage; "
        "it does not mean the APK is safe."
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("--only", nargs="*")
    b.add_argument("--write", action="store_true")
    o = sub.add_parser("openlink")
    o.add_argument("--write", action="store_true")
    args = ap.parse_args()
    with __import__("contextlib").suppress(ImportError):
        from loguru import logger

        logger.disable("androguard")
    return {"baseline": cmd_baseline, "openlink": cmd_openlink}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
