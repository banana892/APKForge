#!/usr/bin/env python3
"""Phase D validation: the generalized modification pipeline on the real OpenLink APK.

Scenarios (all through ModificationPipeline, real toolchain, real DiffEngine):

    A  c5.disable_boot_receiver                       expect VERIFIED, 2 expected changes
    B  test.marker_asset                              expect VERIFIED, 1 expected change
    C  c5.disable_boot_receiver + test.marker_asset   expect VERIFIED, 3 expected, one build
    D  test.marker_asset + test.failing + c5          expect FAILED, marker rolled back,
                                                      c5 not attempted, nothing built
    E  dry run of C                                   expect DRY_RUN, no APK, nothing built
    F  test.undeclared (undeclared asset)             expect FAILED, 1 unexpected change

Usage:
    source tools/env.sh
    .venv-validation/bin/python build-tests/run_phase_d_validation.py [--write]

Outputs go to work/phase-d/<run-id>/. ``--write`` also copies the JSON + Markdown result to
tests/corpus/results/phase-d-openlink-result.{json,md}. No existing baseline is written.
Exit code: 0 every scenario as expected, 1 a scenario deviated, 2 toolchain/corpus missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.integration.phase_d_modifiers import (  # noqa: E402
    FailingModifier,
    UndeclaredChangeModifier,
)

from apkforge.builders import (  # noqa: E402
    BuildService,
    CommandRunner,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.corpus import (  # noqa: E402
    _apkforge_revision,
    new_run_id,
    toolchain_versions,
)
from apkforge.builders.semantic_baseline import NoopSemanticBaseline  # noqa: E402
from apkforge.diff.expectations import ObservationClass  # noqa: E402
from apkforge.modification.builtin import (  # noqa: E402
    BootReceiverModifier,
    MarkerAssetModifier,
)
from apkforge.modification.catalog import ModifierCatalog  # noqa: E402
from apkforge.modification.pipeline import (  # noqa: E402
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
)

CORPUS_DIR = PROJECT_ROOT / "tests" / "corpus"
OPENLINK = CORPUS_DIR / "de.audioattack.openlink_28.apk"
NOOP_BASELINE = CORPUS_DIR / "results" / "c5-semantic-noop-baseline.json"
RESULTS_DIR = CORPUS_DIR / "results"
C5, MARKER = "c5.disable_boot_receiver", "test.marker_asset"

SCENARIOS: list[dict[str, Any]] = [
    {"id": "A", "modifiers": [C5], "expect": "verified", "expected_changes": 2},
    {"id": "B", "modifiers": [MARKER], "expect": "verified", "expected_changes": 1},
    {"id": "C", "modifiers": [C5, MARKER], "expect": "verified", "expected_changes": 3},
    {"id": "D", "modifiers": [MARKER, "test.failing", C5], "expect": "failed"},
    {"id": "E", "modifiers": [C5, MARKER], "expect": "dry_run", "dry_run": True},
    {"id": "F", "modifiers": ["test.undeclared"], "expect": "failed", "unexpected": 1},
]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _summary(res: PipelineResult) -> dict[str, Any]:
    v = res.verdict
    return {
        "status": str(res.status),
        "order": res.order,
        "counts": res.counts(),
        "steps": [
            {
                "modifier": r.info.id,
                "status": str(r.step.status),
                "verification": r.verification_state,
                "rolled_back": r.step.rolled_back,
                "message": r.step.message,
                "expected_observed": len(r.expected_observed),
                "expected_missing": len(r.expected_missing),
            }
            for r in res.modifiers
        ],
        "conflicts": [c.model_dump() for c in res.conflicts],
        "rollback": res.rollback,
        "stages": [f"{s.stage}={s.status}" for s in res.stages],
        "build_passed": res.build_passed,
        "apk_verified": res.apk_verified,
        "verdict_passed": v.passed if v else None,
        "classification": v.counts if v else None,
        "noise_rule_counts": v.noise_rule_counts if v else None,
        "expected_modifications": sorted(
            f"{c.observation.category} {c.observation.kind} {c.observation.identifier}"
            for c in v.of(ObservationClass.EXPECTED_MODIFICATION)
        )
        if v
        else [],
        "unexpected": [
            f"{c.observation.category} {c.observation.kind} {c.observation.identifier}"
            for c in v.of(ObservationClass.UNEXPECTED)
        ]
        if v
        else [],
        "original_sha256_before": res.original_sha256_before,
        "original_sha256_after": res.original_sha256_after,
        "original_preserved": res.original_preserved,
        "original_checkpoints": res.original_checkpoints,
        "output_sha256": res.output_sha256,
        "failures": res.failures,
        "warnings": res.warnings,
    }


def _check(sc: dict[str, Any], s: dict[str, Any]) -> list[str]:
    problems = []
    if s["status"] != sc["expect"]:
        problems.append(f"status {s['status']} != {sc['expect']}")
    if not s["original_preserved"]:
        problems.append("original changed")
    if "expected_changes" in sc and len(s["expected_modifications"]) != sc["expected_changes"]:
        problems.append(f"expected modifications {len(s['expected_modifications'])}")
    if sc["expect"] == "verified" and (s["classification"] or {}).get("unexpected", 1) != 0:
        problems.append("unexpected changes in a verified run")
    if "unexpected" in sc and len(s["unexpected"]) != sc["unexpected"]:
        problems.append(f"unexpected {len(s['unexpected'])} != {sc['unexpected']}")
    if sc["id"] == "D":
        st = s["steps"]
        if not (
            st[0]["rolled_back"] and st[1]["status"] == "failed" and st[2]["status"] == "pending"
        ):
            problems.append("D: rollback / not-attempted semantics not as expected")
        if any(x.split("=")[0] == "build" for x in s["stages"]):
            problems.append("D: something was built")
    if sc["id"] == "E" and s["stages"] != ["prepare=PASS", "decode=PASS"]:
        problems.append("E: dry run went past decode")
    return problems


def render(data: dict[str, Any]) -> str:
    lines = [
        f"# Phase D validation: {'PASS' if data['passed'] else 'FAIL'}",
        "",
        f"Generated {data['generated_at']}. APK `{OPENLINK.name}`, "
        f"original SHA-256 `{data['original_sha256']}`.",
        f"APKForge commit `{data['revision']['git_commit']}` "
        f"(dirty: {data['revision']['git_dirty']}).",
        f"Toolchain: {', '.join(f'{k} {v}' for k, v in data['toolchain_versions'].items())}.",
        "",
        "| scenario | modifiers | expected | status | executed / verified / not attempted "
        "/ rolled back | expected obs. | unexpected | stages | original |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for sc in data["scenarios"]:
        s, c = sc["result"], sc["result"]["counts"]
        lines.append(
            f"| {sc['id']} | {' → '.join(s['order'])} | {sc['expect']} | **{s['status']}** "
            f"| {c['executed']} / {c['verified']} / {c['not_attempted']} / {c['rolled_back']} "
            f"| {len(s['expected_modifications'])} | {len(s['unexpected'])} "
            f"| {', '.join(x.split('=')[0] for x in s['stages'])} "
            f"| {'unchanged' if s['original_preserved'] else 'CHANGED'} |"
        )
    lines += ["", "## Details", ""]
    for sc in data["scenarios"]:
        s = sc["result"]
        lines += [f"### {sc['id']}: {sc['expect']} -> {s['status']}", ""]
        for st in s["steps"]:
            lines.append(
                f"- `{st['modifier']}`: {st['status']}, {st['verification']}"
                + (", rolled back" if st["rolled_back"] else "")
                + f" — {st['message']}"
            )
        if s["expected_modifications"]:
            lines.append(f"- expected modifications: {s['expected_modifications']}")
        if s["classification"]:
            lines.append(f"- classification: {s['classification']}")
            lines.append(f"- noise per rule: {s['noise_rule_counts']}")
        if s["unexpected"]:
            lines.append(f"- unexpected: {s['unexpected']}")
        if s["rollback"]:
            lines.append(f"- rollback: {s['rollback']}")
        lines.append(f"- original checkpoints: {s['original_checkpoints']}")
        for f in s["failures"]:
            lines.append(f"- failure: {f}")
        if sc["problems"]:
            lines.append(f"- **deviation:** {sc['problems']}")
        lines.append("")
    lines += [
        "Modified APKs are not installed or run; VERIFIED does not mean the APK is safe.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="copy results to tests/corpus/results")
    args = ap.parse_args()

    from loguru import logger

    logger.disable("androguard")

    if not OPENLINK.is_file() or not NOOP_BASELINE.is_file():
        print("OpenLink corpus APK or C.5 no-op baseline missing", file=sys.stderr)
        return 2
    run_dir = PROJECT_ROOT / "work" / "phase-d" / new_run_id()
    run_dir.mkdir(parents=True)
    toolchain = ToolchainConfig.discover()
    if toolchain.keytool is None:
        print("keytool not found", file=sys.stderr)
        return 2
    service = BuildService(
        toolchain, ensure_dev_keystore(toolchain.keytool), work_dir=run_dir / "builds"
    )
    check = service.check_toolchain()
    if not check.valid:
        print(f"toolchain unavailable: {check.errors}", file=sys.stderr)
        return 2
    baseline = NoopSemanticBaseline.model_validate_json(NOOP_BASELINE.read_text())
    catalog = ModifierCatalog(
        [
            BootReceiverModifier(),
            MarkerAssetModifier(),
            FailingModifier(),
            UndeclaredChangeModifier(),
        ]
    )
    pipeline = ModificationPipeline(service, catalog)

    original = _sha(OPENLINK)
    scenarios = []
    for sc in SCENARIOS:
        res = pipeline.run(
            OPENLINK,
            [ModifierRequest(modifier_id=m) for m in sc["modifiers"]],
            noop_baseline=baseline,
            dry_run=sc.get("dry_run", False),
            work_dir=run_dir / "work",
            output_apk=run_dir / f"{sc['id']}.apk",
        )
        (run_dir / f"{sc['id']}.result.json").write_text(res.model_dump_json(indent=2))
        summary = _summary(res)
        problems = _check(sc, summary)
        print(f"{sc['id']}: {summary['status']} {problems or 'OK'}")
        scenarios.append({**sc, "result": summary, "problems": problems})

    data = {
        "name": "Phase D validation (generalized modification pipeline, OpenLink)",
        "generated_at": datetime.now(UTC).isoformat(),
        "original_sha256": original,
        "original_unchanged_after_all_runs": _sha(OPENLINK) == original,
        "revision": _apkforge_revision(CommandRunner(), PROJECT_ROOT),
        "toolchain_versions": toolchain_versions(check.to_dict()),
        "scenarios": scenarios,
    }
    data["passed"] = data["original_unchanged_after_all_runs"] and not any(
        s["problems"] for s in scenarios
    )
    out_json = run_dir / "phase-d-openlink-result.json"
    out_md = run_dir / "phase-d-openlink-result.md"
    out_json.write_text(json.dumps(data, indent=2, default=str) + "\n")
    out_md.write_text(render(data))
    print(f"results: {out_json}")
    if args.write:
        shutil.copyfile(out_json, RESULTS_DIR / out_json.name)
        shutil.copyfile(out_md, RESULTS_DIR / out_md.name)
        print(f"written to {RESULTS_DIR}")
    return 0 if data["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
