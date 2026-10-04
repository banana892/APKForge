#!/usr/bin/env python3
"""Phase H.6 validation: controlled call-site replacement (H-TRANS-003).

Subcommands (real toolchain; ``source tools/env.sh`` first):

    synthetic  Publish the H.6 synthetic corpus. For the four positive call-site shapes
               (static, wide/primitive arguments with a primitive result, private-instance
               invoke-direct, the second of two identical calls) run the control experiment
               (A original, B unmodified control rebuild, C H.6 transformed rebuild): expect
               H.6 VERIFIED and H.4 VERIFIED/COMPLETE. Confirm every negative request is
               refused by H.2 (and by the executor), that an already transformed APK and a
               conflicting request set are refused, that every mutation fault is caught
               before build and every build-time fault is rejected by H.4, that the
               integrity checks hold, and that two runs of one plan are reproducible.
    corpus     For the 9 corpus APKs: H.1 analysis, H-TRANS-003 planning over sampled real
               call sites (expected: no ELIGIBLE -> no transformation; H.2 rules never
               relaxed), every input SHA-256 recorded and compared before and after.
    all        Both.

Usage:
    .venv-validation/bin/python build-tests/run_phase_h6_validation.py all [--write]

Work files go to work/phase-h6/<run-id>/. ``--write`` publishes h6-*.json / .md under
artifacts/phase-h/ (H.1-H.5 artifacts there are not touched). Corpus APKs are never
modified. Exit 0: every check as expected; 1: a deviation; 2: toolchain unavailable.
"""

# ruff: noqa: E501 - verbatim smali call-site targets (long type descriptors) cannot be wrapped

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import resource
import shutil
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.h6_apks import (  # noqa: E402
    ARGS_REPLACEMENT,
    ARGS_TARGET,
    CALLER_SMALI,
    FAULTS,
    INSTANCE_REPLACEMENT,
    INSTANCE_TARGET,
    PKG,
    REPEATED_TARGET,
    REPLACEMENT,
    STATIC_TARGET,
    build_corpus,
    inject_at_build,
    publisher_key,
)

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore  # noqa: E402
from apkforge.modification.pipeline import measure_noise_floor  # noqa: E402
from apkforge.reference import ReferenceAnalysisService  # noqa: E402
from apkforge.reference.models import ReferenceKind  # noqa: E402
from apkforge.transformation import (  # noqa: E402
    ApplicationStatus,
    ControlExperiment,
    EligibilityState,
    ReplaceCallSiteModifier,
    TransformationExecutor,
    TransformationPlanner,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationResult,
    TransformationVerificationStatus,
)
from apkforge.transformation.planner import decision_id_for  # noqa: E402

CORPUS = PROJECT_ROOT / "tests" / "corpus"
ARTIFACTS = PROJECT_ROOT / "artifacts" / "phase-h"
C3 = "H-TRANS-003"
AS = ApplicationStatus
S = TransformationVerificationStatus
ES = EligibilityState
G = "getValue()Ljava/lang/String;"
_P = PKG.replace(".", "/")
SRC_REF = f"L{_P}/Source;->{G}"
REP_REF = f"L{_P}/Replacement;->{G}"


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


def _req(target: str, replacement: str | None) -> TransformationRequest:
    params = {"replacement": replacement} if replacement else {}
    return TransformationRequest(transformation_id=C3, target=target, parameters=params)


def _vsum(v: TransformationVerificationResult) -> dict[str, Any]:
    cpa = v.call_site_post_analysis
    return {
        "status": v.status.value,
        "completeness": v.completeness.value,
        "counts": {
            "expected": len(v.expected_changes),
            "noise": len(v.noise_changes),
            "unexpected": len(v.unexpected_changes),
            "unknown": len(v.unknown_changes),
        },
        "expected": sorted(
            f"[{d.domain}] {d.observation.category} {d.observation.kind} {d.observation.identifier}"
            for d in v.expected_changes
        ),
        "unexpected": [
            f"[{d.domain}] {d.observation.category} {d.observation.kind} {d.observation.identifier}"
            for d in v.unexpected_changes
        ],
        "invariants_failed": [i.name for i in v.invariants if i.status.value == "failed"],
        "call_site_post_analysis": (
            None
            if cpa is None
            else {
                "changed_positions": cpa.changed_positions,
                "replacement_at_planned_position": cpa.replacement_at_planned_position,
                "original_calls": f"{cpa.original_calls_before} -> {cpa.original_calls_after}",
                "replacement_calls": f"{cpa.replacement_calls_before} -> "
                f"{cpa.replacement_calls_after}",
                "other_changes": len(cpa.other_reference_changes)
                + len(cpa.caller_reference_changes)
                + len(cpa.declaration_changes),
            }
        ),
    }


_POSITIVE = [
    ("static", STATIC_TARGET, REPLACEMENT),
    ("args_and_result", ARGS_TARGET, ARGS_REPLACEMENT),
    ("private_instance", INSTANCE_TARGET, INSTANCE_REPLACEMENT),
    ("repeated_second_call", REPEATED_TARGET, REPLACEMENT),
]

_NEGATIVE = [
    ("target missing", "h6_callsite", f"{PKG}.A->run()Ljava/lang/String;@{PKG}.Source->missing()V",
     REPLACEMENT, ES.REFUSED, "CALL_SITE_NOT_FOUND"),
    ("caller missing", "h6_callsite", f"{PKG}.A->nope()V@{PKG}.Source->{G}", REPLACEMENT,
     ES.REFUSED, "TARGET_NOT_FOUND"),
    ("target ambiguous", "h6_callsite", f"{PKG}.A->over@{PKG}.Source->{G}", REPLACEMENT,
     ES.REFUSED, "CALL_SITE_AMBIGUOUS"),
    ("multiple matching call sites", "h6_callsite",
     f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT, ES.REFUSED,
     "CALL_SITE_MULTIPLE_MATCHES"),
    ("signature mismatch", "h6_callsite", STATIC_TARGET,
     f"{PKG}.Replacement->getValueInstance()Ljava/lang/String;", ES.REFUSED,
     "REPLACEMENT_SIGNATURE_MISMATCH"),
    ("argument mismatch", "h6_callsite", STATIC_TARGET,
     f"{PKG}.Replacement->getValueArg(I)Ljava/lang/String;", ES.REFUSED, "REGISTER_TYPE_MISMATCH"),
    ("return-type mismatch", "h6_callsite", STATIC_TARGET, f"{PKG}.Replacement->getValueInt()I",
     ES.REFUSED, "RESULT_TYPE_MISMATCH"),
    ("inaccessible replacement", "h6_callsite", STATIC_TARGET,
     f"{PKG}.Replacement->hidden()Ljava/lang/String;", ES.REFUSED, "REPLACEMENT_INACCESSIBLE"),
    ("replacement missing", "h6_callsite", STATIC_TARGET,
     f"{PKG}.Replacement->nothere()Ljava/lang/String;", ES.REFUSED,
     "REPLACEMENT_METHOD_NOT_FOUND"),
    ("replacement parameter missing", "h6_callsite", STATIC_TARGET, None, ES.REFUSED,
     "PARAMETER_INVALID"),
    ("constructor call", "h6_callsite", f"{PKG}.A->make()Ljava/lang/Object;@{PKG}.Source-><init>()V",
     REPLACEMENT, ES.UNSUPPORTED, "CONSTRUCTOR_INVOCATION"),
    ("polymorphic (virtual) call", "h6_callsite",
     f"{PKG}.A->virt(L{_P}/Source;)Ljava/lang/String;@{PKG}.Source->instanceValue()Ljava/lang/String;",
     f"{PKG}.Replacement->getValueInstance()Ljava/lang/String;", ES.UNSUPPORTED,
     "POLYMORPHIC_INVOCATION"),
    ("invoke-polymorphic", "h6_dynamic",
     f"{PKG}.A->poly(Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;@java.lang.invoke.MethodHandle->invoke",
     REPLACEMENT, ES.UNSUPPORTED, "INVOKE_POLYMORPHIC_UNSUPPORTED"),
    ("invoke-custom", "h6_dynamic", f"{PKG}.D->custom()Ljava/lang/Runnable;@{PKG}.Source->bsm",
     REPLACEMENT, ES.UNSUPPORTED, "INVOKE_CUSTOM_UNSUPPORTED"),
    ("incomplete reference analysis", "h6_dynamic", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED,
     "DEX_ANALYSIS_INCOMPLETE"),
    ("unsupported instruction in the caller", "h6_dynamic",
     f"{PKG}.D->mixed()Ljava/lang/String;@{PKG}.Source->{G}", REPLACEMENT, ES.UNDETERMINED,
     "CALLER_ANALYSIS_INCOMPLETE"),
    ("reflection dependency", "h6_reflection", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED,
     "REFLECTION_TARGET_UNKNOWN"),
    ("native dependency", "h6_native", STATIC_TARGET, REPLACEMENT, ES.UNDETERMINED,
     "NATIVE_DEPENDENCY_UNKNOWN"),
    ("native replacement", "h6_native", STATIC_TARGET,
     f"{PKG}.Replacement->nativeValue()Ljava/lang/String;", ES.UNSUPPORTED, "NATIVE_METHOD"),
    ("replacement is the invoked method", "h6_callsite", STATIC_TARGET, f"{PKG}.Source->{G}",
     ES.REFUSED, "CALL_SITE_ALREADY_REPLACED"),
]  # fmt: skip


def _nth(text: str, old: str, new: str, n: int) -> str:
    parts = text.split(old)
    return old.join(parts[:n]) + new + old.join(parts[n:])


def _mutation_fault(name: str) -> Any:  # noqa: ANN401 - patched _rewrite
    def rewrite(self: Any, text: str) -> str | None:  # noqa: ANN401
        k = text[: text.index("twice()")].count(SRC_REF) + 1
        good = _nth(text, SRC_REF, REP_REF, k + 1)
        if name == "wrong_call_site":
            return _nth(text, SRC_REF, REP_REF, k)
        if name == "two_call_sites":
            return _nth(good, SRC_REF, REP_REF, k)
        if name == "wrong_replacement":
            return _nth(text, SRC_REF, f"L{_P}/Replacement;->getValueInstance()Ljava/lang/String;",
                        k + 1)  # fmt: skip
        if name == "wrong_descriptor":
            return _nth(text, SRC_REF, f"L{_P}/Replacement;->getValue()Ljava/lang/Object;", k + 1)
        if name == "unrelated_method":
            return good.replace("move-result v0\n", "move-result v0\n    nop\n", 1)
        src = Path(self._root) / "smali/com/example/h1/Source.smali"  # unrelated_class
        src.write_text(src.read_text().replace('"h6-source"', '"h6-tampered"'))
        return good

    return rewrite


_MUTATION_FAULTS = [
    "wrong_call_site",
    "two_call_sites",
    "wrong_replacement",
    "wrong_descriptor",
    "unrelated_method",
    "unrelated_class",
]


def run_synthetic(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    assert svc.toolchain.keytool is not None
    pub = publisher_key(svc.toolchain.keytool, work / "publisher-key")
    apks = build_corpus(svc, work / "fixtures", pub)
    before = {n: _sha(p) for n, p in apks.items()}
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    planner = TransformationPlanningService(analyzer)
    exp = ControlExperiment(svc, reference_service=analyzer)
    executor = TransformationExecutor(svc, reference_service=analyzer)
    failures: list[str] = []
    out: dict[str, Any] = {"positive": {}, "negative": [], "faults": {}, "integrity": []}
    callsite = apks["h6_callsite"]

    def plan(target: str, replacement: str | None, apk: Path = callsite) -> Any:  # noqa: ANN401
        return planner.plan(apk, [_req(target, replacement)])

    # positive: full control experiment per shape
    published: Path | None = None
    for name, target, replacement in _POSITIVE:
        planning = plan(target, replacement)
        d = planning.decisions[0]
        res = exp.run(callsite, planning, work / "exp" / name)
        app = res.application
        v = res.verification
        m = app.mutation if app else None
        ok = (
            d.eligibility is ES.ELIGIBLE
            and app is not None
            and app.status is AS.VERIFIED
            and v.status is S.VERIFIED
            and v.completeness.value == "COMPLETE"
            and m is not None
            and m.count == 1
            and m.changed_lines == [m.source_line]
        )
        if not ok:
            failures.append(f"{name}: positive not VERIFIED ({v.status.value})")
        if name == "static" and res.transformed:
            published = Path(res.transformed)
        out["positive"][name] = {
            "target": target,
            "replacement": replacement,
            "eligibility": d.eligibility.value,
            "plan_id": d.plan.plan_id if d.plan else None,
            "h6_status": app.status.value if app else None,
            "mutation": None
            if m is None
            else {
                "line": m.source_line,
                "before": m.original_instruction,
                "after": m.replacement_instruction,
                "call_sites_changed": m.count,
                "changed_lines": m.changed_lines,
                "other_changes": len(m.other_changes),
            },
            "verification": _vsum(v),
        }
        print(f"[synthetic] {name}: H.6 {app.status.value if app else '-'} / "
              f"H.4 {v.status.value} ({v.completeness.value})")  # fmt: skip

    # negatives: H.2 must refuse, the executor must not apply
    for label, fixture, target, replacement, want, code in _NEGATIVE:
        planning = plan(target, replacement, apks[fixture])
        d = planning.decisions[0]
        codes = sorted({r.code.value for r in d.reasons})
        res = executor.run(apks[fixture], planning, apply=True,
                           output_apk=work / "neg.apk", work_dir=work / "neg")  # fmt: skip
        ok = (
            d.eligibility is want
            and code in codes
            and d.plan is None
            and res.status is AS.REFUSED
            and not (work / "neg.apk").exists()
        )
        if not ok:
            failures.append(f"negative {label}: {d.eligibility.value} {codes} / {res.status.value}")
        out["negative"].append(
            {
                "case": label,
                "apk": fixture,
                "target": target,
                "replacement": replacement,
                "expected": want.value,
                "expected_reason": code,
                "eligibility": d.eligibility.value,
                "reasons": codes,
                "plan": d.plan is not None,
                "executor": res.status.value,
            }
        )
    refused = sum(1 for n in out["negative"] if not n["plan"] and n["executor"] == "REFUSED")
    print(f"[synthetic] negatives: {refused}/{len(out['negative'])} refused")

    # already transformed (the static positive's verified output) + conflicting set
    if published is not None:
        d = plan(STATIC_TARGET, REPLACEMENT, published).decisions[0]
        codes = sorted({r.code.value for r in d.reasons})
        ok = d.eligibility is ES.REFUSED and codes == ["CALL_SITE_ALREADY_REPLACED"]
        if not ok:
            failures.append(f"already transformed: {d.eligibility.value} {codes}")
        out["already_transformed"] = {"eligibility": d.eligibility.value, "reasons": codes}
    else:
        failures.append("already transformed: no published static output")
    conflict = planner.plan(
        callsite,
        [
            _req(STATIC_TARGET, REPLACEMENT),
            TransformationRequest(transformation_id="H-TRANS-002", target=REPLACEMENT),
        ],
    )
    states = [d.eligibility.value for d in conflict.decisions]
    if states != ["REFUSED", "REFUSED"] or not conflict.conflicts:
        failures.append(f"conflicting set: {states}")
    out["conflicting_transformation"] = {
        "requests": [
            f"{d.transformation_id} {d.target.canonical if d.target else ''}"
            for d in conflict.decisions
        ],
        "eligibility": states,
        "conflicts": [c.kind for c in conflict.conflicts],
    }

    # mutation faults: caught before build
    rep_planning = plan(REPEATED_TARGET, REPLACEMENT)
    real_apply = ReplaceCallSiteModifier.apply
    real_rewrite = ReplaceCallSiteModifier._rewrite

    def apply(self: Any, p: Any, project: Any) -> Any:  # noqa: ANN401
        self._root = project.decoded_dir
        return real_apply(self, p, project)

    out["faults"]["mutation"] = []
    for fault in _MUTATION_FAULTS:
        ReplaceCallSiteModifier.apply = apply  # type: ignore[method-assign]
        ReplaceCallSiteModifier._rewrite = _mutation_fault(fault)  # type: ignore[method-assign]
        try:
            target_out = work / "fault-out.apk"
            res = executor.run(callsite, rep_planning, apply=True, output_apk=target_out,
                               work_dir=work / "mfault" / fault)  # fmt: skip
        finally:
            ReplaceCallSiteModifier.apply = real_apply  # type: ignore[method-assign]
            ReplaceCallSiteModifier._rewrite = real_rewrite  # type: ignore[method-assign]
        built = "build" in [s["stage"] for s in res.build.get("stages", [])]
        code = res.failure.code.value if res.failure else None
        ok = res.status is AS.FAILED and code == "UNEXPECTED_MUTATION" and not built
        ok = ok and not target_out.exists()
        if not ok:
            failures.append(f"mutation fault {fault}: {res.status.value} {code} built={built}")
        out["faults"]["mutation"].append(
            {
                "fault": fault,
                "status": res.status.value,
                "failure": code,
                "built": built,
                "call_sites_changed": res.mutation.count if res.mutation else None,
                "published": target_out.exists(),
            }
        )
        print(f"[synthetic] mutation fault {fault}: {res.status.value} {code}")

    # build-time faults: rejected by H.4, never published
    out["faults"]["build"] = []
    static_planning = plan(STATIC_TARGET, REPLACEMENT)
    for fault in sorted(FAULTS):
        edit, domain = FAULTS[fault]
        with inject_at_build(svc, edit):
            res = exp.run(callsite, static_planning, work / "bfault" / fault,
                          verify_unpublished=True)  # fmt: skip
        v = res.verification
        app = res.application
        domains = sorted({d.domain.value for d in v.unexpected_changes})
        ok = (
            app is not None
            and app.status is AS.FAILED
            and app.output_apk is None
            and v.status is S.FAILED
            and domain in domains
        )
        if not ok:
            failures.append(f"build fault {fault}: H.4 {v.status.value}; domains {domains}")
        out["faults"]["build"].append(
            {
                "fault": fault,
                "domain": domain,
                "h6_status": app.status.value if app else None,
                "h6_failure": app.failure.code.value if app and app.failure else None,
                "h4_status": v.status.value,
                "unexpected_domains": domains,
            }
        )
        print(f"[synthetic] build fault {fault}: H.6 {app.status.value if app else '-'} / "
              f"H.4 {v.status.value}")  # fmt: skip

    # integrity
    good = static_planning.decisions[0].plan
    assert good is not None
    cases: list[tuple[str, Any, Path, str]] = []
    cases.append(("source SHA mismatch", static_planning, apks["h6_callsite_alt"],
                  "SOURCE_SHA_MISMATCH"))  # fmt: skip
    forged = json.loads(good.model_dump_json())
    forged["plan_id"] = "plan-00000000000000000000"
    cases.append(("invalid plan id", forged, callsite, "PLAN_ID_MISMATCH"))
    tampered = json.loads(good.model_dump_json())
    tampered["planned_changes"][0]["details"]["replacement"] = (
        f"L{_P}/Replacement;->getValueInstance()Ljava/lang/String;"
    )
    cases.append(("forged plan (edited replacement)", tampered, callsite, "PLAN_MISMATCH"))
    rebound = json.loads(good.model_dump_json())
    sha = _sha(apks["h6_reflection"])
    rebound["apk"]["sha256"] = sha
    rebound["plan_id"] = "plan-" + decision_id_for(
        sha, C3, STATIC_TARGET, good.parameters, good.analysis_schema
    )
    cases.append(("forged plan (rebound, id recomputed)", rebound, apks["h6_reflection"],
                  "PLAN_NOT_ELIGIBLE"))  # fmt: skip
    for label, p, apk, code in cases:
        path = work / "integrity.json"
        path.write_text(json.dumps(p) if isinstance(p, dict) else p.to_json())
        res = executor.run(apk, path, apply=True, output_apk=work / "int.apk",
                           work_dir=work / "int")  # fmt: skip
        got = res.failure.code.value if res.failure else None
        ok = res.status is AS.REFUSED and got == code and not (work / "int.apk").exists()
        if not ok:
            failures.append(f"integrity {label}: {res.status.value} {got}")
        out["integrity"].append({"case": label, "expected": code, "status": res.status.value,
                                 "failure": got})  # fmt: skip

    class _Drift(BuildService):
        def decode(self, input_apk: Any, workspace: Any, *, timeout: Any = None) -> Any:  # noqa: ANN401
            stage = super().decode(input_apk, workspace, timeout=timeout)
            path = workspace.decoded_dir / CALLER_SMALI
            text = path.read_text()
            i = text.index("run()")
            path.write_text(text[:i] + text[i:].replace(SRC_REF, REP_REF, 1))
            return stage

    drift = TransformationExecutor(
        _Drift(svc.toolchain, svc.signing, work_dir=work / "drift-ws"), reference_service=analyzer
    )
    # the noise floor is measured with the real service (the drifting one would spoil it)
    noise = measure_noise_floor(svc, callsite, work_dir=work / "drift-noise")
    res = drift.run(callsite, static_planning, apply=True, output_apk=work / "drift.apk",
                    noop_baseline=noise,
                    work_dir=work / "drift")  # fmt: skip
    got = res.failure.code.value if res.failure else None
    if res.status is not AS.REFUSED or got != "TARGET_NOT_FOUND" or res.mutation is not None:
        failures.append(f"target disappearing after planning: {res.status.value} {got}")
    out["integrity"].append({"case": "target disappearing after planning",
                             "expected": "TARGET_NOT_FOUND", "status": res.status.value,
                             "failure": got})  # fmt: skip
    print(f"[synthetic] integrity: {sum(1 for x in out['integrity'] if x['status'] == 'REFUSED')}"
          f"/{len(out['integrity'])} refused")  # fmt: skip

    # reproducibility: plan twice, apply twice
    p1, p2 = plan(REPEATED_TARGET, REPLACEMENT), plan(REPEATED_TARGET, REPLACEMENT)
    runs = []
    for i in (1, 2):
        r = executor.run(callsite, p1, apply=True, output_apk=work / f"repro-{i}.apk",
                         noop_baseline=noise, work_dir=work / f"repro-{i}")  # fmt: skip
        runs.append(r)
    repro = {
        "plan_json_identical": p1.to_json() == p2.to_json(),
        "plan_id": p1.decisions[0].plan.plan_id if p1.decisions[0].plan else None,
        "eligibility_identical": p1.decisions[0].eligibility == p2.decisions[0].eligibility,
        "status": [r.status.value for r in runs],
        "mutation_record_identical": runs[0].mutation == runs[1].mutation,
        "post_analysis_identical": runs[0].call_site_analysis == runs[1].call_site_analysis,
        "result_comparable_identical": runs[0].comparable() == runs[1].comparable(),
        "entry_contents_identical": runs[0].output_content_sha256 == runs[1].output_content_sha256,
        "outer_apk_bytes_identical": runs[0].output_apk_sha256 == runs[1].output_apk_sha256,
    }
    required = [k for k, v in repro.items() if k not in ("plan_id", "status",
                                                         "outer_apk_bytes_identical")]  # fmt: skip
    if repro["status"] != ["VERIFIED", "VERIFIED"] or not all(repro[k] for k in required):
        failures.append(f"reproducibility: {repro}")
    out["reproducibility"] = repro
    print(f"[synthetic] reproducibility: {repro}")

    after = {n: _sha(p) for n, p in apks.items()}
    if before != after:
        failures.append("a synthetic input APK changed")
    out["inputs"] = {n: {"sha256": before[n], "unchanged": before[n] == after[n]} for n in apks}
    out["inputs_unchanged"] = before == after
    out["status"] = "PASS" if not failures else "FAIL"
    out["failures"] = failures
    return out


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------

_QUOTA = {
    "invoke-static": 8,
    "invoke-direct": 3,
    "constructor": 2,
    "invoke-virtual": 4,
    "invoke-interface": 2,
    "invoke-super": 1,
}


def _family(e: Any) -> str:  # noqa: ANN401 - Evidence
    if e.kind is ReferenceKind.CONSTRUCTOR_REFERENCE:
        return "constructor"
    return (e.instruction or "").split("/", 1)[0]


def _select_call_sites(result: Any) -> list[dict[str, str]]:  # noqa: ANN401
    """Deterministic spread of real invocations per opcode family, each with a replacement:
    another method of the invoked (else the caller's) class with the same descriptor and
    static-ness when one is declared, else a placeholder that does not exist (the request is
    then refused). Nothing is chosen to be eligible."""
    by_family: dict[str, list[Any]] = {k: [] for k in _QUOTA}
    for e in result.references:
        if e.kind not in (ReferenceKind.METHOD_REFERENCE, ReferenceKind.CONSTRUCTOR_REFERENCE):
            continue
        fam = _family(e)
        if fam in by_family and e.target_class and e.source_class and e.source_method:
            by_family[fam].append(e)
    classes = {c.name: c for c in result.defined_classes}
    index = result.index()
    out = []
    for fam, quota in _QUOTA.items():
        evs = by_family[fam]
        step = max(1, len(evs) // quota) if evs else 1
        for e in evs[::step][:quota]:
            calls = [
                x
                for x in index.invocations_in(e.source_class, e.source_method)
                if x.target == e.target
            ]
            nth = f"#{calls.index(e) + 1}" if len(calls) > 1 and e in calls else ""
            target = (
                f"{e.source_class}->{e.source_method}@{e.target_class}->"
                f"{e.member_name}{e.descriptor}{nth}"
            )
            static = fam == "invoke-static"
            replacement, kind = None, "placeholder"
            for owner in (e.target_class, e.source_class):
                dc = classes.get(owner)
                if dc is None:
                    continue
                cand = next(
                    (
                        m
                        for m in dc.methods
                        if m.descriptor == e.descriptor
                        and m.name not in (e.member_name, "<init>", "<clinit>")
                        and ("static" in m.access_flags) == static
                    ),
                    None,
                )
                if cand is not None:
                    replacement, kind = f"{owner}->{cand.signature}", "same-descriptor method"
                    break
            if replacement is None:
                replacement = f"{e.target_class}->h6NoReplacement{e.descriptor}"
            out.append({"family": fam, "target": target, "replacement": replacement,
                        "replacement_kind": kind})  # fmt: skip
    return out


def run_corpus(work: Path) -> dict[str, Any]:
    svc = _service(work)
    if svc is None:
        raise SystemExit(2)
    analyzer = ReferenceAnalysisService(svc, work_dir=work / "analysis")
    names = sorted(p.name for p in CORPUS.glob("*.apk"))
    before_all = {n: _sha(CORPUS / n) for n in names}
    rows = []
    reasons_total: Counter[str] = Counter()
    for name in names:
        apk = CORPUS / name
        before = before_all[name]
        failures: list[str] = []
        t0 = time.monotonic()
        result = analyzer.analyze(apk)
        h1_seconds = round(time.monotonic() - t0, 1)
        targets = _select_call_sites(result)
        planner = TransformationPlanner(result)
        states = {s.value: 0 for s in EligibilityState}
        reasons: Counter[str] = Counter()
        decisions = []
        for t in targets:
            d = planner.plan([_req(t["target"], t["replacement"])]).decisions[0]
            states[d.eligibility.value] += 1
            codes = sorted({r.code.value for r in d.reasons})
            reasons.update(codes)
            decisions.append({**t, "eligibility": d.eligibility.value, "reasons": codes})
        component_states = {k: v.value for k, v in sorted(result.component_states.items())}
        del result, planner
        reasons_total.update(reasons)
        unchanged = _sha(apk) == before
        if not unchanged:
            failures.append("APK changed")
        applied = 0
        verification = "not applicable (no ELIGIBLE plan)"
        if states["ELIGIBLE"] or states["CONDITIONALLY_ELIGIBLE"]:
            failures.append(
                f"{states['ELIGIBLE']} ELIGIBLE / {states['CONDITIONALLY_ELIGIBLE']} "
                "CONDITIONALLY_ELIGIBLE call site(s): review before applying"
            )
            verification = "not run (unexpected eligibility; see failures)"
        rows.append(
            {
                "apk": name,
                "sha256": before,
                "sha256_after": _sha(apk),
                "original_unchanged": unchanged,
                "component_states": component_states,
                "targets": len(targets),
                "eligibility": states,
                "reasons": dict(sorted(reasons.items())),
                "applied": applied,
                "verification": verification,
                "decisions": decisions,
                "h1_seconds": h1_seconds,
                "result": "PASS" if not failures else "FAIL",
                "failures": failures,
            }
        )
        print(f"[corpus] {name}: targets={len(targets)} {states} {rows[-1]['result']}")
    after_all = {n: _sha(CORPUS / n) for n in names}
    totals = {s.value: sum(r["eligibility"][s.value] for r in rows) for s in EligibilityState}
    return {
        "apks": rows,
        "corpus_sha256_unchanged": before_all == after_all,
        "totals": {
            "targets": sum(r["targets"] for r in rows),
            **totals,
            "applied": sum(r["applied"] for r in rows),
            "reasons": dict(sorted(reasons_total.items())),
        },
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024),
        "status": "PASS"
        if all(r["result"] == "PASS" for r in rows) and before_all == after_all
        else "FAIL",
    }


def _markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Phase H.6 validation (H-TRANS-003 controlled call-site replacement)",
        "",
        f"- Run: `{summary['run_id']}`",
        f"- Overall: **{summary['status']}**",
        "",
    ]
    syn = summary.get("synthetic")
    if syn:
        lines += ["## Synthetic", "", f"- Status: **{syn['status']}**",
                  f"- Inputs unchanged: {syn['inputs_unchanged']}", ""]  # fmt: skip
        lines += ["| Shape | Target | H.6 | H.4 | Completeness | Changed line |",
                  "|---|---|---|---|---|---|"]  # fmt: skip
        for name, p in syn["positive"].items():
            v = p["verification"]
            m = p["mutation"] or {}
            lines.append(f"| {name} | `{p['target']}` | {p['h6_status']} | {v['status']} "
                         f"| {v['completeness']} | {m.get('changed_lines')} |")  # fmt: skip
        lines += ["", "| Negative | Expected | Decision | Reasons | Executor |",
                  "|---|---|---|---|---|"]  # fmt: skip
        for n in syn["negative"]:
            lines.append(f"| {n['case']} | {n['expected']} ({n['expected_reason']}) | "
                         f"{n['eligibility']} | {', '.join(n['reasons'])} | {n['executor']} |")  # fmt: skip
        at = syn.get("already_transformed", {})
        lines += ["", f"- Already transformed APK: {at.get('eligibility')} {at.get('reasons')}"]
        ct = syn.get("conflicting_transformation", {})
        lines += [f"- Conflicting request set: {ct.get('eligibility')} {ct.get('conflicts')}", ""]
        lines += [
            "| Mutation fault | Status | Failure | Built | Published |",
            "|---|---|---|---|---|",
        ]
        for f in syn["faults"]["mutation"]:
            lines.append(f"| {f['fault']} | {f['status']} | {f['failure']} | {f['built']} | "
                         f"{f['published']} |")  # fmt: skip
        lines += ["", "| Build fault | Domain | H.6 | H.4 |", "|---|---|---|---|"]
        for f in syn["faults"]["build"]:
            lines.append(f"| {f['fault']} | {f['domain']} | {f['h6_status']} | {f['h4_status']} |")
        lines += ["", "| Integrity case | Expected | Status | Failure |", "|---|---|---|---|"]
        for f in syn["integrity"]:
            lines.append(f"| {f['case']} | {f['expected']} | {f['status']} | {f['failure']} |")
        lines += ["", "Reproducibility:", ""]
        lines += [f"- {k}: {v}" for k, v in syn["reproducibility"].items()]
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
            f"- {t['targets']} call-site targets: {t['ELIGIBLE']} ELIGIBLE, "
            f"{t['CONDITIONALLY_ELIGIBLE']} CONDITIONALLY_ELIGIBLE, {t['REFUSED']} REFUSED, "
            f"{t['UNSUPPORTED']} UNSUPPORTED, {t['UNDETERMINED']} UNDETERMINED; "
            f"{t['applied']} applied"
        )
        lines += ["", "| APK | Targets | ELIGIBLE | COND. | REFUSED | UNSUPPORTED | UNDETERMINED "
                  "| Applied | Verification | Unchanged |", "|---|---|---|---|---|---|---|---|---|---|"]  # fmt: skip
        for r in corp["apks"]:
            e = r["eligibility"]
            lines.append(
                f"| {r['apk']} | {r['targets']} | {e['ELIGIBLE']} | "
                f"{e['CONDITIONALLY_ELIGIBLE']} | {e['REFUSED']} | {e['UNSUPPORTED']} | "
                f"{e['UNDETERMINED']} | {r['applied']} | {r['verification']} | "
                f"{r['original_unchanged']} |"
            )
        lines += ["", "Reason codes (decisions carrying each):", ""]
        lines += [f"- `{k}`: {v}" for k, v in t["reasons"].items()]
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
    work = PROJECT_ROOT / "work" / "phase-h6" / run_id
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
    print(f"[h6] {summary['status']} -> {work}")
    if args.write:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        for key in ("synthetic", "corpus"):
            if key in summary:
                (ARTIFACTS / f"h6-{key}-summary.json").write_text(
                    json.dumps({k: summary[k] for k in ("run_id", "toolchain", key)}, indent=2)
                    + "\n"
                )
        (ARTIFACTS / "h6-validation-summary.md").write_text(_markdown(summary))
    shutil.rmtree(work / "synthetic" / "ws", ignore_errors=True)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
