"""Phase H.4: hardened verification of an applied ``H-TRANS-001`` transformation.

::

    A original, B unmodified (control) rebuild, C transformed rebuild, H.2 plan
      -> plan integrity (H.3 load_plan, plan id, source SHA-256)     else UNVERIFIED
      -> declared changes re-derived from A + plan (the H.3 functions) else UNVERIFIED
      -> A -> B  DiffEngine + Phase E no-op classification = measured noise floor
                 (content fingerprint; unusable control                 -> UNVERIFIED)
      -> A -> C  Phase E classify() against that noise floor (expected / planned /
                 noise / unexpected / unknown)
      -> B -> C  Phase E verify_expectations(): the transformation signal must be
                 exactly the declared change (+ the planned DEX entry and the v1
                 signature files whose content is a function of it)
      -> cross-check of the three legs per difference -> NOISE /
         EXPECTED_TRANSFORMATION / UNEXPECTED_CHANGE / UNKNOWN
      -> apksigner (C, signer of B), DEX class inventories, H.1 re-analysis
      -> invariants, per-domain completeness, overall status (never stronger than the
         weakest mandatory domain)

No comparison, classification, plan check or expectation logic is re-implemented here:
DiffEngine and the Phase E classifiers compare, :mod:`apkforge.transformation.executor`
and :mod:`apkforge.transformation.modifier` provide the H.3 plan checks, consequence
prediction and post-analysis. H.4 adds the control leg, the cross-leg attribution, the
domain model and the status semantics. Nothing here writes an input APK.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.builders.semantic_baseline import (
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
    classify_noop_diff,
    current_toolchain_identity,
)
from apkforge.diff.archive import ArchiveInventory, EntryKind
from apkforge.diff.expectations import (
    _SIGNATURE_FILE,
    ExpectationVerdict,
    ExpectedChange,
    Observation,
    ObservationClass,
    observe,
    verify_expectations,
)
from apkforge.diff.models import ComparisonStatus
from apkforge.diff.normalization import (
    AcceptedDifference,
    ContentPolicy,
    NoiseFingerprint,
    archive_entries_for,
)
from apkforge.inspection.dex import DEXInspector
from apkforge.transformation.application import SUPPORTED_TRANSFORMATIONS
from apkforge.transformation.dexstate import take_census
from apkforge.transformation.executor import (
    PlanRefusal,
    assess_post_analysis,
    content_sha256,
    load_plan,
    plan_id_for,
    removal_consequences,
)
from apkforge.transformation.modifier import removal_expectations, strings_removed
from apkforge.transformation.verification import (
    DOMAIN_COMPARATORS,
    H4_LIMITATIONS,
    MANDATORY_DOMAINS,
    ClassifiedDifference,
    Completeness,
    ControlPresence,
    DifferenceClass,
    DomainReport,
    InvariantCheck,
    LegSummary,
    RebuildRecord,
    TransformationVerificationResult,
    TransformationVerificationStatus,
    VerificationDomain,
    weakest,
)
from apkforge.verification.checks import signature_check_with_service, structural_check
from apkforge.verification.models import CheckStatus
from apkforge.verification.pair import check_baseline, classify

if TYPE_CHECKING:
    from apkforge.builders.service import BuildService
    from apkforge.diff.engine import DiffEngine
    from apkforge.diff.expectations import ClassifiedObservation
    from apkforge.diff.models import DiffResult
    from apkforge.diff.normalization import ToolchainIdentity
    from apkforge.reference.service import ReferenceAnalysisService
    from apkforge.transformation.models import PlanningResult, TransformationPlan

__all__ = ["LEGS", "TransformationVerifier", "domain_of"]

AB, AC, BC = "original->control", "original->transformed", "control->transformed"
LEGS = (AB, AC, BC)

D = VerificationDomain
K = DifferenceClass
S = TransformationVerificationStatus
OC = ObservationClass
_ATTRIBUTABLE = (OC.EXPECTED_MODIFICATION, OC.PLANNED_ENTRY)
#: sentinel: use the toolchain identity of the verifier's BuildService
CURRENT_TOOLCHAIN: Any = object()

_DOMAIN_LIMITATIONS: dict[VerificationDomain, list[str]] = {
    D.DEX: [
        "DEX classes, methods (code hash), fields, string pool and framework API "
        "references are compared; behaviour is not executed."
    ],
    D.MANIFEST: [
        "Every manifest element and attribute is compared (decoded tree); "
        "<activity-alias> changes are reported by the manifest tree only."
    ],
    D.RESOURCES: [
        "res/ entries and resources.arsc are compared by content hash; binary XML and "
        "resource-table entries are not decoded."
    ],
    D.ASSETS: ["assets/ entries are compared by content hash; their content is not parsed."],
    D.NATIVE: [
        "Native libraries are compared by content hash and ELF metadata; native code is "
        "not analysed (a changed library is detected, not interpreted)."
    ],
    D.ARCHIVE: [
        "Archive entries are compared by path and content hash; ZIP metadata "
        "(timestamps, compression, extra fields) and entry order are packaging details, "
        "recorded but never treated as content."
    ],
    D.SIGNING: [
        "The output is re-signed by APKForge; its certificate must equal the control "
        "rebuild's and apksigner must verify it. v1 signature files between control and "
        "transformed rebuild are accepted by path only."
    ],
    D.ENDPOINTS: [
        "URLs, domains and IPs are extracted statically from DEX, native, manifest and "
        "network-config data; nothing is contacted."
    ],
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def domain_of(obs: Observation) -> VerificationDomain:
    """The verification domain a Phase E observation belongs to."""
    cat = obs.category
    if cat in ("dex_file", "dex_class", "dex_api_reference", "dex_string"):
        return D.DEX
    if cat in (
        "identity",
        "manifest_attribute",
        "uses_permission",
        "declared_permission",
        "component",
        "manifest_element",
    ):
        return D.MANIFEST
    if cat in ("network_url", "network_host"):
        return D.ENDPOINTS
    if cat in ("native_library", "native_abi"):
        return D.NATIVE
    if cat == "certificate":
        return D.SIGNING
    if cat == "file":
        fcat = obs.detail.get("file_category")
        if fcat == "dex":
            return D.DEX
        if fcat == "manifest":
            return D.MANIFEST
        if fcat in ("resource", "resource_table"):
            return D.RESOURCES
        if fcat == "asset":
            return D.ASSETS
        if fcat == "native_lib":
            return D.NATIVE
        if _SIGNATURE_FILE.match(obs.identifier):
            return D.SIGNING
    return D.ARCHIVE


def _key(o: Observation) -> tuple[str, str, str]:
    return (o.category, o.kind, o.identifier)


def _comparator_completeness(status: str, complete: bool) -> Completeness:
    if status == ComparisonStatus.UNDETERMINED:
        return Completeness.UNKNOWN
    if not complete or status in (ComparisonStatus.PARTIAL, ComparisonStatus.NOT_COMPARABLE):
        return Completeness.PARTIAL
    return Completeness.COMPLETE


def _entry_order_changed(a: Path, b: Path) -> bool | None:
    try:
        with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
            na, nb = za.namelist(), zb.namelist()
    except (OSError, zipfile.BadZipFile):
        return None
    common = set(na) & set(nb)
    return [n for n in na if n in common] != [n for n in nb if n in common]


def _classes(apk: Path) -> set[str] | None:
    try:
        insp, _ = DEXInspector().inspect(apk)
    except Exception:
        return None
    return {c.name for df in insp.dex_files if df.inventory for c in df.inventory.classes}


def _cert_fp(certs: list[dict[str, Any]]) -> list[str]:
    return sorted(str(c.get("sha256_fingerprint") or "") for c in certs)


class TransformationVerifier:
    """Verifies a transformed rebuild against its original and an unmodified control.

    Args:
        service: configured BuildService (apksigner, decode for the expectation
            derivation, H.1). ``None`` leaves signing and the H.1 re-analysis UNKNOWN.
        reference_service: H.1 analysis (default: one sharing *service*).
        diff_engine: DiffEngine for the three comparisons.
    """

    def __init__(
        self,
        service: BuildService | None,
        *,
        reference_service: ReferenceAnalysisService | None = None,
        diff_engine: DiffEngine | None = None,
    ) -> None:
        self.service = service
        self._reference = reference_service
        self._engine = diff_engine

    @property
    def engine(self) -> DiffEngine:
        if self._engine is None:
            from apkforge.diff.engine import DiffEngine

            self._engine = DiffEngine()
        return self._engine

    @property
    def reference(self) -> ReferenceAnalysisService | None:
        if self._reference is None and self.service is not None:
            from apkforge.reference.service import ReferenceAnalysisService

            self._reference = ReferenceAnalysisService(
                self.service, work_dir=self.service.work_dir / "h4-references"
            )
        return self._reference

    # -- public -------------------------------------------------------------------

    def verify(
        self,
        original: Path | str,
        control: Path | str | None,
        transformed: Path | str | None,
        plan: Path | str | TransformationPlan | PlanningResult,
        *,
        toolchain: ToolchainIdentity | None = CURRENT_TOOLCHAIN,
        expected: list[ExpectedChange] | None = None,
        work_dir: Path | None = None,
    ) -> TransformationVerificationResult:
        """H.4 verification of *transformed* (C) against *original* (A) for *plan*, with
        *control* (B) as the measured noise floor.

        *toolchain* is the toolchain that built B and C (default: this machine's, i.e.
        both were built locally; ``None``: unknown, so a content mismatch on a noise
        path is UNKNOWN). *expected* overrides the declared changes (default: derived
        from A and the plan with the H.3 functions).
        """
        return self._verify(original, control, transformed, plan, toolchain, expected, work_dir)

    def verify_noop(
        self,
        original: Path | str,
        control: Path | str | None,
        candidate: Path | str | None,
        *,
        toolchain: ToolchainIdentity | None = CURRENT_TOOLCHAIN,
    ) -> TransformationVerificationResult:
        """Control experiment without a plan: *candidate* (e.g. a second unmodified
        rebuild) may differ from *original* only by the noise *control* measured."""
        return self._verify(original, control, candidate, None, toolchain, [], None)

    # -- body ---------------------------------------------------------------------

    def _verify(
        self,
        original: Path | str,
        control: Path | str | None,
        transformed: Path | str | None,
        plan_source: Path | str | TransformationPlan | PlanningResult | None,
        toolchain: ToolchainIdentity | None,
        expected: list[ExpectedChange] | None,
        work_dir: Path | None,
    ) -> TransformationVerificationResult:
        t_start = time.monotonic()
        a = Path(original).expanduser().resolve()
        sha_a = _sha256(a)
        result = TransformationVerificationResult(
            mode="transformation" if plan_source is not None else "noop",
            source_apk=str(a),
            source_apk_sha256=sha_a,
            control_rebuild=RebuildRecord(role="control"),
            transformed_rebuild=RebuildRecord(role="transformed"),
        )
        if toolchain is CURRENT_TOOLCHAIN:
            toolchain = current_toolchain_identity(self.service) if self.service else None
        result.toolchain = toolchain
        ctx = _Context(result=result, a=a, sha_a=sha_a)
        try:
            self._run(ctx, control, transformed, plan_source, expected, work_dir)
        finally:
            after = _sha256(a)
            result.source_apk_sha256_after = after
            result.original_unchanged = after == sha_a
            _finalize(ctx)
            result.timings["total"] = round(time.monotonic() - t_start, 3)
        return result

    def _run(
        self,
        ctx: _Context,
        control: Path | str | None,
        transformed: Path | str | None,
        plan_source: Path | str | TransformationPlan | PlanningResult | None,
        expected: list[ExpectedChange] | None,
        work_dir: Path | None,
    ) -> None:
        r = ctx.result
        # 1. plan
        if plan_source is not None:
            plan = self._plan(ctx, plan_source)
            if plan is None:
                return
            ctx.plan = plan
        # 2. inputs
        ctx.b = self._rebuild(r.control_rebuild, control)
        ctx.c = self._rebuild(r.transformed_rebuild, transformed)
        if ctx.a in (ctx.b, ctx.c):
            ctx.unverified.append("the original APK cannot be its own control/transformed rebuild")
            return
        # 3. declared changes
        if ctx.plan is not None:
            if expected is None:
                t = time.monotonic()
                expected = self._derive_expected(ctx, work_dir)
                r.timings["expectations"] = round(time.monotonic() - t, 3)
                if expected is None:
                    return
            change = ctx.plan.planned_changes[0]
            ctx.planned, unmapped = archive_entries_for([change.artifact or ""])
            if unmapped:
                ctx.unverified.append(f"planned file {unmapped} maps to no archive entry")
                return
        ctx.expected = list(expected or [])
        r.declared_changes = list(ctx.expected)
        # 4. control leg: the measured noise floor
        if ctx.b is None:
            ctx.unverified.append("no control rebuild: the noise floor cannot be measured")
            return
        self._control_leg(ctx)
        if ctx.baseline is None or ctx.check is None or not ctx.check.usable:
            return
        if ctx.c is None:
            ctx.unverified.append("no transformed rebuild to verify")
            return
        # 5. transformation legs + signature
        self._transformed_legs(ctx)
        t = time.monotonic()
        r.signature = signature_check_with_service(self.service, ctx.c, ctx.signer_b)
        r.transformed_rebuild.signature = str(r.signature.status)
        r.timings["signature"] = round(time.monotonic() - t, 3)
        # 6. attribution of every difference
        _attribute(ctx)
        # 7. DEX state and H.1 re-analysis (transformation mode)
        if ctx.plan is not None:
            self._dex_state(ctx)

    # -- steps --------------------------------------------------------------------

    def _plan(
        self, ctx: _Context, source: Path | str | TransformationPlan | PlanningResult
    ) -> TransformationPlan | None:
        r = ctx.result
        try:
            plan = load_plan(source)
        except PlanRefusal as exc:
            ctx.unverified.append(f"plan {exc.failure.code.value}: {exc.failure.message}")
            return None
        r.transformation_id = plan.transformation_id
        r.plan_id = plan.plan_id
        r.target = {"class": plan.target.class_name}
        if plan.planned_changes:
            ch = plan.planned_changes[0]
            r.target.update(file=ch.artifact or "", dex=ch.details.get("dex", ""))
        recomputed = plan_id_for(plan)
        problems = []
        if plan.apk.sha256 != ctx.sha_a:
            problems.append(f"the plan is for SHA-256 {plan.apk.sha256}, not this original")
        if recomputed != plan.plan_id:
            problems.append(f"plan id {plan.plan_id} != recomputed {recomputed}")
        if plan.transformation_id not in SUPPORTED_TRANSFORMATIONS:
            problems.append(
                f"{plan.transformation_id} is planning-only; H.4 verifies "
                f"{', '.join(SUPPORTED_TRANSFORMATIONS)} only"
            )
        ctx.invariant(
            "plan_integrity",
            None,
            "plan for this original, id recomputes, supported transformation",
            "; ".join(problems) or f"{plan.plan_id} ({plan.transformation_id})",
            CheckStatus.FAILED if problems else CheckStatus.PASSED,
        )
        if problems:
            ctx.unverified.extend(problems)
            return None
        return plan

    @staticmethod
    def _rebuild(rec: RebuildRecord, path: Path | str | None) -> Path | None:
        if path is None:
            rec.reasons.append("not given")
            return None
        p = Path(path).expanduser().resolve()
        rec.path = str(p)
        if not p.is_file():
            rec.reasons.append("file not found")
            return None
        rec.sha256 = _sha256(p)
        sc = structural_check(p)
        rec.structural = str(sc.status)
        if sc.status != CheckStatus.PASSED:
            rec.reasons.append(f"structurally invalid: {sc.summary}")
            return None
        rec.content_sha256 = content_sha256(p)
        rec.available = True
        return p

    def _derive_expected(self, ctx: _Context, work_dir: Path | None) -> list[ExpectedChange] | None:
        """The changes removing the target must produce, from A and the plan, with the
        same functions H.3 declares them with (decoded smali + DEX inventory)."""
        plan = ctx.plan
        assert plan is not None
        if self.service is None:
            ctx.unverified.append("no build toolchain: the declared changes cannot be derived")
            return None
        target = plan.target.class_name
        target_file = plan.planned_changes[0].artifact or ""
        try:
            api_removed, pool = removal_consequences(ctx.a, target)
        except PlanRefusal as exc:
            ctx.unverified.append(f"declared changes not derivable: {exc.failure.message}")
            return None
        base = Path(work_dir or self.service.work_dir)
        base.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="h4-expect-", dir=base))
        try:
            ws, prep = self.service.prepare_workspace(work_dir=tmp)
            if ws is None:
                ctx.unverified.append(f"workspace: {prep.failure_cause}")
                return None
            stage = self.service.decode(ctx.a, ws)
            if not stage.passed:
                ctx.unverified.append(f"decode of the original failed: {stage.failure_cause}")
                return None
            census = take_census(ws.decoded_dir)
            if census.classes.get(target) != [target_file] or census.unparsed:
                ctx.unverified.append(
                    f"{target} is not defined exactly once in {target_file} of the original "
                    f"(found {census.classes.get(target)}; unparsed {census.unparsed[:3]})"
                )
                return None
            strings = strings_removed(ws.decoded_dir, census, target_file, pool)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return removal_expectations(target, strings, api_removed)

    def _diff(self, ctx: _Context, leg: str, before: Path, after: Path) -> DiffResult:
        t = time.monotonic()
        diff = self.engine.diff(before, after)
        raw = diff.raw
        ctx.result.legs[leg] = LegSummary(
            leg=leg,
            before_sha256=diff.apk_a.sha256,
            after_sha256=diff.apk_b.sha256,
            diff_status=str(diff.status),
            observations=len(observe(diff)),
            raw_counts=dict(raw.counts) if raw else {},
            metadata_only_changes=raw.metadata_only_changes if raw else 0,
            entry_order_changed=_entry_order_changed(before, after),
            comparators={k: str(v.status) for k, v in sorted(diff.comparisons.items())},
            failures=[*diff.errors, *diff.limitations],
            seconds=round(time.monotonic() - t, 3),
        )
        ctx.diffs[leg] = diff
        return diff

    def _control_leg(self, ctx: _Context) -> None:
        r = ctx.result
        assert ctx.b is not None
        diff = self._diff(ctx, AB, ctx.a, ctx.b)
        noop, detail = classify_noop_diff(diff)
        sig_b = signature_check_with_service(self.service, ctx.b)
        r.control_rebuild.signature = str(sig_b.status)
        cert = (sig_b.details.get("certificate") or {}) if sig_b.details else {}
        ctx.signer_b = cert.get("sha256_digest") or None
        r.control_rebuild.signer_sha256 = ctx.signer_b
        entry = NoopSemanticEntry(
            id=ctx.a.name,
            filename=ctx.a.name,
            sha256=ctx.sha_a,
            package_name=diff.apk_a.package_name,
            build_success=True,
            input_unchanged=True,
            rebuilt_sha256=r.control_rebuild.sha256,
            signer_sha256=ctx.signer_b,
            result=noop,
            **detail,
        )
        ctx.baseline = NoopSemanticBaseline(
            name="H.4 control rebuild (measured noise floor)",
            toolchain={"versions": r.toolchain.model_dump() if r.toolchain else None},
            toolchain_identity=r.toolchain,
            entries=[entry],
        )
        ctx.check = check_baseline(ctx.baseline, ctx.sha_a, r.toolchain)
        r.control_rebuild.noop_result = str(noop)
        r.control_rebuild.baseline_status = str(ctx.check.status)
        r.legs[AB].phase_e_counts = {
            str(OC.REBUILD_NOISE): sum(entry.noise_rule_counts.values()) + len(entry.residue),
            str(OC.UNEXPECTED): len(entry.unexpected),
            str(OC.UNKNOWN): len(entry.unknown),
        }
        fp = entry.fingerprint or NoiseFingerprint()
        r.noise_floor = {
            "measured_by": "unmodified control rebuild of the original (A -> B)",
            "noop_result": str(noop),
            "baseline_status": str(ctx.check.status),
            "baseline_reasons": list(ctx.check.reasons),
            "accepted_rule_counts": fp.rule_counts(),
            "accepted": [f"{a.category} {a.kind} {a.identifier} [{a.rule}]" for a in fp.accepted],
            "unexpected_in_control": [
                f"{o.category} {o.kind} {o.identifier}" for o in entry.unexpected
            ],
            "unknown_in_control": [f"{o.category} {o.kind} {o.identifier}" for o in entry.unknown],
            "control_diff_failures": list(entry.diff_failures),
            "packaging_metadata_only_entries": r.legs[AB].metadata_only_changes,
        }
        ctx.ab_obs = {_key(o): o for o in observe(diff)}
        if sig_b.status != CheckStatus.PASSED:
            r.control_rebuild.reasons.append(f"control signature: {sig_b.summary}")
        ctx.invariant(
            "control_rebuild_equivalent",
            None,
            "the unmodified rebuild differs from the original only by classifiable noise "
            "(EQUIVALENT / EQUIVALENT_WITH_RESIDUE), usable as noise floor",
            f"{noop}; baseline {ctx.check.status}",
            CheckStatus.PASSED
            if ctx.check.usable
            and noop in (SemanticResult.EQUIVALENT, SemanticResult.EQUIVALENT_WITH_RESIDUE)
            else CheckStatus.UNDETERMINED
            if ctx.check.usable
            else CheckStatus.FAILED,
        )
        if not ctx.check.usable:
            ctx.unverified.append(
                f"the control rebuild does not establish a noise floor ({ctx.check.status}: "
                f"{'; '.join(ctx.check.reasons)})"
            )

    def _transformed_legs(self, ctx: _Context) -> None:
        assert ctx.b is not None and ctx.c is not None and ctx.check is not None
        diff_ac = self._diff(ctx, AC, ctx.a, ctx.c)
        ctx.ac = classify(
            diff_ac,
            ctx.expected,
            ctx.baseline,
            ctx.check,
            planned_entries=ctx.planned,
            expected_signer=ctx.signer_b,
            sha256=ctx.sha_a,
        )
        diff_bc = self._diff(ctx, BC, ctx.b, ctx.c)
        ctx.bc = verify_expectations(
            diff_bc,
            ctx.expected,
            fingerprint=_signal_fingerprint(diff_bc),
            planned_entries=ctx.planned,
        )
        for leg, verdict in ((AC, ctx.ac), (BC, ctx.bc)):
            ctx.result.legs[leg].phase_e_counts = verdict.counts

    def _dex_state(self, ctx: _Context) -> None:
        """Class inventories of A, B, C and the H.1 re-analysis of C."""
        r = ctx.result
        assert ctx.plan is not None and ctx.c is not None and ctx.b is not None
        target = ctx.plan.target.class_name
        t = time.monotonic()
        ctx.classes = {"original": _classes(ctx.a), "control": _classes(ctx.b),
                       "transformed": _classes(ctx.c)}  # fmt: skip
        ref = self.reference
        if ref is not None:
            try:
                pre = ref.analyze(ctx.a)
                post = ref.analyze(ctx.c)
                r.post_analysis = assess_post_analysis(pre, post, target)
            except Exception as exc:
                r.errors.append(f"H.1 re-analysis failed: {type(exc).__name__}: {exc}")
        r.timings["dex_state"] = round(time.monotonic() - t, 3)


# ---------------------------------------------------------------------------
# context, attribution, invariants, domains, status
# ---------------------------------------------------------------------------


class _Context:
    def __init__(self, *, result: TransformationVerificationResult, a: Path, sha_a: str) -> None:
        self.result = result
        self.a = a
        self.sha_a = sha_a
        self.b: Path | None = None
        self.c: Path | None = None
        self.plan: TransformationPlan | None = None
        self.expected: list[ExpectedChange] = []
        self.planned: set[str] = set()
        self.baseline: NoopSemanticBaseline | None = None
        self.check: Any = None
        self.signer_b: str | None = None
        self.diffs: dict[str, DiffResult] = {}
        self.ab_obs: dict[tuple[str, str, str], Observation] | None = None
        self.ac: ExpectationVerdict | None = None
        self.bc: ExpectationVerdict | None = None
        self.classes: dict[str, set[str] | None] = {}
        self.unverified: list[str] = []

    def invariant(
        self,
        name: str,
        domain: VerificationDomain | None,
        expected: str,
        actual: str,
        status: CheckStatus,
    ) -> None:
        self.result.invariants.append(
            InvariantCheck(
                name=name, domain=domain, expected=expected, actual=actual, status=status
            )
        )


def _signal_fingerprint(diff_bc: DiffResult) -> NoiseFingerprint:
    """B -> C: only the v1 signature files present in *both* rebuilds may differ without
    a declaration (their content is a function of every other entry); the Phase E
    ``signature_replaced`` rule with its path-only policy. Nothing else is accepted."""
    accepted = [
        AcceptedDifference(
            category=o.category,
            kind=o.kind,
            identifier=o.identifier,
            rule="signature_replaced",
            policy=ContentPolicy.PATH_ONLY,
        )
        for o in observe(diff_bc)
        if o.category == "file" and o.kind == "modified" and _SIGNATURE_FILE.match(o.identifier)
    ]
    return NoiseFingerprint(accepted=accepted)


def _presence(ctx: _Context, o: Observation) -> ControlPresence:
    if ctx.ab_obs is None:
        return ControlPresence.NOT_ANALYZED
    ctrl = ctx.ab_obs.get(_key(o))
    if ctrl is None:
        return ControlPresence.ABSENT
    same = (ctrl.content_before, ctrl.content_after, ctrl.detail) == (
        o.content_before,
        o.content_after,
        o.detail,
    )
    return ControlPresence.SAME_CONTENT if same else ControlPresence.DIFFERENT_CONTENT


def _attribute(ctx: _Context) -> None:
    """Classify every A -> C difference by cross-checking it with A -> B and B -> C;
    then every B -> C difference A -> C does not show."""
    r = ctx.result
    assert ctx.ac is not None and ctx.bc is not None
    signal = {_key(c.observation): c for c in ctx.bc.observations}
    seen: set[tuple[str, str, str]] = set()
    out: list[ClassifiedDifference] = []

    def add(
        c: ClassifiedObservation,
        leg: str,
        cls: DifferenceClass,
        reason: str,
        *,
        in_signal: bool | None,
        attributable: bool = False,
    ) -> None:
        o = c.observation
        out.append(
            ClassifiedDifference(
                domain=domain_of(o),
                leg=leg,
                observation=o,
                classification=cls,
                phase_e_class=str(c.classification),
                rule=c.rule,
                assurance=c.assurance,
                in_control=_presence(ctx, o),
                in_signal=in_signal,
                attributable=attributable,
                reason=reason,
            )
        )

    for c in ctx.ac.observations:
        o = c.observation
        key = _key(o)
        seen.add(key)
        s = signal.get(key)
        in_signal = s is not None
        presence = _presence(ctx, o)
        if c.classification in _ATTRIBUTABLE:
            if s is not None and s.classification in _ATTRIBUTABLE:
                add(c, AC, K.EXPECTED_TRANSFORMATION,
                    f"declared ({c.reason}); absent from the control rebuild "
                    f"({presence}) and present in the control -> transformed signal",
                    in_signal=True, attributable=True)  # fmt: skip
            else:
                add(c, AC, K.UNKNOWN,
                    "declared change observed against the original but not between the "
                    "control and the transformed rebuild: not attributable to the "
                    "transformation", in_signal=in_signal)  # fmt: skip
        elif c.classification == OC.REBUILD_NOISE:
            path_only = c.assurance == ContentPolicy.PATH_ONLY
            reproduced = presence is ControlPresence.SAME_CONTENT or (
                path_only and presence is ControlPresence.DIFFERENT_CONTENT
            )
            if not reproduced:
                add(c, AC, K.UNKNOWN,
                    f"accepted as noise ({c.rule}) but the control rebuild shows it as "
                    f"{presence}", in_signal=in_signal)  # fmt: skip
            elif in_signal and not path_only:
                add(c, AC, K.UNKNOWN,
                    f"identical to the control's noise ({c.rule}) against the original, yet "
                    "the control and transformed rebuilds differ here", in_signal=True)  # fmt: skip
            else:
                add(c, AC, K.NOISE,
                    f"{c.rule}: reproduced by the unmodified control rebuild "
                    f"({c.assurance}); {c.reason}", in_signal=in_signal)  # fmt: skip
        elif c.classification == OC.UNEXPECTED:
            add(c, AC, K.UNEXPECTED_CHANGE,
                f"{c.reason}; control rebuild: {presence}; not declared by the plan",
                in_signal=in_signal)  # fmt: skip
        else:
            add(c, AC, K.UNKNOWN, c.reason, in_signal=in_signal)

    noise_files = {
        (c.observation.category, c.observation.identifier)
        for c in ctx.ac.observations
        if c.classification == OC.REBUILD_NOISE
    }
    for c in ctx.bc.observations:
        o = c.observation
        if _key(o) in seen:
            continue
        if c.classification == OC.REBUILD_NOISE and (o.category, o.identifier) in noise_files:
            # a v1 signature file both rebuilds carry: regenerated because the signed
            # content differs; the same file is control-reproduced noise against A
            add(c, BC, K.NOISE,
                f"{c.rule}: v1 signature file regenerated by re-signing changed content "
                "(path only; correctness established by apksigner); against the original "
                "it is noise reproduced by the control rebuild", in_signal=True)  # fmt: skip
            continue
        add(c, BC, K.UNKNOWN,
            "the control and transformed rebuilds differ here although the transformed "
            "rebuild matches the original: the control's toolchain behaviour is not "
            f"reproduced (Phase E on this leg: {c.classification}, {c.reason})",
            in_signal=True)  # fmt: skip

    buckets = {
        K.EXPECTED_TRANSFORMATION: r.expected_changes,
        K.NOISE: r.noise_changes,
        K.UNEXPECTED_CHANGE: r.unexpected_changes,
        K.UNKNOWN: r.unknown_changes,
    }
    for d in out:
        buckets[d.classification].append(d)
    missing = [f"{AC}: {e.category} {e.kind} {e.identifier}" for e in ctx.ac.expected_missing]
    missing += [f"{BC}: {e.category} {e.kind} {e.identifier}" for e in ctx.bc.expected_missing]
    r.declared_missing = missing


def _invariants(ctx: _Context) -> None:
    r = ctx.result
    if ctx.ac is None or ctx.bc is None:
        return
    p, f, u = CheckStatus.PASSED, CheckStatus.FAILED, CheckStatus.UNDETERMINED
    dex_ok = all(
        ctx.diffs[leg].comparisons.get(name) is not None
        and ctx.diffs[leg].comparisons[name].complete
        for leg in (AC, BC)
        for name in ("dex", "strings")
    )
    if ctx.plan is not None:
        target = ctx.plan.target.class_name
        cls = ctx.classes
        before, control, after = cls.get("original"), cls.get("control"), cls.get("transformed")
        ctx.invariant(
            "target_defined_before", D.DEX, f"{target} defined in the original and the control",
            "unknown" if before is None or control is None else
            f"original {'yes' if target in before else 'no'}, control "
            f"{'yes' if target in control else 'no'}",
            u if before is None or control is None
            else p if target in before and target in control else f,
        )  # fmt: skip
        pa = r.post_analysis
        if after is None:
            st, actual = u, "DEX inventory of the transformed rebuild unavailable"
        else:
            in_h1 = None if pa is None else pa.target_defined
            actual = (
                f"DEX inventory: {'present' if target in after else 'absent'}; H.1: "
                f"{'not analysed' if in_h1 is None else 'present' if in_h1 else 'absent'}"
            )
            st = f if target in after or in_h1 else u if in_h1 is None else p
        ctx.invariant("target_absent_after", D.DEX, "absent", actual, st)
        for leg in (AC, BC):
            d = ctx.diffs[leg].dex
            removed = list(d.classes_removed)
            others = {
                "removed": [c for c in removed if c != target],
                "added": list(d.classes_added),
                "modified": [c.class_name for c in d.classes_modified],
                "dex_files": [*d.dex_files_added, *d.dex_files_removed],
            }
            ok = removed == [target]
            ctx.invariant(
                f"exactly_one_class_removed[{leg}]", D.DEX, f"[{target}]", str(removed),
                p if ok else f if dex_ok else u,
            )  # fmt: skip
            clean = not any(others.values())
            ctx.invariant(
                f"no_other_class_changed[{leg}]", D.DEX, "no other class removed/added/"
                "modified, no DEX file added/removed",
                "none" if clean else "; ".join(f"{k} {v}" for k, v in others.items() if v),
                p if clean else f,
            )  # fmt: skip
        if before is not None and after is not None:
            ctx.invariant(
                "class_count", D.DEX, f"{len(before)} - 1", str(len(after)),
                p if len(after) == len(before) - 1 else f,
            )  # fmt: skip
        if pa is None:
            ctx.invariant("h1_reference_state", D.DEX, "target absent, no reference, DEX "
                          "COMPLETE, no component weakened", "not analysed", u)  # fmt: skip
        else:
            refs = pa.definitive_references + pa.indirect_references
            problems = []
            if not pa.sufficient:
                problems.append(f"analysis {pa.analysis_state}, weakened {pa.weakened_components}")
            if refs:
                problems.append(f"{refs} reference(s) to {target}")
            if pa.other_classes_removed or pa.classes_added:
                problems.append(
                    f"classes removed {pa.other_classes_removed}, added {pa.classes_added}"
                )
            st = (
                f
                if refs or pa.other_classes_removed or pa.classes_added
                else (u if not pa.sufficient else p)
            )
            ctx.invariant("h1_reference_state", D.DEX, "target absent, no reference, DEX "
                          "COMPLETE, no component weakened", "; ".join(problems) or
                          f"{pa.absence_conclusion}; {pa.defined_classes_before} -> "
                          f"{pa.defined_classes_after} classes", st)  # fmt: skip
    missing = r.declared_missing
    ctx.invariant(
        "declared_changes_observed", D.DEX,
        f"all {len(ctx.expected)} declared change(s) on both transformation legs",
        "all observed" if not missing else f"missing: {missing[:5]}",
        p if not missing else f if dex_ok else u,
    )  # fmt: skip
    ctx.invariant(
        "no_unexpected_change", None, "0", str(len(r.unexpected_changes)),
        p if not r.unexpected_changes else f,
    )  # fmt: skip
    ctx.invariant(
        "no_unclassified_difference", None, "0", str(len(r.unknown_changes)),
        p if not r.unknown_changes else u,
    )  # fmt: skip
    sig = r.signature
    ctx.invariant(
        "signature_verified", D.SIGNING,
        "apksigner verifies the transformed rebuild with the control rebuild's signer",
        sig.summary if sig else "not run",
        u if sig is None or sig.status == CheckStatus.UNDETERMINED
        else p if sig.status == CheckStatus.PASSED else f,
    )  # fmt: skip


def _domains(ctx: _Context) -> None:
    r = ctx.result
    by_domain: dict[VerificationDomain, list[ClassifiedDifference]] = {d: [] for d in D}
    for item in r.differences():
        by_domain[item.domain].append(item)
    for dom in D:
        comps: dict[str, dict[str, str]] = {}
        levels: list[Completeness] = []
        reasons: list[str] = []
        limitations = list(_DOMAIN_LIMITATIONS[dom])
        for leg in LEGS:
            diff = ctx.diffs.get(leg)
            if diff is None:
                levels.append(Completeness.NOT_ANALYZED)
                continue
            comps[leg] = {}
            for name in DOMAIN_COMPARATORS[dom]:
                res = diff.comparisons.get(name)
                if res is None:
                    comps[leg][name] = "missing"
                    levels.append(Completeness.UNKNOWN)
                    reasons.append(f"{leg}: comparator {name} did not run")
                    continue
                comps[leg][name] = str(res.status)
                level = _comparator_completeness(str(res.status), res.complete)
                levels.append(level)
                if level is not Completeness.COMPLETE:
                    reasons.append(f"{leg}: {name} {res.status} ({res.reason})")
        if dom is D.DEX and ctx.plan is not None and ctx.ac is not None:
            pa = r.post_analysis
            if pa is None:
                levels.append(Completeness.UNKNOWN)
                reasons.append("H.1 re-analysis of the transformed rebuild not available")
            elif not pa.sufficient:
                levels.append(Completeness.UNKNOWN)
                reasons.append(
                    f"H.1 re-analysis insufficient ({pa.analysis_state}; weakened "
                    f"{pa.weakened_components}; errors {pa.errors[:3]})"
                )
        if dom is D.SIGNING and ctx.ac is not None:
            sig = r.signature
            if sig is None or sig.status in (CheckStatus.UNDETERMINED, CheckStatus.PARTIAL):
                levels.append(Completeness.UNKNOWN)
                reasons.append(f"signature: {sig.summary if sig else 'not run'}")
        completeness = weakest(levels)
        diffs = by_domain[dom]
        counts = Counter(str(d.classification) for d in diffs)
        inv = [i for i in r.invariants if i.domain is dom]
        failed = counts.get(K.UNEXPECTED_CHANGE, 0) or any(
            i.status == CheckStatus.FAILED for i in inv
        )
        open_ = counts.get(K.UNKNOWN, 0) or any(i.status == CheckStatus.UNDETERMINED for i in inv)
        if failed:
            status = CheckStatus.FAILED
        elif open_ or completeness in (Completeness.UNKNOWN, Completeness.NOT_ANALYZED):
            status = CheckStatus.UNDETERMINED
        elif completeness is Completeness.PARTIAL:
            status = CheckStatus.PARTIAL
        else:
            status = CheckStatus.PASSED
        for d in diffs:
            if d.classification in (K.UNEXPECTED_CHANGE, K.UNKNOWN):
                o = d.observation
                reasons.append(f"{d.classification}: {o.category} {o.kind} {o.identifier}")
        for i in inv:
            if i.status in (CheckStatus.FAILED, CheckStatus.UNDETERMINED):
                reasons.append(f"invariant {i.name} {i.status}: {i.actual}")
        for diff in ctx.diffs.values():
            for name in DOMAIN_COMPARATORS[dom]:
                res = diff.comparisons.get(name)
                for lim in res.limitations if res else []:
                    if lim not in limitations:
                        limitations.append(lim)
        r.domains[str(dom)] = DomainReport(
            domain=dom,
            mandatory=dom in MANDATORY_DOMAINS,
            completeness=completeness,
            status=status,
            comparators=comps,
            counts={str(k): counts.get(k, 0) for k in K},
            facts=_facts(ctx, dom),
            limitations=limitations,
            reasons=reasons,
        )


def _inventory(apk: Path | None) -> ArchiveInventory | None:
    if apk is None:
        return None
    try:
        return ArchiveInventory.from_apk(apk)
    except Exception:
        return None


def _changes(ctx: _Context, leg: str, pred: Any) -> list[str]:  # noqa: ANN401 - callable
    diff = ctx.diffs.get(leg)
    if diff is None:
        return []
    return [f"{o.kind} {o.identifier}" for o in observe(diff) if pred(o)]


def _facts(ctx: _Context, dom: VerificationDomain) -> dict[str, Any]:
    """Domain-specific evidence (what was compared, on each side)."""
    r = ctx.result
    ac, bc = ctx.diffs.get(AC), ctx.diffs.get(BC)
    in_dom = lambda o: domain_of(o) is dom  # noqa: E731
    facts: dict[str, Any] = {}
    if ac is not None:
        facts["original_to_transformed"] = _changes(ctx, AC, in_dom)
    if bc is not None:
        facts["control_to_transformed"] = _changes(ctx, BC, in_dom)
    if dom is D.DEX and ac is not None:
        cls = ctx.classes
        facts.update(
            classes={k: (len(v) if v is not None else None) for k, v in cls.items()},
            classes_removed=list(ac.dex.classes_removed),
            classes_added=list(ac.dex.classes_added),
            classes_modified=[c.class_name for c in ac.dex.classes_modified],
            dex_files_added=list(ac.dex.dex_files_added),
            dex_files_removed=list(ac.dex.dex_files_removed),
            strings_removed=ac.strings.total_removed,
            strings_added=ac.strings.total_added,
            api_references_removed=list(ac.dex.api_references_removed),
            api_references_added=list(ac.dex.api_references_added),
        )
        if r.post_analysis is not None:
            pa = r.post_analysis
            facts["h1"] = {
                "analysis_state": pa.analysis_state,
                "dex": pa.component_states.get("dex"),
                "target_defined": pa.target_defined,
                "absence_conclusion": pa.absence_conclusion,
                "references": pa.definitive_references + pa.indirect_references,
            }
    elif dom is D.MANIFEST and ac is not None:
        p = ac.permissions
        facts.update(
            permissions_added=list(p.added),
            permissions_removed=list(p.removed),
            components_changed=[
                f"{c.change_type} {c.name}"
                for c in [
                    *ac.components.activities,
                    *ac.components.services,
                    *ac.components.receivers,
                    *ac.components.providers,
                ]
                if str(c.change_type) != "unchanged"
            ],
            manifest_tree_changes=len(ac.manifest_tree.changes),
        )
    elif dom in (D.RESOURCES, D.ASSETS, D.NATIVE, D.SIGNING, D.ARCHIVE):
        invs = {
            "original": _inventory(ctx.a),
            "control": _inventory(ctx.b),
            "transformed": _inventory(ctx.c),
        }
        kinds = {
            D.RESOURCES: (EntryKind.RESOURCE, EntryKind.RESOURCE_TABLE),
            D.ASSETS: (EntryKind.ASSET,),
            D.NATIVE: (EntryKind.NATIVE_LIBRARY, EntryKind.LIB_OTHER),
            D.SIGNING: (EntryKind.SIGNATURE,),
        }.get(dom)
        if kinds is not None:
            facts["entries"] = {
                side: (
                    {p: e.sha256[:16] for p, e in sorted(inv.entries.items()) if e.kind in kinds}
                    if inv is not None
                    else None
                )
                for side, inv in invs.items()
            }
        if dom is D.NATIVE:
            facts["abis"] = {
                side: (inv.summary()["abis"] if inv is not None else None)
                for side, inv in invs.items()
            }
            facts["analysis"] = "content hash + ELF metadata; native code not analysed"
        if dom is D.SIGNING:
            fps: dict[str, list[str]] = {}
            if ac is not None:
                fps["original"] = _cert_fp(ac.certificates.certificates_before)
                fps["transformed"] = _cert_fp(ac.certificates.certificates_after)
            ab = ctx.diffs.get(AB)
            if ab is not None:
                fps["control"] = _cert_fp(ab.certificates.certificates_after)
            facts["certificates"] = fps
            if "control" in fps and "transformed" in fps:
                facts["resigned_by_apkforge"] = (
                    fps["control"] == fps["transformed"] != fps.get("original")
                )
                facts["certificate_change_explained"] = (
                    "the original -> transformed certificate change also occurs in the "
                    "unmodified control rebuild (APKForge re-signs every rebuild); control "
                    "and transformed rebuild share one certificate"
                    if facts["resigned_by_apkforge"]
                    else "the transformed rebuild's certificate differs from the control's"
                )
            facts["signature_check"] = r.signature.summary if r.signature else None
        if dom is D.ARCHIVE:
            facts["entries"] = {
                side: (inv.entry_count if inv is not None else None) for side, inv in invs.items()
            }
            facts["raw_counts"] = {leg: s.raw_counts for leg, s in r.legs.items()}
            facts["apk_bytes_identical"] = {
                "original_vs_control": r.control_rebuild.sha256 == ctx.sha_a,
                "control_vs_transformed": (
                    r.control_rebuild.sha256 is not None
                    and r.control_rebuild.sha256 == r.transformed_rebuild.sha256
                ),
            }
            facts["packaging"] = {
                leg: {
                    "metadata_only_changes": s.metadata_only_changes,
                    "entry_order_changed": s.entry_order_changed,
                }
                for leg, s in r.legs.items()
            }
    elif dom is D.ENDPOINTS and ac is not None:
        n = ac.network
        facts.update(
            urls_added=[u.url for u in n.urls_added],
            urls_removed=[u.url for u in n.urls_removed],
            hosts_added=[*n.domains_added, *n.ips_added],
            hosts_removed=[*n.domains_removed, *n.ips_removed],
        )
    return facts


def _finalize(ctx: _Context) -> None:
    """Invariants, domains, completeness and the overall status."""
    r = ctx.result
    if ctx.ac is not None:
        _invariants(ctx)
    ctx.invariant(
        "original_unchanged", None, "SHA-256 of the original identical before and after",
        str(r.source_apk_sha256_after), CheckStatus.PASSED if r.original_unchanged
        else CheckStatus.FAILED,
    )  # fmt: skip
    _domains(ctx)
    mandatory = [r.domains[str(d)] for d in MANDATORY_DOMAINS]
    r.completeness = weakest([d.completeness for d in mandatory])
    failed = [i.name for i in r.invariants if i.status == CheckStatus.FAILED]
    failed += [f"domain {d.domain}" for d in mandatory if d.status == CheckStatus.FAILED]
    open_ = [i.name for i in r.invariants if i.status == CheckStatus.UNDETERMINED]
    open_ += [
        f"domain {d.domain} ({d.completeness})"
        for d in mandatory
        if d.status == CheckStatus.UNDETERMINED
    ]
    partial = [d for d in mandatory if d.completeness is Completeness.PARTIAL]
    r.limitations = [
        f"[{d.domain}] {d.completeness}: {'; '.join(d.reasons) or 'see domain limitations'}"
        for d in partial
    ] + list(H4_LIMITATIONS)

    if r.original_unchanged is False or (failed and not ctx.unverified) or r.unexpected_changes:
        r.status = S.FAILED
        why = list(dict.fromkeys(failed)) or ["original changed"]
        if r.unexpected_changes:
            why.append(f"{len(r.unexpected_changes)} unexpected change(s)")
        r.status_reason = "failed: " + ", ".join(why)
    elif ctx.unverified:
        r.status = S.UNVERIFIED
        r.status_reason = "not verifiable: " + "; ".join(ctx.unverified)
        r.errors.extend(ctx.unverified)
    elif (
        open_
        or r.unknown_changes
        or r.completeness
        in (
            Completeness.UNKNOWN,
            Completeness.NOT_ANALYZED,
        )
    ):
        r.status = S.UNKNOWN
        why = list(dict.fromkeys(open_))
        if r.unknown_changes:
            why.append(f"{len(r.unknown_changes)} unclassified difference(s)")
        r.status_reason = "not established: " + (", ".join(why) or f"{r.completeness}")
    elif partial:
        r.status = S.VERIFIED_WITH_LIMITATIONS
        r.status_reason = (
            "every invariant passed and every difference is noise or the declared "
            "transformation, but these domains are only partially established: "
            + ", ".join(f"{d.domain}" for d in partial)
            + " (see limitations)"
        )
    else:
        r.status = S.VERIFIED
        r.status_reason = (
            "every mandatory domain COMPLETE, every invariant passed, every difference is "
            "the declared transformation or noise reproduced by the control rebuild"
            if r.mode == "transformation"
            else "the candidate differs from the original only by noise the control "
            "rebuild reproduces"
        )
