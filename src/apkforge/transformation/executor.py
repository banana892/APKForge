"""Phase H.3/H.5/H.6: apply one validated H.2 plan (H-TRANS-001, -002 or -003).

::

    plan JSON -> load (PLAN_NOT_FOUND / PLAN_INVALID / PLAN_NOT_ELIGIBLE)
      -> source SHA-256 == plan                          (SOURCE_SHA_MISMATCH)
      -> plan id recomputed with the H.2 rules           (PLAN_ID_MISMATCH)
      -> supported transformation, plan ELIGIBLE         (UNSUPPORTED_TRANSFORMATION /
                                                          PLAN_NOT_ELIGIBLE)
      -> H.1 + H.2 re-run on the source: same decision,  (PLAN_NOT_ELIGIBLE /
         identical plan                                   PLAN_MISMATCH)
      [dry run stops here: PLANNED]
      -> expected DEX consequences + noise floor (nothing written yet)
      -> ModificationPipeline (Phase D): decode -> target checks -> remove one smali
         file / one method block / rewrite one invocation -> exact-mutation check -> build
         -> align -> sign -> verify -> Phase E diff + expected-vs-actual classification +
         verification matrix
      -> H.1 re-analysis of the transformed APK (target absent / call site replaced,
         nothing else changed)
      -> verification matrix -> publish the output APK only when every check passed

The eligibility decision is H.2's: H.3 re-runs the *same* planner to establish that the
plan is current and unmodified, and never evaluates eligibility itself. Nothing here
writes the source APK; the output path must differ from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
import zipfile
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from apkforge.builders.semantic_baseline import current_toolchain_identity
from apkforge.diff.expectations import ObservationClass
from apkforge.inspection.dex import DEXInspector
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.modifiers.base import StepStatus
from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineStatus,
    measure_noise_floor,
)
from apkforge.reference.models import (
    SCHEMA_VERSION,
    AnalysisState,
    Component,
    DefinedMethod,
    ReferenceKind,
)
from apkforge.transformation.application import (
    SUPPORTED_TRANSFORMATIONS,
    ApplicationFailure,
    ApplicationReason,
    ApplicationStage,
    ApplicationStatus,
    CallSitePostAnalysis,
    CheckOutcome,
    MatrixRow,
    MethodPostAnalysis,
    MutationRecord,
    PostAnalysis,
    TransformationApplicationResult,
)
from apkforge.transformation.catalog import get_spec
from apkforge.transformation.dexstate import (
    call_site_api_state,
    class_api_references,
    method_api_references,
    method_key,
)
from apkforge.transformation.models import (
    PLANNING_SCHEMA_VERSION,
    EligibilityState,
    PlanningResult,
    TargetKind,
    TransformationPlan,
    TransformationRequest,
)
from apkforge.transformation.modifier import (
    H3_MODIFIER_ID,
    H5_MODIFIER_ID,
    H6_MODIFIER_ID,
    RemoveIsolatedClassModifier,
    RemoveIsolatedMethodModifier,
    ReplaceCallSiteModifier,
    _evidence_target,
    _invocation,
    _other_evidence,
)
from apkforge.transformation.planner import TransformationPlanner, decision_id_for
from apkforge.transformation.selector import TargetEvidenceSelector
from apkforge.transformation.targets import ParseError, parse_target
from apkforge.verification.pair import check_baseline

if TYPE_CHECKING:
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.service import BuildService
    from apkforge.diff.engine import DiffEngine
    from apkforge.modification.pipeline import PipelineResult
    from apkforge.reference.models import Evidence, ReferenceAnalysisResult
    from apkforge.reference.service import ReferenceAnalysisService

__all__ = [
    "H3_LIMITATIONS",
    "PlanRefusal",
    "TransformationExecutor",
    "assess_post_analysis",
    "assess_post_analysis_call_site",
    "assess_post_analysis_method",
    "call_site_consequences",
    "load_plan",
    "method_removal_consequences",
    "plan_id_for",
    "removal_consequences",
]

#: plan change type per supported transformation
_PLAN_CHANGE_TYPE = {
    "H-TRANS-001": "remove_class",
    "H-TRANS-002": "remove_method",
    "H-TRANS-003": "replace_call_site",
}
#: target kind per supported transformation
_TARGET_KIND = {
    "H-TRANS-001": TargetKind.CLASS,
    "H-TRANS-002": TargetKind.METHOD,
    "H-TRANS-003": TargetKind.CALL_SITE,
}
#: planned-change details an H-TRANS-003 plan must carry
_CALL_SITE_DETAILS = (
    "caller_class",
    "caller_method",
    "source_line",
    "opcode",
    "registers",
    "original",
    "replacement",
    "occurrence",
    "occurrences_in_caller",
)

R = ApplicationReason
S = ApplicationStatus
G = ApplicationStage

H3_LIMITATIONS = [
    "The controlled executor applies only H-TRANS-001 (remove isolated class), "
    "H-TRANS-002 (remove isolated method) and H-TRANS-003 (replace one call site) to a "
    "plan H.2 marked ELIGIBLE; it adds no eligibility rule of its own and has no override.",
    "Verification is static: the transformed APK is rebuilt, signed, re-analysed (H.1) and "
    "diffed (Phase E). It is not installed or executed, so runtime behaviour is not observed.",
    "The output is re-signed with the configured (development) key and cannot update an "
    "installation signed with the original key.",
    "A VERIFIED result establishes that exactly the planned class or method was removed, "
    "or exactly the planned invocation was replaced, and nothing else changed within the "
    "analysed scope; it does not establish that the application is safe, benign or "
    "malware-free. H.5 removes no callers and repairs no references: if the target is not "
    "genuinely isolated, H.2 refuses the transformation.",
    "H.6 replaces a call site only with a method of the identical descriptor and invocation "
    "kind; that is a type-level compatibility, not semantic equivalence: no claim is made "
    "that behaviour or functionality is preserved.",
]

_STAGE_REASONS = {
    "prepare": (G.PREPARE, R.DECODE_FAILED),
    "decode": (G.DECODE, R.DECODE_FAILED),
    "build": (G.BUILD, R.BUILD_FAILED),
    "align": (G.ALIGN, R.ALIGN_FAILED),
    "sign": (G.SIGN, R.SIGN_FAILED),
    "verify": (G.VERIFY, R.SIGNATURE_VERIFICATION_FAILED),
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def content_sha256(apk: Path) -> str:
    """SHA-256 over the sorted (entry name, entry content SHA-256) list of an APK."""
    h = hashlib.sha256()
    with zipfile.ZipFile(apk) as z:
        for name in sorted(z.namelist()):
            h.update(f"{name}\t{hashlib.sha256(z.read(name)).hexdigest()}\n".encode())
    return h.hexdigest()


class _Refusal(Exception):
    def __init__(
        self,
        code: ApplicationReason,
        stage: ApplicationStage,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.failure = ApplicationFailure(
            code=code, stage=stage, message=message, details=details or {}
        )


#: public name of the refusal raised by :func:`load_plan` / :func:`removal_consequences`
PlanRefusal = _Refusal


def load_plan(source: Path | str | TransformationPlan | PlanningResult) -> TransformationPlan:
    """The single plan in *source* (a plan, an H.2 result or a JSON file of either).

    Raises :class:`_Refusal` (PLAN_NOT_FOUND, PLAN_INVALID, PLAN_NOT_ELIGIBLE).
    """
    data: Any = source
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise _Refusal(R.PLAN_NOT_FOUND, G.PLAN_LOAD, f"plan file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _Refusal(R.PLAN_INVALID, G.PLAN_LOAD, f"plan is not JSON: {exc}") from exc
    try:
        if isinstance(data, dict):
            data = (PlanningResult if "decisions" in data else TransformationPlan).model_validate(
                data
            )
    except ValidationError as exc:
        msg = f"plan does not match the H.2 schema: {exc.error_count()} error(s)"
        raise _Refusal(R.PLAN_INVALID, G.PLAN_LOAD, msg) from exc
    if isinstance(data, PlanningResult):
        if len(data.decisions) != 1:
            raise _Refusal(
                R.PLAN_INVALID,
                G.PLAN_LOAD,
                f"the H.2 result holds {len(data.decisions)} decisions; H.3 applies exactly "
                "one (plan each target separately)",
            )
        d = data.decisions[0]
        if d.plan is None:
            raise _Refusal(
                R.PLAN_NOT_ELIGIBLE,
                G.ELIGIBILITY,
                f"H.2 decided {d.eligibility.value} for {d.transformation_id} "
                f"{d.target.canonical if d.target else '(invalid target)'}; no plan exists",
                {
                    "eligibility": d.eligibility.value,
                    "reasons": sorted({r.code.value for r in d.reasons}),
                },
            )
        if d.plan.eligibility is not d.eligibility:
            raise _Refusal(R.PLAN_INVALID, G.PLAN_LOAD, "decision and plan disagree on eligibility")
        data = d.plan
    if not isinstance(data, TransformationPlan):
        raise _Refusal(R.PLAN_INVALID, G.PLAN_LOAD, "not an H.2 plan or planning result")
    if data.planning_schema != PLANNING_SCHEMA_VERSION or data.analysis_schema != SCHEMA_VERSION:
        raise _Refusal(
            R.PLAN_INVALID,
            G.PLAN_LOAD,
            f"plan schemas (planning {data.planning_schema}, analysis {data.analysis_schema}) "
            f"differ from this APKForge (planning {PLANNING_SCHEMA_VERSION}, analysis "
            f"{SCHEMA_VERSION})",
        )
    changes = data.planned_changes
    expected_type = _PLAN_CHANGE_TYPE.get(data.transformation_id)
    if expected_type is not None and (
        len(changes) != 1 or changes[0].type != expected_type or not changes[0].artifact
    ):
        raise _Refusal(
            R.PLAN_INVALID, G.PLAN_LOAD, f"plan does not hold one {expected_type} change"
        )
    if expected_type == "replace_call_site":
        det = changes[0].details
        # registers may be empty (an invocation without arguments), never absent
        missing = [
            k for k in _CALL_SITE_DETAILS if k not in det or (k != "registers" and not det[k])
        ]
        numeric = all(det.get(k, "").isdigit() for k in ("source_line", "occurrence"))
        if missing or not numeric or det.get("expected_mutation_count") != "1":
            raise _Refusal(
                R.PLAN_INVALID,
                G.PLAN_LOAD,
                f"the replace_call_site change is incomplete (missing {missing}, or an invalid "
                "line / occurrence / expected mutation count other than 1)",
            )
    return data


class TransformationExecutor:
    """Validates and applies one H.2 plan. See the module docstring.

    Args:
        build_service: configured BuildService (decode/build/align/sign/verify).
        reference_service: H.1 analysis for the re-evaluation and the post-analysis
            (default: one sharing *build_service*).
        diff_engine: DiffEngine for the Phase E comparison.
    """

    def __init__(
        self,
        build_service: BuildService,
        *,
        reference_service: ReferenceAnalysisService | None = None,
        diff_engine: DiffEngine | None = None,
    ) -> None:
        from apkforge.reference.service import ReferenceAnalysisService

        self.service = build_service
        self.reference = reference_service or ReferenceAnalysisService(
            build_service, work_dir=build_service.work_dir / "h3-references"
        )
        self.diff_engine = diff_engine

    def run(
        self,
        apk: Path | str,
        plan: Path | str | TransformationPlan | PlanningResult,
        *,
        apply: bool = False,
        output_apk: Path | str | None = None,
        noop_baseline: NoopSemanticBaseline | None = None,
        work_dir: Path | None = None,
        keep_workspace: bool = False,
    ) -> TransformationApplicationResult:
        """Validate *plan* against *apk*; with ``apply`` transform, verify and publish.

        Without ``apply`` nothing is mutated, built or signed (status PLANNED or
        REFUSED). ``noop_baseline`` None measures this APK's noise floor first (one
        unmodified rebuild).
        """
        src = Path(apk).expanduser().resolve()
        sha = _sha256(src)
        result = TransformationApplicationResult(
            source_apk=str(src),
            source_apk_sha256=sha,
            status=S.PLANNED,
            dry_run=not apply,
            limitations=list(H3_LIMITATIONS),
        )
        facts: dict[str, tuple[str, bool | None]] = {}
        try:
            self._run(result, facts, src, plan, apply, output_apk, noop_baseline, work_dir,
                      keep_workspace)  # fmt: skip
        except _Refusal as exc:
            result.failure = exc.failure
            result.advance(_final_status(result.status, exc.failure))
        finally:
            after = _sha256(src)
            result.source_apk_sha256_after = after
            result.original_unchanged = after == sha
            facts["original"] = (after, after == sha)
            if not result.original_unchanged:
                result.failure = ApplicationFailure(
                    code=R.ORIGINAL_CHANGED,
                    stage=G.PUBLISH,
                    message="the source APK changed during the run",
                )
                if result.output_apk:  # never leave an output of an invalid run behind
                    Path(result.output_apk).unlink(missing_ok=True)
                result.output_apk = result.output_apk_sha256 = None
                result.advance(S.FAILED)
            if apply:
                result.verification = _matrix(facts, result.transformation_id)
        return result

    # -- body -------------------------------------------------------------------

    def _run(
        self,
        result: TransformationApplicationResult,
        facts: dict[str, tuple[str, bool | None]],
        src: Path,
        source: Path | str | TransformationPlan | PlanningResult,
        apply: bool,
        output_apk: Path | str | None,
        noop_baseline: NoopSemanticBaseline | None,
        work_dir: Path | None,
        keep_workspace: bool,
    ) -> None:
        plan = load_plan(source)
        result.planning_schema = plan.planning_schema
        result.analysis_schema = plan.analysis_schema
        result.transformation_id = plan.transformation_id
        result.plan_id = plan.plan_id
        result.plan_source_sha256 = plan.apk.sha256
        result.target = {"class": plan.target.class_name}
        if plan.target.kind is TargetKind.METHOD:
            result.target.update(
                method=plan.target.method_name or "", descriptor=plan.target.descriptor or ""
            )
        if plan.planned_changes:
            ch = plan.planned_changes[0]
            result.target.update(file=ch.artifact or "", dex=ch.details.get("dex", ""))
            if plan.target.kind is TargetKind.CALL_SITE:
                result.target.update(
                    call_site=plan.target.canonical,
                    method=ch.details.get("caller_method", ""),
                    line=ch.details.get("source_line", ""),
                    original=ch.details.get("original", ""),
                    replacement=ch.details.get("replacement", ""),
                )
        result.planned_changes = [c.model_dump(mode="json") for c in plan.planned_changes]

        # 1. source identity
        facts["source"] = (result.source_apk_sha256, plan.apk.sha256 == result.source_apk_sha256)
        if plan.apk.sha256 != result.source_apk_sha256:
            raise _Refusal(
                R.SOURCE_SHA_MISMATCH,
                G.PLAN_INTEGRITY,
                f"APK SHA-256 {result.source_apk_sha256} differs from the plan's {plan.apk.sha256}",
            )
        # 2. plan identity (H.2 rules)
        recomputed = _plan_id(plan)
        facts["plan_id"] = (recomputed or "(target unparseable)", recomputed == plan.plan_id)
        if recomputed != plan.plan_id:
            raise _Refusal(
                R.PLAN_ID_MISMATCH,
                G.PLAN_INTEGRITY,
                f"plan id {plan.plan_id} does not match the id recomputed from its contents "
                f"({recomputed})",
            )
        # 3. supported + eligible
        if plan.transformation_id not in SUPPORTED_TRANSFORMATIONS:
            raise _Refusal(
                R.UNSUPPORTED_TRANSFORMATION,
                G.ELIGIBILITY,
                f"the controlled executor applies only {', '.join(SUPPORTED_TRANSFORMATIONS)}; "
                f"{plan.transformation_id} is planning-only",
            )
        # the plan's target kind must match the transformation it names (H-TRANS-001 class,
        # H-TRANS-002 method, H-TRANS-003 call site): a plan never reaches another
        # transformation's modifier
        want_kind = _TARGET_KIND[plan.transformation_id]
        if plan.target.kind is not want_kind:
            raise _Refusal(
                R.UNSUPPORTED_TARGET_TYPE,
                G.ELIGIBILITY,
                f"{plan.transformation_id} targets a {want_kind.value}, but the plan's target "
                f"is a {plan.target.kind.value}",
            )
        facts["eligibility"] = (
            plan.eligibility.value,
            plan.eligibility is EligibilityState.ELIGIBLE,
        )
        if plan.eligibility is not EligibilityState.ELIGIBLE or plan.conditions:
            raise _Refusal(
                R.PLAN_NOT_ELIGIBLE,
                G.ELIGIBILITY,
                f"plan eligibility is {plan.eligibility.value}; only ELIGIBLE plans are applied",
            )
        # 4. the plan is what H.2 produces for this APK today
        pre = self._reevaluate(plan, src, facts)
        result.advance(S.PLANNED)
        if not apply:
            return

        # 5. output path, expected consequences, noise floor (nothing written yet)
        out = self._output(output_apk, src)
        is_method = plan.target.kind is TargetKind.METHOD
        is_call = plan.target.kind is TargetKind.CALL_SITE
        api_added: set[str] = set()
        if is_call:
            api_removed, api_added, pool = call_site_consequences(src, plan)
        elif is_method:
            assert plan.target.method_name is not None and plan.target.descriptor is not None
            _, api_removed, pool = method_removal_consequences(
                src, plan.target.class_name, plan.target.method_name, plan.target.descriptor
            )
        else:
            api_removed, pool = _consequences(src, plan.target.class_name)
        sha = result.source_apk_sha256
        if noop_baseline is None:
            tmp = Path(tempfile.mkdtemp(prefix="h3-noise-", dir=self._work(work_dir)))
            try:
                noop_baseline = measure_noise_floor(self.service, src, work_dir=tmp,
                                                    diff_engine=self.diff_engine)  # fmt: skip
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        check = check_baseline(noop_baseline, sha, current_toolchain_identity(self.service))
        if not check.usable:
            raise _Refusal(
                R.NOISE_BASELINE_UNAVAILABLE,
                G.PREPARE,
                f"no usable no-op noise baseline for this APK ({check.status}: "
                f"{'; '.join(check.reasons)}); the transformation could not be verified",
            )

        # 6. mutation + build + Phase E (ModificationPipeline)
        result.advance(S.APPLYING)
        modifier: (
            RemoveIsolatedClassModifier | RemoveIsolatedMethodModifier | ReplaceCallSiteModifier
        )
        if is_call:
            modifier = ReplaceCallSiteModifier(
                plan,
                defined_classes=len(pre.defined_classes),
                string_pool=pool,
                api=(api_removed, api_added),
            )
            modifier_id = H6_MODIFIER_ID
        elif is_method:
            modifier = RemoveIsolatedMethodModifier(
                plan,
                defined_classes=len(pre.defined_classes),
                string_pool=pool,
                api_removed=api_removed,
            )
            modifier_id = H5_MODIFIER_ID
        else:
            modifier = RemoveIsolatedClassModifier(
                plan,
                defined_classes=len(pre.defined_classes),
                string_pool=pool,
                api_removed=api_removed,
            )
            modifier_id = H3_MODIFIER_ID
        pipeline = ModificationPipeline(
            self.service, ModifierCatalog([modifier]), diff_engine=self.diff_engine
        )
        pres = pipeline.run(
            src,
            [ModifierRequest(modifier_id=modifier_id)],
            noop_baseline=noop_baseline,
            work_dir=work_dir,
            keep_workspace=True,
        )
        result.workspace = pres.workspace
        result.workspace_id = Path(pres.workspace).name if pres.workspace else None
        published = False
        try:
            self._pipeline_outcome(result, facts, pres, modifier)
            assert pres.output_apk is not None
            built = Path(pres.output_apk)
            # 7. H.1 re-analysis of the transformed APK
            if is_call:
                result.call_site_analysis = self._post_analysis_call_site(pre, built, plan, facts)
            elif is_method:
                assert plan.target.method_name is not None and plan.target.descriptor is not None
                result.method_analysis = self._post_analysis_method(
                    pre, built, plan.target.class_name,
                    plan.target.method_name, plan.target.descriptor, facts,
                )  # fmt: skip
            else:
                result.analysis = self._post_analysis(pre, built, plan.target.class_name, facts)
            # 8. publish
            if _sha256(src) != sha:
                raise _Refusal(R.ORIGINAL_CHANGED, G.PUBLISH, "the source APK changed")
            self._publish(result, built, out)
            published = True
            facts["published"] = (str(out), True)
            result.advance(S.VERIFIED)
        finally:
            keep = keep_workspace or (not published and result.mutation is not None)
            result.workspace_kept = keep
            if not keep and pres.workspace:
                shutil.rmtree(pres.workspace, ignore_errors=True)

    # -- steps ------------------------------------------------------------------

    def _reevaluate(
        self,
        plan: TransformationPlan,
        src: Path,
        facts: dict[str, tuple[str, bool | None]],
    ) -> ReferenceAnalysisResult:
        pre = self.reference.analyze(src)
        if pre.errors:
            raise _Refusal(
                R.ANALYSIS_INCOMPLETE,
                G.ELIGIBILITY,
                f"H.1 analysis of the source failed: {'; '.join(pre.errors)}",
            )
        request = TransformationRequest(
            transformation_id=plan.transformation_id,
            target=plan.target.raw,
            parameters=plan.parameters,
        )
        decision = TransformationPlanner(pre).plan([request]).decisions[0]
        facts["eligibility"] = (
            f"plan {plan.eligibility.value}, re-evaluated {decision.eligibility.value}",
            decision.eligibility is EligibilityState.ELIGIBLE,
        )
        if decision.eligibility is not EligibilityState.ELIGIBLE or decision.plan is None:
            raise _Refusal(
                R.PLAN_NOT_ELIGIBLE,
                G.ELIGIBILITY,
                f"H.2 re-evaluation of the source decides {decision.eligibility.value}",
                {"reasons": sorted({r.code.value for r in decision.reasons})},
            )
        fresh = decision.plan.model_dump(mode="json")
        given = plan.model_dump(mode="json")
        # the APK is identified by its SHA-256 (checked above), not by its file name
        fresh["apk"]["file_name"] = given["apk"]["file_name"]
        if fresh != given:
            fields = sorted(k for k in fresh.keys() | given.keys() if fresh.get(k) != given.get(k))
            raise _Refusal(
                R.PLAN_MISMATCH,
                G.PLAN_INTEGRITY,
                f"the plan differs from H.2's plan for this APK in: {', '.join(fields)}",
                {"fields": fields},
            )
        by_name = {c.name: c for c in pre.defined_classes}
        if plan.target.kind is TargetKind.CALL_SITE:
            d = plan.planned_changes[0].details
            calls = pre.index().invocations_in(d["caller_class"], d["caller_method"])
            present = any(
                e.evidence_id == d.get("evidence_id")
                and str(e.source_line) == d["source_line"]
                and e.target == _evidence_target(d["original"])
                for e in calls
            )
            facts["before"] = (
                f"{'present' if present else 'absent'} at line {d['source_line']}",
                present,
            )
        elif plan.target.kind is TargetKind.METHOD:
            dc = by_name.get(plan.target.class_name)
            sig = f"{plan.target.method_name}{plan.target.descriptor}"
            present = dc is not None and any(m.signature == sig for m in dc.methods)
            facts["before"] = ("present" if present else "absent", present)
        else:
            present = plan.target.class_name in by_name
            facts["before"] = ("present" if present else "absent", present)
        return pre

    def _work(self, work_dir: Path | None) -> Path:
        base = Path(work_dir or self.service.work_dir)
        base.mkdir(parents=True, exist_ok=True)
        return base

    @staticmethod
    def _output(output_apk: Path | str | None, src: Path) -> Path:
        if output_apk is None:
            raise _Refusal(R.OUTPUT_INVALID, G.PREPARE, "an output APK path is required")
        out = Path(output_apk).expanduser().resolve()
        if out == src:
            raise _Refusal(R.OUTPUT_INVALID, G.PREPARE, "the output path is the source APK")
        if out.is_dir():
            raise _Refusal(R.OUTPUT_INVALID, G.PREPARE, f"the output path is a directory: {out}")
        return out

    def _pipeline_outcome(
        self,
        result: TransformationApplicationResult,
        facts: dict[str, tuple[str, bool | None]],
        pres: PipelineResult,
        modifier: RemoveIsolatedClassModifier
        | RemoveIsolatedMethodModifier
        | ReplaceCallSiteModifier,
    ) -> None:
        """Record the pipeline run; raise :class:`_Refusal` unless it fully verified."""
        run = pres.modifiers[0]
        if run.plan is not None:
            result.expected_changes = list(run.plan.expected_changes)
        if run.apply is not None and "mutation" in run.apply.details:
            result.mutation = MutationRecord.model_validate(run.apply.details["mutation"])
        stages = {s.stage: s for s in pres.stages}
        result.build = {
            "pipeline_status": str(pres.status),
            "stages": [
                {
                    "stage": s.stage,
                    "status": s.status,
                    "failure_category": s.failure_category,
                    "failure_cause": s.failure_cause,
                }
                for s in pres.stages
            ],
            "build_passed": pres.build_passed,
            "apk_verified": pres.apk_verified,
            "signer_sha256": pres.signer_sha256,
            "signing_mode": pres.signing_mode,
            "verification": {
                k: v for k, v in (pres.verification or {}).items() if k != "apksigner_warnings"
            },
            "noise_floor": pres.noise_floor,
        }
        for name in ("build", "align", "sign", "verify"):
            st = stages.get(name)
            facts[name] = (st.status if st else "not run", st.status == "PASS" if st else None)
        m = result.mutation
        if m is not None and m.operation == "REPLACE_CALL_SITE":
            ok_line = m.changed_lines == [m.source_line]
            facts["after"] = (
                f"line {m.source_line}: {m.replacement_instruction}",
                ok_line and len(m.removed_invocations) == 1,
            )
            facts["replacement"] = (
                "; ".join(m.added_invocations) or "none",
                ok_line and len(m.added_invocations) == 1,
            )
            facts["removed"] = (str(m.count), m.count == 1)
            others = m.other_changes + m.removed_classes + m.added_classes
            facts["others"] = (
                f"{len(others)} other change(s); changed lines {m.changed_lines}",
                not others and ok_line,
            )
        elif m is not None and m.operation == "REMOVE_METHOD":
            sig = m.method_signature or ""
            absent = m.removed_methods == [sig] and sig not in m.added_methods
            facts["after"] = ("absent" if absent else "present/changed", absent)
            facts["removed"] = (str(m.count), m.count == 1)
            others = (
                [s for s in m.removed_methods if s != sig]
                + m.added_methods
                + m.removed_classes
                + m.added_classes
            )
            ok_others = (
                not others
                and m.classes_before == m.classes_after
                and m.methods_before is not None
                and m.methods_after == m.methods_before - 1
            )
            facts["others"] = (str(len(others)), ok_others)
        elif m is not None:
            facts["after"] = (
                "absent" if m.post_transform_sha256 is None else "present",
                m.post_transform_sha256 is None,
            )
            facts["removed"] = (str(m.count), m.count == 1)
            others = [c for c in m.removed_classes if c != m.target] + m.added_classes
            facts["others"] = (str(len(others)), not others)
        if pres.verdict is not None:
            v = pres.verdict
            bad = (ObservationClass.UNEXPECTED, ObservationClass.UNKNOWN)
            unexpected = [o.observation for o in v.observations if o.classification in bad]
            result.diff = {
                "passed": v.passed,
                "mode": v.mode,
                "diff_status": v.diff_status,
                "counts": v.counts,
                "expected_observed": [
                    f"{e.category} {e.kind} {e.identifier}" for e in v.expected_observed
                ],
                "expected_missing": [
                    f"{e.category} {e.kind} {e.identifier}" for e in v.expected_missing
                ],
                "unexpected": [f"{o.category} {o.kind} {o.identifier}" for o in unexpected],
                "noise_rule_counts": v.noise_rule_counts,
                "failures": list(v.failures),
                "matrix": (
                    {
                        "overall": str(pres.verification_matrix.overall),
                        "reason": pres.verification_matrix.overall_reason,
                        "checks": {
                            n: str(c.status)
                            for n, c in sorted(pres.verification_matrix.checks.items())
                        },
                    }
                    if pres.verification_matrix
                    else None
                ),
            }
            clean = v.passed and not unexpected and not v.expected_missing
            facts["semantic"] = (
                f"{len(unexpected)} unexpected/unknown, {len(v.expected_missing)} expected "
                "change(s) missing",
                clean,
            )

        if not pres.original_preserved:
            raise _Refusal(R.ORIGINAL_CHANGED, G.MUTATION, "the source APK changed")
        for name in ("prepare", "decode"):
            st = stages.get(name)
            if st is not None and st.status != "PASS":
                stage, code = _STAGE_REASONS[name]
                raise _Refusal(code, stage, f"{name}: {st.failure_category}: {st.failure_cause}")
        if run.step.status is StepStatus.SKIPPED and run.plan is not None:
            code = R(run.plan.refusal_code or R.TRANSFORMATION_PRECONDITION_FAILED.value)
            raise _Refusal(code, G.PRE_TRANSFORM, "; ".join(run.plan.problems))
        if (
            run.apply is None
            or not run.apply.applied
            or (run.source_check is not None and not run.source_check.passed)
        ):
            reason = (run.apply.details.get("reason") if run.apply else None) or (
                R.UNEXPECTED_MUTATION.value
                if run.source_check is not None
                else R.TRANSFORMATION_PRECONDITION_FAILED.value
            )
            problems = [run.step.message]
            if run.source_check is not None:
                problems += run.source_check.problems
            raise _Refusal(R(reason), G.MUTATION, "; ".join(p for p in problems if p))
        for name in ("build", "align", "sign", "verify"):
            st = stages.get(name)
            if st is None or st.status != "PASS":
                stage, code = _STAGE_REASONS[name]
                cause = f"{st.failure_category}: {st.failure_cause}" if st else "not run"
                raise _Refusal(code, stage, f"{name}: {cause}")
        result.advance(S.BUILT)
        if pres.verdict is None or not facts.get("semantic", ("", False))[1]:
            noise = any("noise floor not established" in f for f in pres.failures)
            raise _Refusal(
                R.NOISE_BASELINE_UNAVAILABLE if noise else R.UNEXPECTED_DIFF,
                G.DIFF,
                "; ".join(pres.failures) or "the Phase E comparison did not pass",
                {"unexpected": result.diff.get("unexpected", [])},
            )
        if run.step.verified is not True or pres.status is not PipelineStatus.VERIFIED:
            msg = run.verification.message if run.verification else "; ".join(pres.failures)
            raise _Refusal(
                R.POST_TRANSFORMATION_VERIFICATION_FAILED,
                G.DIFF,
                msg or f"pipeline status {pres.status} (verification matrix not VERIFIED)",
            )
        if modifier.mutation is None:
            raise _Refusal(R.UNEXPECTED_MUTATION, G.MUTATION, "no mutation record")

    def _post_analysis(
        self,
        pre: ReferenceAnalysisResult,
        built: Path,
        target: str,
        facts: dict[str, tuple[str, bool | None]],
    ) -> PostAnalysis:
        pa = assess_post_analysis(pre, self.reference.analyze(built), target)
        weakened, sufficient = pa.weakened_components, pa.sufficient
        facts["analysis"] = (
            f"{pa.analysis_state}; weakened {weakened or 'none'}",
            sufficient,
        )
        # the mutation record (decoded project) and the re-analysis must both agree
        mutated_ok = facts.get("after", ("", True))[1] is True
        facts["after"] = (
            "present" if pa.target_defined else "absent (decoded project and H.1 re-analysis)",
            mutated_ok and not pa.target_defined,
        )
        others_ok = not pa.other_classes_removed and not pa.classes_added
        facts["others"] = (
            f"{len(pa.other_classes_removed)} removed, {len(pa.classes_added)} added",
            others_ok and facts.get("others", ("", True))[1] is True,
        )
        if not sufficient:
            raise _Refusal(
                R.ANALYSIS_INCOMPLETE,
                G.POST_ANALYSIS,
                "the H.1 analysis of the transformed APK is not sufficient to establish the "
                f"result ({pa.analysis_state}; weakened: {weakened}; errors: {pa.errors})",
            )
        problems = []
        if pa.target_defined:
            problems.append(f"{target} is still defined")
        if not others_ok:
            problems.append(
                f"other classes changed (removed {pa.other_classes_removed}, added "
                f"{pa.classes_added})"
            )
        if pa.defined_classes_after != pa.defined_classes_before - 1:
            problems.append(
                f"defined classes {pa.defined_classes_before} -> {pa.defined_classes_after}"
            )
        if pa.definitive_references or pa.indirect_references:
            problems.append(
                f"{pa.definitive_references} structural / {pa.indirect_references} indirect "
                f"reference(s) to {target} in the transformed APK"
            )
        if problems:
            raise _Refusal(
                R.POST_TRANSFORMATION_VERIFICATION_FAILED, G.POST_ANALYSIS, "; ".join(problems)
            )
        return pa

    def _post_analysis_method(
        self,
        pre: ReferenceAnalysisResult,
        built: Path,
        class_name: str,
        method_name: str,
        descriptor: str,
        facts: dict[str, tuple[str, bool | None]],
    ) -> MethodPostAnalysis:
        pa = assess_post_analysis_method(
            pre, self.reference.analyze(built), class_name, method_name, descriptor
        )
        sufficient = pa.sufficient
        facts["analysis"] = (f"{pa.analysis_state}; weakened {pa.weakened_components or 'none'}",
                             sufficient)  # fmt: skip
        mutated_ok = facts.get("after", ("", True))[1] is True
        facts["after"] = (
            "present" if pa.target_method_present else "absent (decoded project and H.1)",
            mutated_ok and pa.class_defined and not pa.target_method_present,
        )
        others_ok = not pa.other_methods_removed and not pa.methods_added
        facts["others"] = (
            f"{len(pa.other_methods_removed)} removed, {len(pa.methods_added)} added",
            others_ok and facts.get("others", ("", True))[1] is True,
        )
        if not sufficient:
            raise _Refusal(
                R.ANALYSIS_INCOMPLETE,
                G.POST_ANALYSIS,
                "the H.1 analysis of the transformed APK is not sufficient to establish the "
                f"result ({pa.analysis_state}; weakened: {pa.weakened_components}; errors: "
                f"{pa.errors})",
            )
        problems = []
        if not pa.class_defined:
            problems.append(f"{class_name} is no longer defined (the class must be retained)")
        if pa.target_method_present:
            problems.append(f"{class_name}->{pa.method_signature} is still declared")
        if not others_ok:
            problems.append(
                f"other methods of the class changed (removed {pa.other_methods_removed}, "
                f"added {pa.methods_added})"
            )
        if pa.methods_after != pa.methods_before - 1:
            problems.append(f"method count {pa.methods_before} -> {pa.methods_after}")
        if pa.definitive_references or pa.indirect_references:
            problems.append(
                f"{pa.definitive_references} structural / {pa.indirect_references} indirect "
                f"reference(s) to {class_name}->{pa.method_signature} remain"
            )
        if problems:
            raise _Refusal(
                R.POST_TRANSFORMATION_VERIFICATION_FAILED, G.POST_ANALYSIS, "; ".join(problems)
            )
        return pa

    def _post_analysis_call_site(
        self,
        pre: ReferenceAnalysisResult,
        built: Path,
        plan: TransformationPlan,
        facts: dict[str, tuple[str, bool | None]],
    ) -> CallSitePostAnalysis:
        pa = assess_post_analysis_call_site(pre, self.reference.analyze(built), plan)
        facts["analysis"] = (f"{pa.analysis_state}; weakened {pa.weakened_components or 'none'}",
                             pa.sufficient)  # fmt: skip
        mutated_ok = facts.get("after", ("", True))[1] is True
        gone = pa.original_calls_after == pa.original_calls_before - 1
        facts["after"] = (
            f"original invocations {pa.original_calls_before} -> {pa.original_calls_after} "
            "(decoded project and H.1)",
            mutated_ok and gone and pa.caller_present,
        )
        repl_ok = facts.get("replacement", ("", True))[1] is True
        facts["replacement"] = (
            f"at planned position: {pa.replacement_at_planned_position}; replacement "
            f"invocations {pa.replacement_calls_before} -> {pa.replacement_calls_after}",
            repl_ok and pa.replacement_at_planned_position,
        )
        others = pa.other_reference_changes + pa.caller_reference_changes + pa.declaration_changes
        facts["others"] = (
            f"{len(others)} other reference/declaration change(s); changed positions "
            f"{pa.changed_positions}",
            not others
            and len(pa.changed_positions) == 1
            and facts.get("others", ("", True))[1] is True,
        )
        if not pa.sufficient:
            raise _Refusal(
                R.ANALYSIS_INCOMPLETE,
                G.POST_ANALYSIS,
                "the H.1 analysis of the transformed APK is not sufficient to establish the "
                f"result ({pa.analysis_state}; weakened: {pa.weakened_components}; errors: "
                f"{pa.errors})",
            )
        problems = []
        if not pa.caller_present:
            problems.append(f"{pa.caller_class}->{pa.caller_method} is no longer declared")
        if not pa.replacement_at_planned_position:
            problems.append("the replacement invocation is not at the planned position")
        if len(pa.changed_positions) != 1:
            problems.append(f"invocation positions changed: {pa.changed_positions}")
        if not gone:
            problems.append(
                f"original invocations {pa.original_calls_before} -> {pa.original_calls_after}"
            )
        if others:
            problems.append(f"other changes: {others[:5]}")
        if problems:
            raise _Refusal(
                R.POST_TRANSFORMATION_VERIFICATION_FAILED, G.POST_ANALYSIS, "; ".join(problems)
            )
        return pa

    @staticmethod
    def _publish(result: TransformationApplicationResult, built: Path, out: Path) -> None:
        """Copy the verified APK to *out* atomically (temp file + rename)."""
        out.parent.mkdir(parents=True, exist_ok=True)
        expected = _sha256(built)
        tmp = out.with_name(f".{out.name}.{uuid.uuid4().hex[:8]}.partial")
        try:
            shutil.copyfile(built, tmp)
            if _sha256(tmp) != expected:
                raise _Refusal(R.OUTPUT_INVALID, G.PUBLISH, "copied output does not match")
            os.replace(tmp, out)
        finally:
            tmp.unlink(missing_ok=True)
        result.output_apk = str(out)
        result.output_apk_sha256 = expected
        result.output_content_sha256 = content_sha256(out)


def _final_status(current: ApplicationStatus, failure: ApplicationFailure) -> ApplicationStatus:
    """REFUSED before any mutation, UNKNOWN when the result cannot be established,
    FAILED otherwise."""
    if current is S.PLANNED or failure.stage is G.PRE_TRANSFORM:
        return S.REFUSED
    if failure.code is R.ANALYSIS_INCOMPLETE and failure.stage is G.POST_ANALYSIS:
        return S.UNKNOWN
    return S.FAILED


def assess_post_analysis(
    pre: ReferenceAnalysisResult, post: ReferenceAnalysisResult, target: str
) -> PostAnalysis:
    """Compare the H.1 analysis of a transformed APK (*post*) with the original's (*pre*)
    for the removal of *target*. Shared by H.3 (before publishing) and H.4."""
    pre_states = pre.component_states
    post_states = post.component_states
    weakened = sorted(
        k
        for k, v in pre_states.items()
        if v is AnalysisState.COMPLETE and post_states.get(k) is not AnalysisState.COMPLETE
    )
    before = {c.name for c in pre.defined_classes} - {target}
    after = {c.name for c in post.defined_classes}
    absence = post.index().assess_absence(target)
    sufficient = (
        not post.errors
        and not weakened
        and post.component_state(Component.DEX) is AnalysisState.COMPLETE
    )
    return PostAnalysis(
        analysis_schema=post.schema_version,
        analysis_state=post.analysis_state.value,
        component_states={k: v.value for k, v in sorted(post_states.items())},
        weakened_components=weakened,
        defined_classes_before=len(pre.defined_classes),
        defined_classes_after=len(post.defined_classes),
        target_defined=target in after,
        other_classes_removed=sorted(before - after),
        classes_added=sorted(after - before - {target}),
        absence_conclusion=absence.conclusion.value,
        definitive_references=len(absence.definitive_references),
        indirect_references=len(absence.indirect_evidence),
        sufficient=sufficient,
        errors=list(post.errors),
    )


def assess_post_analysis_method(
    pre: ReferenceAnalysisResult,
    post: ReferenceAnalysisResult,
    class_name: str,
    method_name: str,
    descriptor: str,
) -> MethodPostAnalysis:
    """Compare the H.1 analysis of a transformed APK (*post*) with the original's (*pre*)
    for the removal of one method: the class survives, the method is gone, every other
    method is unchanged and nothing references the method any more. Shared by H.5 (before
    publishing) and H.4."""
    signature = f"{method_name}{descriptor}"
    pre_states = pre.component_states
    post_states = post.component_states
    weakened = sorted(
        k
        for k, v in pre_states.items()
        if v is AnalysisState.COMPLETE and post_states.get(k) is not AnalysisState.COMPLETE
    )
    pre_by_name = {c.name: c for c in pre.defined_classes}
    post_by_name = {c.name: c for c in post.defined_classes}
    pre_cls = pre_by_name.get(class_name)
    post_cls = post_by_name.get(class_name)
    pre_sigs = [m.signature for m in pre_cls.methods] if pre_cls else []
    post_sigs = [m.signature for m in post_cls.methods] if post_cls else []
    other_removed = sorted((set(pre_sigs) - {signature}) - set(post_sigs))
    added = sorted(set(post_sigs) - set(pre_sigs))

    # remaining references to the (now absent) method, using the H.2 selector on *post*
    definitive = indirect = 0
    if post_cls is not None:
        selector = TargetEvidenceSelector(post)
        probe = DefinedMethod(name=method_name, descriptor=descriptor)
        cats = selector._method_categories(class_name, probe)
        definitive = len(cats.get("call_sites", [])) + len(cats.get("reflection_targeting", []))
        indirect = (
            len(cats.get("reflection_name_match", []))
            + len(cats.get("reflection_unresolved", []))
            + len(cats.get("string_mentions", []))
        )
    dex_ok = post.component_state(Component.DEX) is AnalysisState.COMPLETE
    reflection_ok = post.component_state(Component.REFLECTION) is AnalysisState.COMPLETE
    sufficient = not post.errors and not weakened and dex_ok and reflection_ok
    return MethodPostAnalysis(
        analysis_schema=post.schema_version,
        analysis_state=post.analysis_state.value,
        component_states={k: v.value for k, v in sorted(post_states.items())},
        weakened_components=weakened,
        class_name=class_name,
        class_defined=class_name in post_by_name,
        method_signature=signature,
        target_method_present=signature in post_sigs,
        methods_before=len(pre_sigs),
        methods_after=len(post_sigs),
        other_methods_removed=other_removed,
        methods_added=added,
        definitive_references=definitive,
        indirect_references=indirect,
        sufficient=sufficient,
        errors=list(post.errors),
    )


def assess_post_analysis_call_site(
    pre: ReferenceAnalysisResult, post: ReferenceAnalysisResult, plan: TransformationPlan
) -> CallSitePostAnalysis:
    """Compare the H.1 analysis of a transformed APK (*post*) with the original's (*pre*)
    for one call-site replacement: the caller's invocation sequence differs at exactly the
    planned position (original -> replacement; same opcode, registers and result), and no
    other reference or declaration of the APK differs. Shared by H.6 and H.4."""
    d = plan.planned_changes[0].details
    caller_class, caller_method = d["caller_class"], d["caller_method"]
    orig_t, repl_t = _evidence_target(d["original"]), _evidence_target(d["replacement"])
    pre_states, post_states = pre.component_states, post.component_states
    weakened = sorted(
        k
        for k, v in pre_states.items()
        if v is AnalysisState.COMPLETE and post_states.get(k) is not AnalysisState.COMPLETE
    )
    pre_cls = {c.name: c for c in pre.defined_classes}
    post_cls = {c.name: c for c in post.defined_classes}
    caller_post = post_cls.get(caller_class)
    caller_present = caller_post is not None and any(
        m.signature == caller_method for m in caller_post.methods
    )
    pre_inv = pre.index().invocations_in(caller_class, caller_method)
    post_inv = post.index().invocations_in(caller_class, caller_method)
    before = [_invocation(e, line=False) for e in pre_inv]
    after = [_invocation(e, line=False) for e in post_inv]
    pos = next(
        (i for i, e in enumerate(pre_inv) if str(e.source_line) == d["source_line"]
         and e.target == orig_t),
        None,
    )  # fmt: skip
    changed = [
        i
        for i in range(max(len(before), len(after)))
        if (before[i] if i < len(before) else None) != (after[i] if i < len(after) else None)
    ]
    at_pos = (
        pos is not None
        and len(before) == len(after)
        and after[pos] == before[pos].replace(f" {orig_t}", f" {repl_t}", 1)
        and post_inv[pos].target == repl_t
    )

    def refs(res: ReferenceAnalysisResult, inside: bool) -> Counter[str]:
        out: Counter[str] = Counter()
        for e in res.references:
            in_caller = e.source_class == caller_class and e.source_method == caller_method
            if in_caller != inside:
                continue
            if e.kind in (ReferenceKind.METHOD_REFERENCE, ReferenceKind.CONSTRUCTOR_REFERENCE):
                if inside:
                    continue  # compared position by position above
                out[f"{e.source_class} {_invocation(e, line=False)}"] += 1
            elif (
                inside
                and e.kind
                in (
                    ReferenceKind.CLASS_REFERENCE,
                    ReferenceKind.TYPE_REFERENCE,
                )
                and e.context == "member-owner"
                and e.target in (orig_t.rsplit(".", 1)[0], repl_t.rsplit(".", 1)[0])
            ):
                continue  # the swapped reference's owner class (a consequence)
            else:
                out[f"{e.source_class} {_other_evidence(e)}"] += 1
        return out

    def delta(a: Counter[str], b: Counter[str], limit: int = 20) -> list[str]:
        diff = [f"- {k}" for k in sorted((a - b).elements())]
        diff += [f"+ {k}" for k in sorted((b - a).elements())]
        return diff[:limit]

    other_changes = delta(refs(pre, False), refs(post, False))
    caller_changes = delta(refs(pre, True), refs(post, True))
    decl: list[str] = []
    for name in sorted(set(pre_cls) | set(post_cls)):
        a, b = pre_cls.get(name), post_cls.get(name)
        sigs_a = sorted(m.signature for m in a.methods) if a else None
        sigs_b = sorted(m.signature for m in b.methods) if b else None
        if sigs_a != sigs_b:
            decl.append(f"{name}: {'absent' if a is None else len(sigs_a or [])} -> "
                        f"{'absent' if b is None else len(sigs_b or [])} methods")  # fmt: skip

    def count(evs: list[Evidence], target: str) -> int:
        return sum(1 for e in evs if e.target == target)

    sufficient = (
        not post.errors
        and not weakened
        and post.component_state(Component.DEX) is AnalysisState.COMPLETE
    )
    return CallSitePostAnalysis(
        analysis_schema=post.schema_version,
        analysis_state=post.analysis_state.value,
        component_states={k: v.value for k, v in sorted(post_states.items())},
        weakened_components=weakened,
        caller_class=caller_class,
        caller_method=caller_method,
        caller_present=caller_present,
        invocations_before=before,
        invocations_after=after,
        changed_positions=changed,
        replacement_at_planned_position=at_pos,
        original_calls_before=count(pre_inv, orig_t),
        original_calls_after=count(post_inv, orig_t),
        replacement_calls_before=count(pre_inv, repl_t),
        replacement_calls_after=count(post_inv, repl_t),
        other_reference_changes=other_changes,
        caller_reference_changes=caller_changes,
        declaration_changes=decl[:20],
        sufficient=sufficient,
        errors=list(post.errors),
    )


def call_site_consequences(
    src: Path, plan: TransformationPlan
) -> tuple[set[str], set[str], set[str]]:
    """(framework API references removed, added, the DEX string pool) for one call-site
    replacement, from the original APK. The per-instruction attribution must reproduce the
    Phase E DEX inventory and locate exactly the planned invocation."""
    d = plan.planned_changes[0].details
    state = call_site_api_state(
        src, d["caller_class"], d["caller_method"], d["original"], d["replacement"],
        int(d["occurrence"]),
    )  # fmt: skip
    inspection, _ = DEXInspector().inspect(src)
    inventory = {a for df in inspection.dex_files for a in df.api_references}
    if state is None or state.inventory != inventory:
        raise _Refusal(
            R.TRANSFORMATION_PRECONDITION_FAILED,
            G.PRE_TRANSFORM,
            "the planned invocation could not be located exactly once in the DEX, or the "
            "per-instruction API attribution does not reproduce the Phase E DEX inventory; "
            "the expected change cannot be declared",
        )
    pool = {s.value for s in inspection.strings if s.value}
    return state.removed, state.added, pool


def _plan_id(plan: TransformationPlan) -> str | None:
    spec = get_spec(plan.transformation_id)
    if spec is None:
        return None
    target = parse_target(spec.target_type, plan.target.raw)
    if isinstance(target, ParseError) or target.model_dump() != plan.target.model_dump():
        return None
    did = decision_id_for(
        plan.apk.sha256, spec.id, target.canonical, plan.parameters, plan.analysis_schema
    )
    return f"plan-{did}"


def _consequences(src: Path, target: str) -> tuple[set[str], set[str]]:
    """(API references used only by *target*, the DEX string pool) of the source APK."""
    by_class = class_api_references(src)
    inspection, _ = DEXInspector().inspect(src)
    inventory = {a for df in inspection.dex_files for a in df.api_references}
    attributed = set().union(*by_class.values()) if by_class else set()
    if attributed != inventory:
        raise _Refusal(
            R.TRANSFORMATION_PRECONDITION_FAILED,
            G.PRE_TRANSFORM,
            "per-class API attribution does not reproduce the Phase E DEX inventory "
            f"({len(attributed)} vs {len(inventory)}); the expected change cannot be declared",
        )
    others = set().union(*(v for k, v in by_class.items() if k != target))
    pool = {s.value for s in inspection.strings if s.value}
    return by_class.get(target, set()) - others, pool


def _method_consequences(
    src: Path, class_name: str, method_name: str, descriptor: str
) -> tuple[str, set[str], set[str]]:
    """(Phase E method key, API references used only by this method, the DEX string pool).

    Mirrors :func:`_consequences` at method granularity: the framework API references the
    method removal makes disappear are the target method's references minus every other
    method's. The per-method attribution must reproduce the Phase E DEX inventory."""
    key = method_key(method_name, descriptor)
    by_method = method_api_references(src)
    inspection, _ = DEXInspector().inspect(src)
    inventory = {a for df in inspection.dex_files for a in df.api_references}
    attributed = set().union(*by_method.values()) if by_method else set()
    if attributed != inventory:
        raise _Refusal(
            R.TRANSFORMATION_PRECONDITION_FAILED,
            G.PRE_TRANSFORM,
            "per-method API attribution does not reproduce the Phase E DEX inventory "
            f"({len(attributed)} vs {len(inventory)}); the expected change cannot be declared",
        )
    target = (class_name, key)
    others = set().union(*(v for k, v in by_method.items() if k != target))
    pool = {s.value for s in inspection.strings if s.value}
    return key, by_method.get(target, set()) - others, pool


_ROWS = [
    ("source", "Source SHA", "matches the plan"),
    ("plan_id", "Plan ID", "exact match"),
    ("eligibility", "Eligibility", "ELIGIBLE"),
    ("before", "Target class before", "present"),
    ("after", "Target class after", "absent"),
    ("removed", "Classes removed", "1"),
    ("others", "Other classes removed", "0"),
    ("build", "Build", "success"),
    ("align", "Align", "success"),
    ("sign", "Sign", "success"),
    ("verify", "Signature verification", "success"),
    ("analysis", "Post-transform analysis", "sufficient"),
    ("semantic", "Unexpected semantic changes", "none"),
    ("original", "Original APK SHA", "unchanged"),
]

_CALL_SITE_ROWS = [
    ("source", "Source SHA", "matches the plan"),
    ("plan_id", "Plan ID", "exact match"),
    ("eligibility", "Eligibility", "ELIGIBLE"),
    ("before", "Original invocation before", "present at the planned location"),
    ("after", "Original invocation after", "gone from the planned location"),
    ("replacement", "Replacement invocation after", "exactly at the planned location"),
    ("removed", "Call sites changed", "1"),
    ("others", "Other instruction/method/class changes", "0"),
    ("build", "Build", "success"),
    ("align", "Align", "success"),
    ("sign", "Sign", "success"),
    ("verify", "Signature verification", "success"),
    ("analysis", "Post-transform analysis", "sufficient"),
    ("semantic", "Unexpected semantic changes", "none"),
    ("original", "Original APK SHA", "unchanged"),
]

_METHOD_ROWS = [
    ("source", "Source SHA", "matches the plan"),
    ("plan_id", "Plan ID", "exact match"),
    ("eligibility", "Eligibility", "ELIGIBLE"),
    ("before", "Target method before", "present"),
    ("after", "Target method after", "absent"),
    ("removed", "Methods removed", "1"),
    ("others", "Other method/class changes", "0"),
    ("build", "Build", "success"),
    ("align", "Align", "success"),
    ("sign", "Sign", "success"),
    ("verify", "Signature verification", "success"),
    ("analysis", "Post-transform analysis", "sufficient"),
    ("semantic", "Unexpected semantic changes", "none"),
    ("original", "Original APK SHA", "unchanged"),
]


def _matrix(
    facts: dict[str, tuple[str, bool | None]], transformation_id: str | None = None
) -> list[MatrixRow]:
    rows_spec = {"H-TRANS-002": _METHOD_ROWS, "H-TRANS-003": _CALL_SITE_ROWS}.get(
        transformation_id or "", _ROWS
    )
    rows = []
    for key, check, expected in rows_spec:
        actual, ok = facts.get(key, ("not reached", None))
        status = (
            CheckOutcome.NOT_RUN if ok is None else CheckOutcome.PASS if ok else CheckOutcome.FAIL
        )
        rows.append(MatrixRow(check=check, expected=expected, actual=actual, status=status))
    return rows


#: public names for H.4 (same functions H.3/H.5 use; no second implementation)
plan_id_for = _plan_id
removal_consequences = _consequences
method_removal_consequences = _method_consequences
