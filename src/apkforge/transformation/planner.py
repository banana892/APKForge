"""Deterministic transformation planning (Phase H.2).

::

    ReferenceAnalysisService (H.1, read-only)
            -> TargetEvidenceSelector   (target evidence set)
            -> EligibilityEvaluator     (state + reason codes)
            -> TransformationPlanner    (compact deterministic plan)
            -> TransformationPlan       [STOP: H.3 applies plans]

Plan ids hash only the APK SHA-256, transformation id, normalised target, parameters and
the H.1/H.2 schema versions; plans contain no timestamps, random ids or absolute paths.
Nothing here writes, rebuilds, signs or installs an APK.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.reference.models import Component
from apkforge.transformation.catalog import get_spec
from apkforge.transformation.conflicts import detect_conflicts
from apkforge.transformation.eligibility import EligibilityEvaluator, Evaluation
from apkforge.transformation.models import (
    PLANNING_SCHEMA_VERSION,
    ConflictRecord,
    DecisionReason,
    EligibilityState,
    PlanCondition,
    PlannedTransformChange,
    PlanningResult,
    ReasonDetail,
    RequirementCheck,
    TargetKind,
    TransformationDecision,
    TransformationPlan,
    TransformationRequest,
    TransformationTarget,
)
from apkforge.transformation.selector import TargetEvidenceSelector
from apkforge.transformation.targets import ParseError, parse_target, resolve_class, resolve_method

if TYPE_CHECKING:
    from apkforge.reference.models import ReferenceAnalysisResult
    from apkforge.reference.service import ReferenceAnalysisService
    from apkforge.transformation.models import TransformationSpec
    from apkforge.transformation.selector import TargetEvidenceSet

__all__ = [
    "H2_STATEMENT",
    "TransformationPlanner",
    "TransformationPlanningService",
    "decision_id_for",
]

H2_STATEMENT = (
    "H.2 determines whether a proposed transformation is supported by the available static "
    "evidence and produces a deterministic plan. It does not apply the transformation and "
    "does not establish that the target behavior is malicious."
)
H2_LIMITATIONS = [
    H2_STATEMENT,
    "Planning only: no APK is modified, rebuilt, aligned, signed or installed.",
    "Each request is evaluated against the original APK; requests in the same set are never "
    "assumed to have been applied.",
    "UNDETERMINED means the available analysis cannot establish eligibility; it is never "
    "treated as eligible.",
]

_STATEMENTS = {
    EligibilityState.ELIGIBLE: (
        "Every required evidence item and precondition is satisfied within the static scope. "
        "A plan was generated; it has not been applied."
    ),
    EligibilityState.CONDITIONALLY_ELIGIBLE: (
        "Required evidence is satisfied, but the listed condition(s) must be met before the "
        "plan may be applied. A plan was generated; it has not been applied."
    ),
    EligibilityState.REFUSED: (
        "The request conflicts with observed evidence or a safety rule. No plan was generated."
    ),
    EligibilityState.UNSUPPORTED: (
        "APKForge does not support this transformation for this target. No plan was generated."
    ),
    EligibilityState.UNDETERMINED: (
        "The available analysis is insufficient to establish eligibility. No plan was generated."
    ),
}


def decision_id_for(
    apk_sha256: str | None,
    transformation_id: str,
    target: str,
    parameters: dict[str, str],
    analysis_schema: int,
) -> str:
    """Stable hex id from the plan-defining inputs only."""
    key = json.dumps(
        {
            "apk_sha256": apk_sha256,
            "transformation_id": transformation_id,
            "target": target,
            "parameters": dict(sorted(parameters.items())),
            "analysis_schema": analysis_schema,
            "planning_schema": PLANNING_SCHEMA_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


class TransformationPlanner:
    """Pure planner over one H.1 result: requests in, decisions (and plans) out."""

    def __init__(self, result: ReferenceAnalysisResult) -> None:
        self.result = result
        self.selector = TargetEvidenceSelector(result)
        self.evaluator = EligibilityEvaluator(result)

    def plan(self, requests: list[TransformationRequest]) -> PlanningResult:
        parsed: list[tuple[TransformationSpec | None, TransformationTarget | ParseError]] = []
        for req in requests:
            spec = get_spec(req.transformation_id)
            if spec is None:
                parsed.append((None, ParseError(DecisionReason.UNKNOWN_TRANSFORMATION, "")))
            else:
                parsed.append((spec, parse_target(spec.target_type, req.target)))
        conflicts = detect_conflicts(
            [
                (
                    spec.id if spec else req.transformation_id,
                    None if isinstance(t, ParseError) else t,
                )
                for req, (spec, t) in zip(requests, parsed, strict=True)
            ]
        )
        decisions = [
            self._decide(req, spec, t, conflicts.get(i, []))
            for i, (req, (spec, t)) in enumerate(zip(requests, parsed, strict=True))
        ]
        records = {r.message: r for recs in conflicts.values() for r in recs}
        return PlanningResult(
            analysis_schema=self.result.schema_version,
            apk=self.result.apk,
            analysis_state=self.result.analysis_state,
            component_states=dict(sorted(self.result.component_states.items())),
            decisions=decisions,
            conflicts=[records[k] for k in sorted(records)],
            limitations=[*H2_LIMITATIONS, *self.result.limitations],
            errors=list(self.result.errors),
            original_unchanged=self.result.original_unchanged,
        )

    # -- one request -----------------------------------------------------------

    def _decide(
        self,
        req: TransformationRequest,
        spec: TransformationSpec | None,
        target: TransformationTarget | ParseError,
        conflicts: list[ConflictRecord],
    ) -> TransformationDecision:
        tid = spec.id if spec else req.transformation_id.strip()
        canonical = target.canonical if isinstance(target, TransformationTarget) else req.target
        did = decision_id_for(
            self.result.apk.sha256, tid, canonical, req.parameters, self.result.schema_version
        )
        if spec is None or isinstance(target, ParseError):
            if spec is None:
                code = DecisionReason.UNKNOWN_TRANSFORMATION
                msg = f"{tid!r} is not a catalogued transformation"
            else:
                assert isinstance(target, ParseError)
                code, msg = target.code, target.message
            reason = ReasonDetail(
                code=code, state=EligibilityState.UNSUPPORTED, requirement="target", message=msg
            )
            return self._final(did, tid, None, req, EligibilityState.UNSUPPORTED, [reason], [])

        ev = self.evaluator.start(spec)
        first = "class_exists" if spec.target_type is TargetKind.CLASS else "method_exists"
        res = resolve_class(target, self.selector.classes, self.selector.simple_names)
        method = None
        if res.code is None and target.kind is TargetKind.METHOD:
            assert res.defined is not None
            res = resolve_method(target, res.defined)
            method = res.method
        if res.code is not None:
            self._unresolved(ev, first, res.code, res.message)
            self._conflicts(ev, conflicts)
            return self._final(did, tid, target, req, ev.state, ev.reasons, ev.requirements)
        ev.ok(first)

        ts = self.selector.select(target, res.defined, method)
        if target.kind is TargetKind.CLASS:
            self.evaluator.evaluate_class(ev, ts)
        else:
            self.evaluator.evaluate_method(ev, ts, self.selector.classes)
        self._conflicts(ev, conflicts)
        return self._final(
            did, tid, target, req, ev.state, ev.reasons, ev.requirements, ts=ts, spec=spec
        )

    def _unresolved(self, ev: Evaluation, req: str, code: DecisionReason, message: str) -> None:
        if code is DecisionReason.TARGET_NOT_FOUND and not self.evaluator.definitions_complete:
            dex = self.result.component_state(Component.DEX)
            ev.fail(
                req,
                DecisionReason.ANALYSIS_INCOMPLETE,
                f"{message}; DEX analysis is {dex.value} and not every class definition "
                "was read, so the target may exist in unanalysed input",
            )
        else:
            ev.fail(req, code, message)

    @staticmethod
    def _conflicts(ev: Evaluation, conflicts: list[ConflictRecord]) -> None:
        req = "no_conflicting_transformation"
        for c in conflicts:
            ev.fail(req, DecisionReason.CONFLICTING_TRANSFORMATION, c.message)
        ev.ok(req)

    def _final(
        self,
        did: str,
        tid: str,
        target: TransformationTarget | None,
        req: TransformationRequest,
        state: EligibilityState,
        reasons: list[ReasonDetail],
        requirements: list[RequirementCheck],
        *,
        ts: TargetEvidenceSet | None = None,
        spec: TransformationSpec | None = None,
    ) -> TransformationDecision:
        summary = ts.summary() if ts is not None else None
        plan = None
        if state.plannable and spec is not None and target is not None and ts is not None:
            plan = self._plan(did, spec, target, req, state, reasons, requirements, ts)
        return TransformationDecision(
            decision_id=f"dec-{did}",
            transformation_id=tid,
            target=target,
            parameters=dict(sorted(req.parameters.items())),
            eligibility=state,
            reasons=reasons,
            requirements=requirements,
            target_evidence_summary=summary,
            plan=plan,
            statement=_STATEMENTS[state],
        )

    def _plan(
        self,
        did: str,
        spec: TransformationSpec,
        target: TransformationTarget,
        req: TransformationRequest,
        state: EligibilityState,
        reasons: list[ReasonDetail],
        requirements: list[RequirementCheck],
        ts: TargetEvidenceSet,
    ) -> TransformationPlan:
        dc = ts.defined
        assert dc is not None
        dex = dc.source_dex or "classes.dex"
        if target.kind is TargetKind.CLASS:
            changes = [
                PlannedTransformChange(
                    type="remove_class",
                    target=dc.name,
                    artifact=dc.source_file,
                    details={"dex": dex},
                )
            ]
            expected = [
                f"{dex}: class {dc.name} is no longer defined (decoded {dc.source_file} removed)",
                f"defined class count decreases by exactly 1 ({len(self.result.defined_classes)} "
                f"-> {len(self.result.defined_classes) - 1})",
                "no other DEX, manifest, resource, asset or native-library entry changes "
                "(signature files excepted)",
            ]
        else:
            m = ts.method
            assert m is not None
            changes = [
                PlannedTransformChange(
                    type="remove_method",
                    target=f"{dc.name}->{m.signature}",
                    artifact=dc.source_file,
                    details={
                        "dex": dex,
                        "declaration_line": str(m.source_line or ""),
                        "access_flags": " ".join(m.access_flags),
                    },
                )
            ]
            expected = [
                f"{dex}: {dc.name} no longer declares {m.signature}",
                f"{dc.name} method count decreases by exactly 1 ({len(dc.methods)} -> "
                f"{len(dc.methods) - 1}); every other declaration is unchanged",
                "no other class, manifest, resource, asset or native-library entry changes "
                "(signature files excepted)",
            ]
        conditions = [
            PlanCondition(code=r.code, description=r.message)
            for r in reasons
            if r.state is EligibilityState.CONDITIONALLY_ELIGIBLE
        ]
        return TransformationPlan(
            plan_id=f"plan-{did}",
            analysis_schema=self.result.schema_version,
            transformation_id=spec.id,
            apk=self.result.apk,
            target=target,
            parameters=dict(sorted(req.parameters.items())),
            eligibility=state,
            decision_reasons=reasons,
            target_evidence_summary=ts.summary(),
            preconditions=requirements,
            conditions=conditions,
            planned_changes=changes,
            expected_changes=expected,
            verification_requirements=list(spec.verification_requirements),
            risk=spec.risk,
            reversibility=spec.reversibility,
            compatibility_constraints=list(spec.compatibility_constraints),
            limitations=list(spec.limitations),
        )


class TransformationPlanningService:
    """Programmatic entry point: H.1 evidence in, :class:`PlanningResult` out.

    ``plan(apk, requests)`` runs the read-only H.1 analysis first; ``plan_from_result``
    plans over an existing :class:`ReferenceAnalysisResult`. Neither writes any file
    besides H.1's throwaway decode workspace, which H.1 deletes.
    """

    def __init__(self, reference_service: ReferenceAnalysisService | None = None) -> None:
        self._reference_service = reference_service

    def plan(
        self,
        apk: Path | str,
        requests: list[TransformationRequest],
        *,
        include_resources: bool = True,
    ) -> PlanningResult:
        from apkforge.reference.service import ReferenceAnalysisService

        path = Path(apk).expanduser().resolve()
        before = _sha256(path)
        svc = self._reference_service or ReferenceAnalysisService()
        result = svc.analyze(path, include_resources=include_resources)
        out = self.plan_from_result(result, requests)
        unchanged = _sha256(path) == before and result.original_unchanged is not False
        out.original_unchanged = unchanged
        if not unchanged:
            out.errors.append("input APK changed during planning (SHA-256 mismatch)")
        return out

    @staticmethod
    def plan_from_result(
        result: ReferenceAnalysisResult, requests: list[TransformationRequest]
    ) -> PlanningResult:
        return TransformationPlanner(result).plan(requests)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
