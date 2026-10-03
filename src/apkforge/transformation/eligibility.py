"""Eligibility evaluation for H-TRANS-001 / H-TRANS-002 (Phase H.2).

Every requirement of a :class:`TransformationSpec` is answered from a
:class:`TargetEvidenceSet`. A requirement is SATISFIED only by an established absence
(nothing observed *and* the relevant H.1 components COMPLETE); observed evidence or an
incomplete component produces a machine-readable :class:`DecisionReason`. The final state
is the strongest state any reason imposes (REFUSED > UNSUPPORTED > UNDETERMINED >
CONDITIONALLY_ELIGIBLE); ELIGIBLE requires every requirement SATISFIED.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from apkforge.reference.models import AnalysisState, Component, MatchBasis
from apkforge.transformation.models import (
    REASON_STATES,
    STATE_PRECEDENCE,
    DecisionReason,
    EligibilityState,
    ReasonDetail,
    RequirementCheck,
    RequirementStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from apkforge.reference.models import DefinedClass, Evidence, ReferenceAnalysisResult
    from apkforge.transformation.models import TransformationSpec
    from apkforge.transformation.selector import TargetEvidenceSet

__all__ = [
    "METADATA_ANNOTATIONS",
    "EligibilityEvaluator",
    "Evaluation",
    "definitions_complete",
]

R = DecisionReason
#: evidence ids kept per reason
REASON_EVIDENCE_LIMIT = 10

#: manifest elements that declare an app component
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
#: annotations that only carry compiler/debug metadata (no runtime dispatch)
METADATA_ANNOTATIONS = {
    "kotlin.Metadata",
    "kotlin.coroutines.jvm.internal.DebugMetadata",
    "kotlin.jvm.internal.SourceDebugExtension",
}
KOTLIN_METADATA = "kotlin.Metadata"
OBJECT_METHODS = {
    ("equals", "(Ljava/lang/Object;)Z"),
    ("hashCode", "()I"),
    ("toString", "()Ljava/lang/String;"),
    ("finalize", "()V"),
    ("clone", "()Ljava/lang/Object;"),
}
SERIALIZATION_HOOKS = {
    ("writeObject", "(Ljava/io/ObjectOutputStream;)V"),
    ("readObject", "(Ljava/io/ObjectInputStream;)V"),
    ("readObjectNoData", "()V"),
    ("writeReplace", "()Ljava/lang/Object;"),
    ("readResolve", "()Ljava/lang/Object;"),
}
VIEW_HANDLER = "(Landroid/view/View;)V"

_STATUS_ORDER = (
    RequirementStatus.VIOLATED,
    RequirementStatus.UNSUPPORTED,
    RequirementStatus.NOT_ESTABLISHED,
    RequirementStatus.CONDITIONAL,
    RequirementStatus.SATISFIED,
    RequirementStatus.NOT_EVALUATED,
)
_STATE_STATUS = {
    EligibilityState.REFUSED: RequirementStatus.VIOLATED,
    EligibilityState.UNSUPPORTED: RequirementStatus.UNSUPPORTED,
    EligibilityState.UNDETERMINED: RequirementStatus.NOT_ESTABLISHED,
    EligibilityState.CONDITIONALLY_ELIGIBLE: RequirementStatus.CONDITIONAL,
}


def definitions_complete(result: ReferenceAnalysisResult) -> bool:
    """Every smali file had its class header read and no decoded DEX is missing, so a
    class absent from ``defined_classes`` is not merely hidden in unanalysed input."""
    dex = next((c for c in result.components if c.component == Component.DEX.value), None)
    if dex is None or dex.state in (AnalysisState.UNKNOWN, AnalysisState.NOT_ANALYZED):
        return False
    return dex.inputs_analyzed == dex.inputs_total and all(
        s.state in (AnalysisState.COMPLETE, AnalysisState.PARTIAL) for s in dex.subcomponents
    )


class Evaluation:
    """Collects requirement outcomes and reasons for one decision."""

    def __init__(self, requirements: Sequence[str], descriptions: dict[str, str]) -> None:
        self.checks: dict[str, RequirementCheck] = {
            r: RequirementCheck(
                id=r, description=descriptions.get(r, r), status=RequirementStatus.NOT_EVALUATED
            )
            for r in requirements
        }
        self.reasons: list[ReasonDetail] = []

    def fail(
        self,
        requirement: str,
        code: DecisionReason,
        message: str,
        evidence: Sequence[Evidence] = (),
    ) -> None:
        state = REASON_STATES[code]
        check = self.checks[requirement]
        status = _STATE_STATUS[state]
        if check.status is RequirementStatus.NOT_EVALUATED or _STATUS_ORDER.index(
            status
        ) < _STATUS_ORDER.index(check.status):
            check.status = status
        if code not in check.reasons:
            check.reasons.append(code)
        self.reasons.append(
            ReasonDetail(
                code=code,
                state=state,
                requirement=requirement,
                message=message,
                evidence_ids=[e.evidence_id for e in evidence[:REASON_EVIDENCE_LIMIT]],
                evidence_count=len(evidence),
            )
        )

    def ok(self, requirement: str) -> None:
        check = self.checks[requirement]
        if check.status is RequirementStatus.NOT_EVALUATED:
            check.status = RequirementStatus.SATISFIED

    @property
    def state(self) -> EligibilityState:
        states = {r.state for r in self.reasons}
        for s in STATE_PRECEDENCE:
            if s in states:
                return s
        if any(c.status is not RequirementStatus.SATISFIED for c in self.checks.values()):
            # defensive: an unanswered requirement can never become ELIGIBLE
            return EligibilityState.UNDETERMINED
        return EligibilityState.ELIGIBLE

    @property
    def requirements(self) -> list[RequirementCheck]:
        return list(self.checks.values())


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _sources(evs: Sequence[Evidence], limit: int = 5) -> str:
    names = sorted({e.source_class or e.source_file for e in evs})
    more = f" (+{len(names) - limit} more)" if len(names) > limit else ""
    return ", ".join(names[:limit]) + more


class EligibilityEvaluator:
    """Applies the catalog rules to a target evidence set (pure; no I/O)."""

    DESCRIPTIONS: ClassVar[dict[str, str]] = {
        "class_exists": "target class is defined exactly once",
        "method_exists": "target method is declared exactly once",
        "dex_analysis_complete": "DEX analysis (and the target's own file) is COMPLETE",
        "no_callers": "no other class references the class",
        "no_type_references": "no type reference (signatures, fields, casts, annotations)",
        "no_member_references": "no method/field access through the class",
        "no_constructor_references": "no constructor invocation",
        "no_const_class_references": "no const-class load of the class",
        "no_string_references": "no string constant names the target",
        "no_reflection_target": "no reflection resolved to, or possibly reaching, the target",
        "no_dynamic_code_loading": "no dynamic code loading",
        "no_dynamic_invocation": "no dynamic code loading / unresolved dynamic invocation",
        "no_native_dependency": "no native method and no unanalysed native code",
        "no_native_boundary": "no unanalysed native code that could call the method",
        "no_manifest_reference": "no manifest reference",
        "no_resource_reference": "no resource / asset reference",
        "no_conflicting_transformation": "no other request in the set overlaps the target",
        "ordinary_method": "an ordinary concrete method (not constructor/abstract/native...)",
        "no_call_sites": "no call site on the class or a defined subclass",
        "no_override_relationship": "neither overrides nor is overridden",
        "no_annotation_driven_access": "no runtime annotation that frameworks dispatch on",
        "no_resource_method_reference": "not an android:onClick-shaped handler",
        "metadata_consistency": "no compiler metadata that would describe the removed member",
    }

    def __init__(self, result: ReferenceAnalysisResult) -> None:
        self.result = result
        self.definitions_complete = definitions_complete(result)

    def start(self, spec: TransformationSpec) -> Evaluation:
        return Evaluation(spec.preconditions, self.DESCRIPTIONS)

    # -- shared checks -----------------------------------------------------------

    def _code_category(
        self,
        ev: Evaluation,
        ts: TargetEvidenceSet,
        requirement: str,
        category: str,
        code: DecisionReason,
        what: str,
    ) -> None:
        evs = ts.categories.get(category, [])
        if evs:
            ev.fail(
                requirement,
                code,
                f"{_plural(len(evs), what)} from {_sources(evs)}",
                evs,
            )
        elif ts.state(category) is not AnalysisState.COMPLETE:
            ev.fail(
                requirement,
                R.DEX_ANALYSIS_INCOMPLETE,
                f"no {what} observed, but DEX analysis is {ts.state(category).value}; "
                "absence is not established",
            )
        else:
            ev.ok(requirement)

    def _dex(self, ev: Evaluation, ts: TargetEvidenceSet) -> None:
        dex = ts.component_states[Component.DEX.value]
        if dex is not AnalysisState.COMPLETE:
            ev.fail(
                "dex_analysis_complete",
                R.DEX_ANALYSIS_INCOMPLETE,
                f"DEX analysis is {dex.value}",
            )
        if ts.defined is not None and ts.defined.analysis_state is not AnalysisState.COMPLETE:
            ev.fail(
                "dex_analysis_complete",
                R.TARGET_DEFINITION_INCOMPLETE,
                f"{ts.defined.source_file} (defining {ts.defined.name}) is "
                f"{ts.defined.analysis_state.value}",
            )
        ev.ok("dex_analysis_complete")

    def _strings(self, ev: Evaluation, ts: TargetEvidenceSet, what: str) -> None:
        evs = ts.categories.get("string_mentions", [])
        if evs:
            ev.fail(
                "no_string_references",
                R.STRING_REFERENCE_UNRESOLVED,
                f"{_plural(len(evs), 'string constant')} name {what} ({_sources(evs)}); "
                "indirect evidence, not a direct reference, but its use is not resolved",
                evs,
            )
        elif ts.state("string_mentions") is not AnalysisState.COMPLETE:
            ev.fail(
                "no_string_references",
                R.DEX_ANALYSIS_INCOMPLETE,
                "string constants were not completely analysed",
            )
        else:
            ev.ok("no_string_references")

    def _reflection(self, ev: Evaluation, ts: TargetEvidenceSet, what: str) -> None:
        req = "no_reflection_target"
        targeting = ts.categories.get("reflection_targeting", [])
        if targeting:
            ev.fail(
                req,
                R.REFLECTION_TARGET_PRESENT,
                f"{_plural(len(targeting), 'reflection call')} statically resolved to {what} "
                f"({_sources(targeting)})",
                targeting,
            )
        name_match = ts.categories.get("reflection_name_match", [])
        if name_match:
            ev.fail(
                req,
                R.REFLECTION_TARGET_UNKNOWN,
                f"{_plural(len(name_match), 'reflection call')} name the member on an "
                "unresolved class",
                name_match,
            )
        unresolved = ts.categories.get("reflection_unresolved", [])
        if unresolved:
            ev.fail(
                req,
                R.REFLECTION_TARGET_UNKNOWN,
                f"{_plural(len(unresolved), 'reflection call')} with a statically unknown "
                "target exist in the APK; any of them may reach the target",
                unresolved,
            )
        state = ts.component_states[Component.REFLECTION.value]
        if not unresolved and state is not AnalysisState.COMPLETE:
            ev.fail(
                req,
                R.REFLECTION_ANALYSIS_INCOMPLETE,
                f"reflection analysis is {state.value}",
            )
        ev.ok(req)

    def _dynamic_loading(self, ev: Evaluation, ts: TargetEvidenceSet, requirement: str) -> None:
        loaders = ts.categories.get("dynamic_code_loading", [])
        if loaders:
            ev.fail(
                requirement,
                R.DYNAMIC_CODE_LOADING_PRESENT,
                f"{_plural(len(loaders), 'class loader')} created ({_sources(loaders)}); "
                "code they load is invisible to static analysis",
                loaders,
            )
        elif ts.component_states[Component.DEX.value] is not AnalysisState.COMPLETE:
            ev.fail(
                requirement,
                R.DEX_ANALYSIS_INCOMPLETE,
                "dynamic-loading indicators were not completely analysed",
            )
        else:
            ev.ok(requirement)

    def _native_state(self, ev: Evaluation, ts: TargetEvidenceSet, requirement: str) -> None:
        for comp in (Component.NATIVE_INDICATORS, Component.NATIVE_CODE):
            state = ts.component_states[comp.value]
            if state is not AnalysisState.COMPLETE:
                n = len(self.result.bundled_native_libraries)
                ev.fail(
                    requirement,
                    R.NATIVE_DEPENDENCY_UNKNOWN,
                    f"{comp.value} analysis is {state.value} ({_plural(n, 'bundled .so')}); "
                    "JNI code can reach Java classes and methods without static evidence",
                )
        ev.ok(requirement)

    # -- H-TRANS-001 -------------------------------------------------------------

    def evaluate_class(self, ev: Evaluation, ts: TargetEvidenceSet) -> None:
        cls = ts.target.class_name
        self._dex(ev, ts)
        self._code_category(
            ev, ts, "no_callers", "class_references", R.CLASS_CALLER_PRESENT, "class reference"
        )
        self._code_category(
            ev,
            ts,
            "no_type_references",
            "type_references",
            R.TYPE_REFERENCE_PRESENT,
            "type reference",
        )
        self._code_category(
            ev,
            ts,
            "no_member_references",
            "method_references",
            R.METHOD_CALLER_PRESENT,
            "method call",
        )
        self._code_category(
            ev,
            ts,
            "no_member_references",
            "field_references",
            R.FIELD_REFERENCE_PRESENT,
            "field access",
        )
        self._code_category(
            ev,
            ts,
            "no_constructor_references",
            "constructor_references",
            R.CONSTRUCTOR_REFERENCE_PRESENT,
            "constructor call",
        )
        self._code_category(
            ev,
            ts,
            "no_const_class_references",
            "const_class_references",
            R.CONST_CLASS_REFERENCE_PRESENT,
            "const-class load",
        )
        self._strings(ev, ts, cls)
        self._reflection(ev, ts, cls)
        self._dynamic_loading(ev, ts, "no_dynamic_code_loading")

        native = ts.categories.get("native_declared", [])
        if native:
            ev.fail(
                "no_native_dependency",
                R.NATIVE_METHOD_DECLARED,
                f"{cls} declares {_plural(len(native), 'native method')}; removing JNI-bound "
                "code is not supported",
                native,
            )
        self._native_state(ev, ts, "no_native_dependency")

        self._manifest(ev, ts)
        self._resources(ev, ts)

    def _manifest(self, ev: Evaluation, ts: TargetEvidenceSet) -> None:
        req = "no_manifest_reference"
        evs = ts.categories.get("manifest_references", [])
        component = [e for e in evs if e.definitive and e.instruction in COMPONENT_TAGS]
        other = [e for e in evs if e.definitive and e.instruction not in COMPONENT_TAGS]
        textual = [e for e in evs if not e.definitive]
        if component:
            tags = sorted({f"<{e.instruction} {e.context}>" for e in component})
            ev.fail(
                req,
                R.MANIFEST_COMPONENT_REFERENCE,
                f"declared by {', '.join(tags)}; disabling a component is a Phase G "
                "remediation, not part of this transformation",
                component,
            )
        if other:
            tags = sorted({f"<{e.instruction} {e.context}>" for e in other})
            ev.fail(req, R.MANIFEST_REFERENCE_PRESENT, f"named by {', '.join(tags)}", other)
        if textual:
            ev.fail(
                req,
                R.MANIFEST_TEXTUAL_MATCH,
                f"{_plural(len(textual), 'manifest value')} equal the class name (textual "
                "match; use not established)",
                textual,
            )
        state = ts.state("manifest_references")
        if state is not AnalysisState.COMPLETE:
            ev.fail(req, R.MANIFEST_ANALYSIS_INCOMPLETE, f"manifest analysis is {state.value}")
        ev.ok(req)

    def _resources(self, ev: Evaluation, ts: TargetEvidenceSet) -> None:
        req = "no_resource_reference"
        evs = ts.categories.get("resource_references", [])
        structural = [e for e in evs if e.definitive]
        textual = [e for e in evs if not e.definitive]
        if structural:
            bases = sorted({(e.match_basis or MatchBasis.EXACT_VALUE).value for e in structural})
            ev.fail(
                req,
                R.RESOURCE_REFERENCE_PRESENT,
                f"{_plural(len(structural), 'structural resource reference')} "
                f"({', '.join(bases)}) in {_sources(structural)}",
                structural,
            )
        if textual:
            ev.fail(
                req,
                R.RESOURCE_TEXTUAL_MATCH,
                f"{_plural(len(textual), 'textual match')} in {_sources(textual)}; not "
                "treated as a definitive reference, but its use is not established",
                textual,
            )
        state = ts.state("resource_references")
        if state is not AnalysisState.COMPLETE:
            comps = ", ".join(
                f"{c} {ts.component_states[c].value}"
                for c in (Component.RESOURCES.value, Component.ASSETS.value)
                if ts.component_states[c] is not AnalysisState.COMPLETE
            )
            ev.fail(req, R.RESOURCE_ANALYSIS_INCOMPLETE, f"resource analysis incomplete: {comps}")
        ev.ok(req)

    # -- H-TRANS-002 -------------------------------------------------------------

    def evaluate_method(
        self, ev: Evaluation, ts: TargetEvidenceSet, classes: dict[str, DefinedClass]
    ) -> None:
        m = ts.method
        dc = ts.defined
        assert m is not None and dc is not None
        flags = set(m.access_flags)
        class_flags = set(dc.access_flags)
        label = f"{dc.name}->{m.signature}"
        self._dex(ev, ts)

        # method shape
        shape = "ordinary_method"
        if m.name == "<clinit>":
            ev.fail(shape, R.CLASS_INITIALIZER, f"{label} is the class initializer")
        elif m.name == "<init>":
            ev.fail(shape, R.CONSTRUCTOR_METHOD, f"{label} is a constructor")
        if "abstract" in flags:
            ev.fail(shape, R.ABSTRACT_METHOD, f"{label} is abstract")
        if "interface" in class_flags:
            ev.fail(shape, R.INTERFACE_METHOD, f"{dc.name} is an interface")
        if "native" in flags:
            ev.fail(shape, R.NATIVE_METHOD, f"{label} is native (JNI-bound)")
        generated = sorted(flags & {"bridge", "synthetic"})
        if generated:
            ev.fail(
                shape, R.SYNTHETIC_METHOD, f"{label} is compiler-generated ({', '.join(generated)})"
            )
        if "enum" in class_flags and (
            (m.name == "values" and m.descriptor.startswith("()["))
            or (m.name == "valueOf" and m.descriptor.startswith("(Ljava/lang/String;)"))
        ):
            ev.fail(
                shape,
                R.ENUM_IMPLICIT_METHOD,
                f"{label} is an implicit enum method (called reflectively by the runtime)",
            )
        if (m.name, m.descriptor) in SERIALIZATION_HOOKS:
            ev.fail(
                shape,
                R.SERIALIZATION_HOOK_METHOD,
                f"{label} is a Java serialization hook (invoked reflectively)",
            )
        ev.ok(shape)

        self._code_category(
            ev, ts, "no_call_sites", "call_sites", R.METHOD_CALLER_PRESENT, "call site"
        )
        self._overrides(ev, ts, classes)
        self._reflection(ev, ts, label)
        self._dynamic_loading(ev, ts, "no_dynamic_invocation")
        self._native_state(ev, ts, "no_native_boundary")

        runtime = sorted(
            a
            for a in m.annotations
            if a not in METADATA_ANNOTATIONS and not a.startswith("dalvik.annotation.")
        )
        if runtime:
            ev.fail(
                "no_annotation_driven_access",
                R.ANNOTATION_DRIVEN_ACCESS_POSSIBLE,
                f"{label} is annotated with {', '.join(runtime)}; frameworks may invoke "
                "annotated methods reflectively without static call sites",
            )
        ev.ok("no_annotation_driven_access")

        if "public" in flags and m.descriptor == VIEW_HANDLER:
            ev.fail(
                "no_resource_method_reference",
                R.RESOURCE_METHOD_REFERENCE_NOT_ANALYZED,
                f"{label} has the android:onClick handler shape; method names in layouts "
                "are not indexed by H.1",
            )
        ev.ok("no_resource_method_reference")

        self._strings(ev, ts, f"the method name {m.name!r}")

        if KOTLIN_METADATA in dc.annotations:
            ev.fail(
                "metadata_consistency",
                R.KOTLIN_METADATA_UPDATE_REQUIRED,
                f"{dc.name} carries kotlin.Metadata, which still declares the function after "
                "removal; H.3 must rewrite the metadata or the approver must accept stale "
                "Kotlin metadata (affects kotlin-reflect consumers only)",
            )
        ev.ok("metadata_consistency")

    def _overrides(
        self, ev: Evaluation, ts: TargetEvidenceSet, classes: dict[str, DefinedClass]
    ) -> None:
        req = "no_override_relationship"
        m = ts.method
        dc = ts.defined
        assert m is not None and dc is not None
        flags = set(m.access_flags)
        if m.name in ("<init>", "<clinit>") or flags & {"private", "static"}:
            ev.ok(req)  # not virtual: no override relationship possible
            return
        key = (m.name, m.descriptor)
        overridden = [
            s
            for s in ts.supertypes
            if any(
                (x.name, x.descriptor) == key and not {"private", "static"} & set(x.access_flags)
                for x in classes[s].methods
            )
        ]
        if key in OBJECT_METHODS:
            overridden.append("java.lang.Object")
        if overridden:
            ev.fail(
                req,
                R.METHOD_OVERRIDES,
                f"{dc.name}->{m.signature} overrides/implements {', '.join(sorted(overridden))}",
            )
        overriders = [
            s
            for s in ts.subtypes
            if any(
                (x.name, x.descriptor) == key and "static" not in x.access_flags
                for x in classes[s].methods
            )
        ]
        if overriders:
            ev.fail(
                req,
                R.METHOD_OVERRIDDEN,
                f"overridden by {', '.join(overriders[:5])}"
                + (f" (+{len(overriders) - 5} more)" if len(overriders) > 5 else ""),
            )
        if ts.unresolved_supertypes:
            missing = ts.unresolved_supertypes
            ev.fail(
                req,
                R.OVERRIDE_RELATIONSHIP_UNRESOLVED,
                f"supertype(s) not defined in the APK: {', '.join(missing[:5])}"
                + (f" (+{len(missing) - 5} more)" if len(missing) > 5 else "")
                + "; whether the method overrides one of their methods cannot be resolved",
            )
        ev.ok(req)
