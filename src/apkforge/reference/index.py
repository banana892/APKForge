"""Deterministic queries over an H.1 :class:`ReferenceAnalysisResult`.

Every query returns a :class:`QueryResult` carrying the states of the components that
could have produced (or hidden) the evidence asked for. An empty result is only an
established absence when that state is ``COMPLETE``.

Relevant components per query:

- class / method / field / type / constructor / const-class: ``dex``, ``reflection``
  (dynamic resolution may reach the target) and ``native_code`` (JNI may reach it)
- strings: ``dex``; reflection: ``dex``, ``reflection``
- native: ``dex``, ``native_indicators``, ``native_code``
- manifest: ``manifest``; resources: ``resources``, ``assets``
- :meth:`ReferenceIndex.assess_absence`: every component
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING

from apkforge.reference.models import (
    AbsenceAssessment,
    AbsenceConclusion,
    AnalysisState,
    Component,
    Evidence,
    QueryResult,
    ReferenceKind,
    combine_states,
)
from apkforge.reference.smali import normalize_class_name

if TYPE_CHECKING:
    from collections.abc import Iterable

    from apkforge.reference.models import ReferenceAnalysisResult

__all__ = ["ReferenceIndex"]

_CODE = (Component.DEX, Component.REFLECTION, Component.NATIVE_CODE)
_ALL = tuple(Component)


def _sorted(evs: Iterable[Evidence]) -> list[Evidence]:
    return sorted(evs, key=Evidence.sort_key)


class ReferenceIndex:
    """Lookup tables built once from a result; all answers are sorted deterministically."""

    def __init__(self, result: ReferenceAnalysisResult) -> None:
        self.result = result
        self._by_target: dict[tuple[ReferenceKind, str], list[Evidence]] = defaultdict(list)
        self._strings: dict[str, list[Evidence]] = defaultdict(list)
        for ev in result.all_evidence():
            if ev.target_class is not None:
                self._by_target[(ev.kind, ev.target_class)].append(ev)
            if ev.kind is ReferenceKind.STRING_REFERENCE and ev.string_value is not None:
                self._strings[ev.string_value].append(ev)
        self.defined_classes = {c.name for c in result.defined_classes}
        self._invocations: dict[tuple[str, str], list[Evidence]] | None = None

    # -- helpers ---------------------------------------------------------------

    def _states(self, components: Iterable[Component]) -> dict[str, AnalysisState]:
        return {c.value: self.result.component_state(c) for c in components}

    def _query(
        self,
        query: str,
        target: str,
        evidence: Iterable[Evidence],
        components: Iterable[Component],
    ) -> QueryResult:
        states = self._states(components)
        return QueryResult(
            query=query,
            target=target,
            analysis_state=combine_states(states.values()),
            component_states=states,
            evidence=_sorted(evidence),
        )

    def _targeting(
        self, kind: ReferenceKind, cls: str, *, include_self: bool = True
    ) -> list[Evidence]:
        evs = self._by_target.get((kind, cls), [])
        return evs if include_self else [e for e in evs if e.source_class != cls]

    # -- raw lookups (no state attached; callers must apply completeness) ---------

    def evidence_targeting(self, kind: ReferenceKind, class_name: str) -> list[Evidence]:
        """Indexed records of *kind* whose ``target_class`` is *class_name* (unsorted,
        self-references included). O(matches); never traverses the whole index."""
        return list(self._by_target.get((kind, normalize_class_name(class_name)), ()))

    def invocations_in(self, source_class: str, source_method: str) -> list[Evidence]:
        """Invocation records (method and constructor references) inside one method, in
        source order. *source_method* is ``name`` + smali proto (``run(I)V``). The table is
        built once, lazily (schema 3; used by Phase H.6 call-site planning)."""
        if self._invocations is None:
            table: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
            for ev in self.result.references:
                if (
                    ev.kind in (ReferenceKind.METHOD_REFERENCE, ReferenceKind.CONSTRUCTOR_REFERENCE)
                    and ev.source_class is not None
                    and ev.source_method is not None
                ):
                    table[(ev.source_class, ev.source_method)].append(ev)
            for evs in table.values():
                evs.sort(key=lambda e: (e.source_file, e.source_line or 0))
            self._invocations = dict(table)
        return list(self._invocations.get((normalize_class_name(source_class), source_method), ()))

    def string_values(self) -> Iterable[tuple[str, list[Evidence]]]:
        """Distinct string constants with the records that load them."""
        return self._strings.items()

    # -- queries ---------------------------------------------------------------

    def find_class_references(self, class_name: str, *, include_self: bool = False) -> QueryResult:
        """Instruction-level class edges (invoke owner, field owner, new-instance, casts,
        const-class, catch, super/implements). Self-references excluded by default."""
        cls = normalize_class_name(class_name)
        evs = self._targeting(ReferenceKind.CLASS_REFERENCE, cls, include_self=include_self)
        return self._query("find_class_references", cls, evs, _CODE)

    def callers_of(self, class_name: str) -> list[str]:
        """Classes (other than itself) observed referencing *class_name*."""
        res = self.find_class_references(class_name)
        return sorted({e.source_class for e in res.evidence if e.source_class})

    def find_method_references(
        self, class_name: str, method_name: str, signature: str | None = None
    ) -> QueryResult:
        """Invocations of ``class.method``; *signature* is the proto (``(I)V``) or None.

        ``<init>`` returns constructor references."""
        cls = normalize_class_name(class_name)
        kind = (
            ReferenceKind.CONSTRUCTOR_REFERENCE
            if method_name == "<init>"
            else ReferenceKind.METHOD_REFERENCE
        )
        evs = [
            e
            for e in self._targeting(kind, cls)
            if e.member_name == method_name and (signature is None or e.descriptor == signature)
        ]
        label = f"{cls}.{method_name}{signature or ''}"
        return self._query("find_method_references", label, evs, _CODE)

    def find_constructor_references(
        self, class_name: str, signature: str | None = None
    ) -> QueryResult:
        return self.find_method_references(class_name, "<init>", signature)

    def find_field_references(
        self, class_name: str, field_name: str, signature: str | None = None
    ) -> QueryResult:
        """Field accesses; *signature* is the field type descriptor (``I``) or None."""
        cls = normalize_class_name(class_name)
        evs = [
            e
            for e in self._targeting(ReferenceKind.FIELD_REFERENCE, cls)
            if e.member_name == field_name and (signature is None or e.descriptor == signature)
        ]
        label = f"{cls}.{field_name}" + (f":{signature}" if signature else "")
        return self._query("find_field_references", label, evs, _CODE)

    def find_type_references(self, type_name: str, *, include_self: bool = False) -> QueryResult:
        """Every mention of the type: signatures, operands, casts, arrays, annotations..."""
        cls = normalize_class_name(type_name)
        evs = self._targeting(ReferenceKind.TYPE_REFERENCE, cls, include_self=include_self)
        return self._query("find_type_references", cls, evs, _CODE)

    def find_const_class_references(self, class_name: str) -> QueryResult:
        cls = normalize_class_name(class_name)
        evs = self._targeting(ReferenceKind.CONST_CLASS_REFERENCE, cls)
        return self._query("find_const_class_references", cls, evs, _CODE)

    def find_string_references(self, value: str, *, contains: bool = False) -> QueryResult:
        if contains:
            evs = [e for v, lst in self._strings.items() if value in v for e in lst]
        else:
            evs = list(self._strings.get(value, []))
        return self._query("find_string_references", value, evs, (Component.DEX,))

    def find_reflection_evidence(self, target: str | None = None) -> QueryResult:
        """Reflection indicators; with *target*, those resolved to that class/member."""
        evs = self.result.reflection
        if target is not None:
            cls = normalize_class_name(target)
            evs = [
                e
                for e in evs
                if target in (e.target, e.member_name) or e.target_class in (cls, target)
            ]
        return self._query(
            "find_reflection_evidence",
            target or "*",
            evs,
            (Component.DEX, Component.REFLECTION),
        )

    def find_native_dependencies(self, class_name: str | None = None) -> QueryResult:
        """Native methods declared by, and library loads performed in, *class_name*."""
        evs = self.result.native
        if class_name is not None:
            cls = normalize_class_name(class_name)
            evs = [e for e in evs if cls in (e.target_class, e.source_class)]
        return self._query(
            "find_native_dependencies",
            class_name or "*",
            evs,
            (Component.DEX, Component.NATIVE_INDICATORS, Component.NATIVE_CODE),
        )

    def find_manifest_references(self, target: str) -> QueryResult:
        """Manifest entries naming the class (or provider authority) *target*."""
        cls = normalize_class_name(target)
        evs = [
            e
            for e in self.result.manifest
            if target == e.target or cls in (e.target, e.target_class)
        ]
        return self._query("find_manifest_references", target, evs, (Component.MANIFEST,))

    def find_resource_references(self, target: str) -> QueryResult:
        """res/ and assets/ mentions of a class or authority (structural and textual)."""
        cls = normalize_class_name(target)
        evs = [
            e for e in self.result.resources if e.target in (target, cls) or e.target_class == cls
        ]
        return self._query(
            "find_resource_references",
            target,
            evs,
            (Component.RESOURCES, Component.ASSETS),
        )

    # -- absence ---------------------------------------------------------------

    def _string_mentions(self, cls: str) -> list[Evidence]:
        pats = [
            re.compile(r"(?<![\w$.])" + re.escape(cls) + r"(?![\w$])"),
            re.compile(r"(?<![\w$/])" + re.escape(cls.replace(".", "/")) + r"(?![\w$])"),
        ]
        return [
            e
            for v, lst in self._strings.items()
            if any(p.search(v) for p in pats)
            for e in lst
            if e.source_class != cls
        ]

    def assess_absence(self, class_name: str) -> AbsenceAssessment:
        """Is anything (outside the class itself) observed referencing *class_name*?

        Absence is established only when nothing is observed — no structural reference
        and no indirect hint — and every component is COMPLETE. Even then the statement
        is limited to static analysis of this APK.
        """
        cls = normalize_class_name(class_name)
        definitive: list[Evidence] = []
        indirect: list[Evidence] = []
        for ev in self.result.all_evidence():
            if ev.source_class == cls or ev.kind is ReferenceKind.STRING_REFERENCE:
                continue
            if ev.target_class != cls and ev.target != cls:
                continue
            (definitive if ev.definitive else indirect).append(ev)
        indirect.extend(self._string_mentions(cls))
        states = self._states(_ALL)
        overall = combine_states(states.values())
        reasons = [
            f"{name} analysis is {state.value}"
            for name, state in states.items()
            if state is not AnalysisState.COMPLETE
        ]
        if cls not in self.defined_classes:
            reasons.append(f"{cls} is not defined in the analysed smali")

        if definitive:
            conclusion = AbsenceConclusion.REFERENCES_OBSERVED
            statement = f"{len(definitive)} structural reference(s) to {cls} observed."
        elif indirect:
            conclusion = AbsenceConclusion.ONLY_INDIRECT_EVIDENCE
            statement = (
                f"No structural reference to {cls} observed, but {len(indirect)} indirect "
                "item(s) (strings, reflection or textual matches) mention it; "
                "reference absence cannot be established."
            )
        elif overall is not AnalysisState.COMPLETE:
            conclusion = AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
            statement = (
                f"No references to {cls} observed, but analysis is {overall.value} "
                f"({'; '.join(reasons)}); reference absence cannot yet be established."
            )
        else:
            conclusion = AbsenceConclusion.NO_REFERENCES_WITHIN_SCOPE
            statement = (
                f"No references to {cls} observed and every component is COMPLETE. This "
                "covers static analysis of this APK only; it does not establish runtime "
                "behaviour."
            )
        return AbsenceAssessment(
            target=cls,
            conclusion=conclusion,
            absence_established=conclusion is AbsenceConclusion.NO_REFERENCES_WITHIN_SCOPE,
            analysis_state=overall,
            component_states=states,
            definitive_references=_sorted(definitive),
            indirect_evidence=_sorted(indirect),
            reasons=reasons,
            statement=statement,
        )
