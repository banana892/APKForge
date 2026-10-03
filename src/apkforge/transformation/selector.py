"""Target evidence extraction (Phase H.2).

``Full H.1 index -> target query -> TargetEvidenceSet -> eligibility -> compact plan``

:class:`TargetEvidenceSelector` builds a few small lookup tables once per H.1 result
(class hierarchy, reflection/native/manifest/resource records by class, string tokens)
and then answers each target with dictionary lookups. It never walks the full evidence
list per target, so evaluating many targets does not multiply H.1's cost.

The selected set holds only the records relevant to one decision, each with its H.1
provenance (``evidence_id``, source file/line) intact.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkforge.reference.models import (
    AnalysisState,
    Component,
    Evidence,
    ReferenceKind,
    ResolutionStatus,
    combine_states,
)
from apkforge.transformation.models import (
    AbsenceStatus,
    CategorySummary,
    TargetEvidenceSummary,
    TargetKind,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from apkforge.reference.models import DefinedClass, DefinedMethod, ReferenceAnalysisResult
    from apkforge.transformation.models import TransformationTarget

__all__ = [
    "OBJECT",
    "TargetEvidenceSelector",
    "TargetEvidenceSet",
]

OBJECT = "java.lang.Object"
#: evidence ids / source classes kept per category in a plan summary
SUMMARY_LIMIT = 10

_TOKEN = re.compile(r"[A-Za-z_$][\w$]*(?:[./][A-Za-z_$][\w$]*)+")
_METHOD_ENUMERATION = {"java.lang.Class.getMethods", "java.lang.Class.getDeclaredMethods"}

#: category -> components whose completeness its absence depends on
CATEGORY_COMPONENTS: dict[str, tuple[Component, ...]] = {
    "class_references": (Component.DEX,),
    "type_references": (Component.DEX,),
    "method_references": (Component.DEX,),
    "field_references": (Component.DEX,),
    "constructor_references": (Component.DEX,),
    "const_class_references": (Component.DEX,),
    "call_sites": (Component.DEX,),
    "string_mentions": (Component.DEX,),
    "reflection_targeting": (Component.DEX, Component.REFLECTION),
    "reflection_name_match": (Component.DEX, Component.REFLECTION),
    "reflection_unresolved": (Component.DEX, Component.REFLECTION),
    "dynamic_code_loading": (Component.DEX,),
    "native_declared": (Component.DEX, Component.NATIVE_INDICATORS),
    "native_code": (Component.DEX, Component.NATIVE_INDICATORS, Component.NATIVE_CODE),
    "manifest_references": (Component.MANIFEST,),
    "resource_references": (Component.RESOURCES, Component.ASSETS),
}
#: categories whose records are never direct references (strings, unresolved hints)
INDIRECT_CATEGORIES = {"string_mentions", "reflection_name_match", "reflection_unresolved"}


def _sorted(evs: Iterable[Evidence]) -> list[Evidence]:
    return sorted({id(e): e for e in evs}.values(), key=Evidence.sort_key)


@dataclass
class TargetEvidenceSet:
    """Evidence relevant to one target, grouped by category, with completeness."""

    target: TransformationTarget
    defined: DefinedClass | None
    method: DefinedMethod | None
    categories: dict[str, list[Evidence]]
    component_states: dict[str, AnalysisState]
    #: defined supertypes / subtypes and supertypes not defined in the APK
    supertypes: list[str] = field(default_factory=list)
    subtypes: list[str] = field(default_factory=list)
    unresolved_supertypes: list[str] = field(default_factory=list)

    def state(self, category: str) -> AnalysisState:
        comps = CATEGORY_COMPONENTS[category]
        return combine_states(self.component_states[c.value] for c in comps)

    def absence(self, category: str) -> AbsenceStatus:
        evs = self.categories.get(category, [])
        if evs:
            if category in INDIRECT_CATEGORIES or not any(e.definitive for e in evs):
                return AbsenceStatus.ONLY_INDIRECT_EVIDENCE
            return AbsenceStatus.REFERENCES_PRESENT
        if self.state(category) is AnalysisState.COMPLETE:
            return AbsenceStatus.ABSENCE_ESTABLISHED
        return AbsenceStatus.ABSENCE_NOT_ESTABLISHED

    def summary(self, limit: int = SUMMARY_LIMIT) -> TargetEvidenceSummary:
        cats = []
        for name in sorted(self.categories):
            evs = self.categories[name]
            sources = sorted({e.source_class for e in evs if e.source_class})
            cats.append(
                CategorySummary(
                    category=name,
                    count=len(evs),
                    absence=self.absence(name),
                    analysis_state=self.state(name),
                    evidence_ids=[e.evidence_id for e in evs[:limit]],
                    truncated=len(evs) > limit,
                    source_classes=sources[:limit],
                )
            )
        return TargetEvidenceSummary(
            target=self.target.canonical,
            component_states=dict(sorted(self.component_states.items())),
            categories=cats,
            total_evidence=sum(len(v) for v in self.categories.values()),
        )


class TargetEvidenceSelector:
    """Per-result lookup tables; :meth:`select` extracts one target's evidence set."""

    def __init__(self, result: ReferenceAnalysisResult) -> None:
        self.result = result
        self.index = result.index()
        self.classes: dict[str, DefinedClass] = {c.name: c for c in result.defined_classes}
        self.simple_names: dict[str, list[str]] = defaultdict(list)
        self.children: dict[str, list[str]] = defaultdict(list)
        for c in result.defined_classes:
            self.simple_names[c.name.rsplit(".", 1)[-1]].append(c.name)
            for parent in (c.superclass, *c.interfaces):
                if parent:
                    self.children[parent].append(c.name)
        self.component_states = {c.value: result.component_state(c) for c in Component}

        self._reflection_by_class: dict[str, list[Evidence]] = defaultdict(list)
        self._reflection_by_member: dict[str, list[Evidence]] = defaultdict(list)
        self.reflection_unresolved: list[Evidence] = []
        self.dynamic_loading: list[Evidence] = []
        for ev in result.reflection:
            if ev.target_class:
                self._reflection_by_class[ev.target_class].append(ev)
            if ev.member_name:
                self._reflection_by_member[ev.member_name].append(ev)
            if ev.context == "dynamic-code-loading":
                self.dynamic_loading.append(ev)
            elif ev.resolution is ResolutionStatus.TARGET_UNKNOWN:
                self.reflection_unresolved.append(ev)
        self.reflection_unresolved.sort(key=Evidence.sort_key)
        self.dynamic_loading.sort(key=Evidence.sort_key)

        self._native_by_class: dict[str, list[Evidence]] = defaultdict(list)
        for ev in result.native:
            for cls in {ev.target_class, ev.source_class}:
                if cls:
                    self._native_by_class[cls].append(ev)
        self._manifest_by_class: dict[str, list[Evidence]] = defaultdict(list)
        for ev in result.manifest:
            for cls in {ev.target_class, ev.target}:
                if cls:
                    self._manifest_by_class[cls].append(ev)
        self._resources_by_class: dict[str, list[Evidence]] = defaultdict(list)
        for ev in result.resources:
            for cls in {ev.target_class, ev.target}:
                if cls:
                    self._resources_by_class[cls].append(ev)
        self._tokens: dict[str, list[Evidence]] | None = None

    # -- shared tables -----------------------------------------------------------

    def _string_tokens(self) -> dict[str, list[Evidence]]:
        """Defined class name -> string constants mentioning it (built once, lazily).

        A string mentions a class when a dotted/slashed identifier token in it, or a
        dotted prefix of such a token, is the name of a class defined in the APK (the
        same boundary rule as H.1 ``assess_absence``)."""
        if self._tokens is None:
            tokens: dict[str, list[Evidence]] = defaultdict(list)
            for value, evs in self.index.string_values():
                names: set[str] = set()
                for tok in _TOKEN.findall(value):
                    parts = tok.replace("/", ".").split(".")
                    for i in range(2, len(parts) + 1):
                        name = ".".join(parts[:i])
                        if name in self.classes:
                            names.add(name)
                for name in names:
                    tokens[name].extend(evs)
            self._tokens = dict(tokens)
        return self._tokens

    def supertypes(self, cls: str) -> tuple[list[str], list[str]]:
        """(defined supertypes, supertypes not defined in the APK) — transitive."""
        defined: list[str] = []
        missing: list[str] = []
        seen = {cls}
        stack = [cls]
        while stack:
            dc = self.classes.get(stack.pop())
            if dc is None:
                continue
            for parent in (dc.superclass, *dc.interfaces):
                if not parent or parent in seen:
                    continue
                seen.add(parent)
                if parent in self.classes:
                    defined.append(parent)
                    stack.append(parent)
                elif parent != OBJECT:
                    missing.append(parent)
        return sorted(defined), sorted(missing)

    def subtypes(self, cls: str) -> list[str]:
        out: set[str] = set()
        stack = [cls]
        while stack:
            for child in self.children.get(stack.pop(), ()):
                if child not in out and child != cls:
                    out.add(child)
                    stack.append(child)
        return sorted(out)

    # -- selection ---------------------------------------------------------------

    def select(
        self,
        target: TransformationTarget,
        defined: DefinedClass | None,
        method: DefinedMethod | None = None,
    ) -> TargetEvidenceSet:
        if target.kind is TargetKind.CLASS:
            cats = self._class_categories(target.class_name)
        else:
            cats = self._method_categories(target.class_name, method)
        supers, missing = self.supertypes(target.class_name)
        return TargetEvidenceSet(
            target=target,
            defined=defined,
            method=method,
            categories={k: _sorted(v) for k, v in cats.items()},
            component_states=dict(self.component_states),
            supertypes=supers,
            subtypes=self.subtypes(target.class_name),
            unresolved_supertypes=missing,
        )

    def _code(self, kind: ReferenceKind, cls: str) -> list[Evidence]:
        return [e for e in self.index.evidence_targeting(kind, cls) if e.source_class != cls]

    def _class_categories(self, cls: str) -> dict[str, list[Evidence]]:
        k = ReferenceKind
        return {
            "class_references": self._code(k.CLASS_REFERENCE, cls),
            "type_references": self._code(k.TYPE_REFERENCE, cls),
            "method_references": self._code(k.METHOD_REFERENCE, cls),
            "field_references": self._code(k.FIELD_REFERENCE, cls),
            "constructor_references": self._code(k.CONSTRUCTOR_REFERENCE, cls),
            "const_class_references": self._code(k.CONST_CLASS_REFERENCE, cls),
            "string_mentions": [
                e for e in self._string_tokens().get(cls, ()) if e.source_class != cls
            ],
            "reflection_targeting": [
                e
                for e in self._reflection_by_class.get(cls, ())
                if e.resolution is ResolutionStatus.TARGET_IDENTIFIED
            ],
            "reflection_unresolved": list(self.reflection_unresolved),
            "dynamic_code_loading": list(self.dynamic_loading),
            "native_declared": [
                e
                for e in self._native_by_class.get(cls, ())
                if e.kind is ReferenceKind.NATIVE_METHOD and e.target_class == cls
            ],
            "native_code": [
                e
                for e in self._native_by_class.get(cls, ())
                if e.kind is ReferenceKind.NATIVE_LIBRARY_LOAD
            ],
            "manifest_references": list(self._manifest_by_class.get(cls, ())),
            "resource_references": list(self._resources_by_class.get(cls, ())),
        }

    def _method_categories(
        self, cls: str, method: DefinedMethod | None
    ) -> dict[str, list[Evidence]]:
        if method is None:
            return {}
        owners = [cls, *self.subtypes(cls)]
        sig = method.signature
        kind = (
            ReferenceKind.CONSTRUCTOR_REFERENCE
            if method.name == "<init>"
            else ReferenceKind.METHOD_REFERENCE
        )
        calls = [
            e
            for owner in owners
            for e in self.index.evidence_targeting(kind, owner)
            if e.member_name == method.name
            and e.descriptor == method.descriptor
            # a method calling itself is not a remaining caller
            and not (e.source_class == cls and e.source_method == sig)
        ]
        targeting = [
            e
            for owner in owners
            for e in self._reflection_by_class.get(owner, ())
            if e.member_name == method.name or e.reflection_api in _METHOD_ENUMERATION
        ]
        # member name resolved but the receiver class is not: may be the target
        # (a name resolved on another class is unrelated and ignored)
        name_match = [
            e for e in self._reflection_by_member.get(method.name, ()) if e.target_class is None
        ]
        strings = [
            e
            for e in self.index.find_string_references(method.name).evidence
            if not (e.source_class == cls and e.source_method == sig)
        ]
        return {
            "call_sites": calls,
            "reflection_targeting": targeting,
            "reflection_name_match": name_match,
            "reflection_unresolved": list(self.reflection_unresolved),
            "dynamic_code_loading": list(self.dynamic_loading),
            "string_mentions": strings,
            "native_declared": [
                e
                for e in self._native_by_class.get(cls, ())
                if e.kind is ReferenceKind.NATIVE_METHOD and e.target_class == cls
            ],
        }
