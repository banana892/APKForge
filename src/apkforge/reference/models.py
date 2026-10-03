"""Phase H.1 evidence and reference-analysis data models.

Everything here describes *observed static evidence* inside a decoded APK project and
how complete the analysis that produced it was. Nothing here modifies an APK, and
nothing here states that an application (or a class) is safe, unused, malicious or
benign.

Central rule
------------
An empty evidence list is only meaningful together with its :class:`AnalysisState`.
When the state is anything other than :attr:`AnalysisState.COMPLETE`, the absence of an
observed reference must never be read as proof that no reference exists. The
:class:`QueryResult` and :class:`AbsenceAssessment` models make that machine-readable
through ``absence_established``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, PrivateAttr, computed_field

if TYPE_CHECKING:
    from collections.abc import Iterable

    from apkforge.reference.index import ReferenceIndex

__all__ = [
    "SCHEMA_VERSION",
    "AbsenceAssessment",
    "AbsenceConclusion",
    "AnalysisIssue",
    "AnalysisState",
    "ApkIdentity",
    "Component",
    "ComponentAnalysis",
    "DefinedClass",
    "DefinedMethod",
    "Evidence",
    "FieldAccess",
    "InvokeKind",
    "MatchBasis",
    "NativeResolution",
    "QueryResult",
    "ReferenceAnalysisResult",
    "ReferenceKind",
    "ResolutionStatus",
    "StringUse",
    "combine_states",
    "evidence_id_for",
]

#: 2: DefinedClass carries access flags, interfaces, annotations, method declarations,
#: its file's analysis state and duplicate definitions (additive; used by Phase H.2)
SCHEMA_VERSION = 2


class AnalysisState(StrEnum):
    """Completeness of one analysis operation.

    COMPLETE      the relevant input was inspected; the result is complete within the
                  documented analysis scope (static, decoded-smali level).
    PARTIAL       some relevant input could not be analysed.
    UNKNOWN       the analyser cannot determine whether the relationship exists.
    NOT_ANALYZED  the analysis was not requested or intentionally not performed.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOT_ANALYZED = "NOT_ANALYZED"


def combine_states(states: Iterable[AnalysisState]) -> AnalysisState:
    """Aggregate component states; never more complete than the weakest input.

    - no inputs, or all NOT_ANALYZED -> NOT_ANALYZED
    - all COMPLETE                   -> COMPLETE
    - nothing COMPLETE or PARTIAL    -> UNKNOWN  (only UNKNOWN / NOT_ANALYZED inputs)
    - anything else (a mixture)      -> PARTIAL
    """
    items = list(states)
    if not items or all(s is AnalysisState.NOT_ANALYZED for s in items):
        return AnalysisState.NOT_ANALYZED
    if all(s is AnalysisState.COMPLETE for s in items):
        return AnalysisState.COMPLETE
    if not any(s in (AnalysisState.COMPLETE, AnalysisState.PARTIAL) for s in items):
        return AnalysisState.UNKNOWN
    return AnalysisState.PARTIAL


class ReferenceKind(StrEnum):
    CLASS_REFERENCE = "CLASS_REFERENCE"
    METHOD_REFERENCE = "METHOD_REFERENCE"
    FIELD_REFERENCE = "FIELD_REFERENCE"
    TYPE_REFERENCE = "TYPE_REFERENCE"
    STRING_REFERENCE = "STRING_REFERENCE"
    CONSTRUCTOR_REFERENCE = "CONSTRUCTOR_REFERENCE"
    CONST_CLASS_REFERENCE = "CONST_CLASS_REFERENCE"
    REFLECTION_INDICATOR = "REFLECTION_INDICATOR"
    NATIVE_METHOD = "NATIVE_METHOD"
    NATIVE_LIBRARY_LOAD = "NATIVE_LIBRARY_LOAD"
    MANIFEST_REFERENCE = "MANIFEST_REFERENCE"
    RESOURCE_REFERENCE = "RESOURCE_REFERENCE"


class InvokeKind(StrEnum):
    STATIC = "invoke-static"
    DIRECT = "invoke-direct"
    VIRTUAL = "invoke-virtual"
    SUPER = "invoke-super"
    INTERFACE = "invoke-interface"
    POLYMORPHIC = "invoke-polymorphic"


class FieldAccess(StrEnum):
    IGET = "iget"
    IPUT = "iput"
    SGET = "sget"
    SPUT = "sput"


class StringUse(StrEnum):
    """Interpretation of a string constant. Stronger values need supporting evidence."""

    #: ordinary text, not shaped like a class or member name
    STRING_LITERAL = "STRING_LITERAL"
    #: shaped like a class name AND names a class defined in this APK
    POSSIBLE_CLASS_NAME = "POSSIBLE_CLASS_NAME"
    #: observed flowing into the member-name argument of a reflection API
    POSSIBLE_METHOD_NAME = "POSSIBLE_METHOD_NAME"
    #: observed flowing into the class-name argument of a reflection/class-loading API
    POSSIBLE_REFLECTION_TARGET = "POSSIBLE_REFLECTION_TARGET"
    #: identifier/class-name shaped, but no supporting evidence of how it is used
    UNKNOWN_STRING_USE = "UNKNOWN_STRING_USE"


class ResolutionStatus(StrEnum):
    """What a reflection indicator resolves to statically."""

    #: the API takes no name; its target was chosen elsewhere (e.g. Method.invoke)
    NO_TARGET_IDENTIFIED = "NO_TARGET_IDENTIFIED"
    #: the name/class argument was traced to a constant in the same basic block
    TARGET_IDENTIFIED = "TARGET_IDENTIFIED"
    #: the API takes a name/class but the argument could not be traced statically
    TARGET_UNKNOWN = "TARGET_UNKNOWN"


class NativeResolution(StrEnum):
    IDENTIFIED = "IDENTIFIED"
    UNKNOWN = "UNKNOWN"


class MatchBasis(StrEnum):
    """Why a manifest/resource value was matched to a target."""

    # structural: the value sits where Android expects a class / authority
    CLASS_ATTRIBUTE = "CLASS_ATTRIBUTE"
    XML_ELEMENT_NAME = "XML_ELEMENT_NAME"
    PROVIDER_AUTHORITY = "PROVIDER_AUTHORITY"
    SERVICE_LOADER_ENTRY = "SERVICE_LOADER_ENTRY"
    # textual: the value merely contains / equals the target string
    EXACT_VALUE = "EXACT_VALUE"
    EMBEDDED_TOKEN = "EMBEDDED_TOKEN"  # noqa: S105 - not a credential

    @property
    def structural(self) -> bool:
        return self in _STRUCTURAL


_STRUCTURAL = {
    MatchBasis.CLASS_ATTRIBUTE,
    MatchBasis.XML_ELEMENT_NAME,
    MatchBasis.PROVIDER_AUTHORITY,
    MatchBasis.SERVICE_LOADER_ENTRY,
}


class Component(StrEnum):
    """Analysis components whose states are reported (and aggregated) separately."""

    DEX = "dex"
    REFLECTION = "reflection"
    NATIVE_INDICATORS = "native_indicators"
    NATIVE_CODE = "native_code"
    MANIFEST = "manifest"
    RESOURCES = "resources"
    ASSETS = "assets"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

#: fields that identify an evidence record (interpretation fields excluded)
_ID_FIELDS = (
    "kind",
    "source_file",
    "source_line",
    "instruction",
    "context",
    "target",
    "member_name",
    "descriptor",
    "xml_location",
    "matched_value",
)


def evidence_id_for(ev: Evidence | dict[str, Any]) -> str:
    """Stable id: hash of the identifying fields (no paths outside the project)."""
    get = ev.get if isinstance(ev, dict) else (lambda k: getattr(ev, k, None))
    key = json.dumps([get(k) for k in _ID_FIELDS], separators=(",", ":"), default=str)
    return "ev-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class Evidence:
    """One observed reference/indicator with provenance.

    ``source_file`` is relative to the decoded project root (posix separators).
    ``source_line`` is the 1-based line in that file; ``java_line`` is the original
    source line from a smali ``.line`` directive when debug info exists.

    A slotted dataclass rather than a pydantic model: large apps yield millions of
    records. Pydantic still validates/serialises it as a field of the result models.
    """

    kind: ReferenceKind
    source_file: str
    target: str
    evidence_id: str = ""
    source_dex: str | None = None
    source_class: str | None = None
    source_method: str | None = None
    source_line: int | None = None
    java_line: int | None = None
    instruction: str | None = None
    #: role of the mention (e.g. ``method-parameter``, ``superclass``, ``operand``)
    context: str | None = None
    target_class: str | None = None
    member_name: str | None = None
    #: raw smali descriptor: method proto ``(I)V`` or field type ``I``
    descriptor: str | None = None
    parameter_types: tuple[str, ...] = ()
    return_type: str | None = None
    invoke_kind: InvokeKind | None = None
    access_kind: FieldAccess | None = None
    array_dimensions: int = 0
    #: same (source method, target, role) seen again: first location kept, count here
    occurrences: int = 1
    string_value: str | None = None
    string_use: StringUse | None = None
    reflection_api: str | None = None
    resolution: ResolutionStatus | None = None
    native_resolution: NativeResolution | None = None
    library_name: str | None = None
    xml_location: str | None = None
    matched_value: str | None = None
    match_basis: MatchBasis | None = None
    associated_evidence: tuple[str, ...] = ()
    analysis_state: AnalysisState = AnalysisState.COMPLETE
    confidence_basis: str = ""

    def finalize_id(self) -> Evidence:
        self.evidence_id = evidence_id_for(self)
        return self

    def sort_key(self) -> tuple[str, int, str, str, str]:
        return (
            self.source_file,
            self.source_line or 0,
            self.kind.value,
            self.target,
            self.evidence_id,
        )

    @property
    def definitive(self) -> bool:
        """True for structural references; False for strings/textual/reflection hints."""
        if self.kind in (ReferenceKind.MANIFEST_REFERENCE, ReferenceKind.RESOURCE_REFERENCE):
            return self.match_basis is not None and self.match_basis.structural
        return self.kind not in (
            ReferenceKind.STRING_REFERENCE,
            ReferenceKind.REFLECTION_INDICATOR,
            ReferenceKind.NATIVE_LIBRARY_LOAD,
        )


class AnalysisIssue(BaseModel):
    """Something that prevented complete analysis of one input."""

    code: str
    location: str
    message: str


class ComponentAnalysis(BaseModel):
    """State of one analysis component (``dex``, ``dex:classes2.dex``, ``resources``...)."""

    component: str
    state: AnalysisState
    inputs_total: int = 0
    inputs_analyzed: int = 0
    issue_count: int = 0
    #: first issues only (see ``issue_count`` for the total)
    issues: list[AnalysisIssue] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    subcomponents: list[ComponentAnalysis] = Field(default_factory=list)


@dataclass(slots=True)
class DefinedMethod:
    """A method declared in a class (``.method`` header), as decoded from smali.

    ``access_flags`` are the smali modifiers in source order (``public``, ``static``,
    ``native``, ``abstract``, ``constructor``, ``bridge``, ``synthetic``...).
    ``annotations`` are the method-level annotation types (parameter annotations excluded).
    """

    name: str
    descriptor: str
    access_flags: tuple[str, ...] = ()
    annotations: tuple[str, ...] = ()
    source_line: int | None = None

    @property
    def signature(self) -> str:
        return self.name + self.descriptor


class DefinedClass(BaseModel):
    name: str
    source_file: str
    source_dex: str | None = None
    superclass: str | None = None
    access_flags: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)
    #: class-level annotation types
    annotations: list[str] = Field(default_factory=list)
    methods: list[DefinedMethod] = Field(default_factory=list)
    #: state of the smali file that defines the class (PARTIAL: declarations may be missing)
    analysis_state: AnalysisState = AnalysisState.COMPLETE
    #: other project files defining the same class (the first definition is kept)
    duplicate_sources: list[str] = Field(default_factory=list)


class ApkIdentity(BaseModel):
    file_name: str | None = None
    sha256: str | None = None
    size: int | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None


# ---------------------------------------------------------------------------
# Query / absence models
# ---------------------------------------------------------------------------


class QueryResult(BaseModel):
    """Evidence returned for one query together with its completeness."""

    query: str
    target: str
    analysis_state: AnalysisState
    component_states: dict[str, AnalysisState]
    evidence: list[Evidence] = Field(default_factory=list)

    @property
    def observed(self) -> bool:
        return bool(self.evidence)

    @property
    def absence_established(self) -> bool:
        """Only an empty result of a COMPLETE analysis establishes absence (in scope)."""
        return not self.evidence and self.analysis_state is AnalysisState.COMPLETE


class AbsenceConclusion(StrEnum):
    #: definitive (structural) references were observed
    REFERENCES_OBSERVED = "REFERENCES_OBSERVED"
    #: no structural reference, but strings / reflection / textual matches mention it
    ONLY_INDIRECT_EVIDENCE = "ONLY_INDIRECT_EVIDENCE"
    #: nothing observed, but some relevant analysis is not COMPLETE
    ABSENCE_NOT_ESTABLISHED = "ABSENCE_NOT_ESTABLISHED"
    #: nothing observed and every relevant component is COMPLETE (static scope only)
    NO_REFERENCES_WITHIN_SCOPE = "NO_REFERENCES_WITHIN_SCOPE"


class AbsenceAssessment(BaseModel):
    """Machine-readable answer to "is anything still referencing this class?"."""

    target: str
    conclusion: AbsenceConclusion
    absence_established: bool
    analysis_state: AnalysisState
    component_states: dict[str, AnalysisState]
    definitive_references: list[Evidence] = Field(default_factory=list)
    indirect_evidence: list[Evidence] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    statement: str


# ---------------------------------------------------------------------------
# Aggregate result
# ---------------------------------------------------------------------------


class ReferenceAnalysisResult(BaseModel):
    """Read-only H.1 reference analysis of one APK (or decoded project)."""

    schema_version: int = SCHEMA_VERSION
    apk: ApkIdentity = Field(default_factory=ApkIdentity)
    analysis_state: AnalysisState
    components: list[ComponentAnalysis] = Field(default_factory=list)
    defined_classes: list[DefinedClass] = Field(default_factory=list)
    #: code references: class / method / field / type / constructor / const-class / string
    references: list[Evidence] = Field(default_factory=list)
    reflection: list[Evidence] = Field(default_factory=list)
    native: list[Evidence] = Field(default_factory=list)
    bundled_native_libraries: list[str] = Field(default_factory=list)
    manifest: list[Evidence] = Field(default_factory=list)
    resources: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    #: SHA-256 of the input APK was identical before and after (None: no APK given)
    original_unchanged: bool | None = None

    _index: ReferenceIndex | None = PrivateAttr(default=None)

    def component_state(self, name: str | Component) -> AnalysisState:
        key = str(name)
        for c in self.components:
            if c.component == key:
                return c.state
        return AnalysisState.NOT_ANALYZED

    @property
    def component_states(self) -> dict[str, AnalysisState]:
        return {c.component: c.state for c in self.components}

    def all_evidence(self) -> list[Evidence]:
        return [
            *self.references,
            *self.reflection,
            *self.native,
            *self.manifest,
            *self.resources,
        ]

    def index(self) -> ReferenceIndex:
        """Query interface over this result (built once, cached)."""
        if self._index is None:
            from apkforge.reference.index import ReferenceIndex

            self._index = ReferenceIndex(self)
        return self._index

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {k.value: 0 for k in ReferenceKind}
        for ev in self.all_evidence():
            counts[ev.kind.value] += 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_counts(self) -> dict[str, int]:
        return self.summary()

    def to_json(self, *, indent: int | None = 2, include_code_references: bool = True) -> str:
        """Deterministic JSON (no timestamps, no absolute paths, None fields omitted).

        ``include_code_references=False`` drops the per-instruction ``references`` list
        (millions of records for large apps; ``evidence_counts`` still reports it) and the
        per-class method declarations.
        """
        exclude: dict[str, Any] | None = (
            None
            if include_code_references
            else {"references": True, "defined_classes": {"__all__": {"methods"}}}
        )
        return self.model_dump_json(indent=indent, exclude_none=True, exclude=exclude)
