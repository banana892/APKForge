"""Phase H.1: read-only evidence & reference analysis.

Answers "what references this class / method / field, and is the analysis complete
enough to rely on the answer?" for a decoded APK. It produces evidence only: nothing in
this package modifies, patches, rebuilds, signs or installs an APK, and no result states
that an APK, class or reference is safe or unused beyond the documented static scope.

Pipeline position (future stages consume this evidence)::

    Phase F/G finding -> evidence -> H.1 reference analysis
        -> (H.2) transformation eligibility -> (H.3+) transformation
"""

from __future__ import annotations

from apkforge.reference.index import ReferenceIndex
from apkforge.reference.models import (
    SCHEMA_VERSION,
    AbsenceAssessment,
    AbsenceConclusion,
    AnalysisIssue,
    AnalysisState,
    ApkIdentity,
    Component,
    ComponentAnalysis,
    DefinedClass,
    Evidence,
    FieldAccess,
    InvokeKind,
    MatchBasis,
    NativeResolution,
    QueryResult,
    ReferenceAnalysisResult,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
    combine_states,
)
from apkforge.reference.report import format_reference_report
from apkforge.reference.service import ReferenceAnalysisService
from apkforge.reference.smali import parse_smali

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
    "Evidence",
    "FieldAccess",
    "InvokeKind",
    "MatchBasis",
    "NativeResolution",
    "QueryResult",
    "ReferenceAnalysisResult",
    "ReferenceAnalysisService",
    "ReferenceIndex",
    "ReferenceKind",
    "ResolutionStatus",
    "StringUse",
    "combine_states",
    "format_reference_report",
    "parse_smali",
]
