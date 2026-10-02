"""Expected-vs-actual classification of a :class:`DiffResult` (Phase C.5).

A modification run declares, before it touches anything, which semantic changes it
expects (:class:`ExpectedChange`). After the rebuild, :func:`verify_expectations`
flattens the DiffEngine result into individual observations and classifies each:

- ``EXPECTED_MODIFICATION``: matches a declared expected change exactly
- ``REBUILD_NOISE``: matches a documented no-op rebuild noise rule (:data:`NOISE_RULES`)
- ``UNEXPECTED``: anything else, including noise that is not part of the target APK's
  measured no-op baseline when ``allowed_noise_rules`` is given
- ``UNKNOWN``: the comparison could not establish the facts (a differ failed, output
  was truncated, the diff is not complete)

The verdict passes only with zero ``UNEXPECTED``, zero ``UNKNOWN`` and every expected
change observed. Nothing is downgraded to a warning.

The noise rules were derived from the C.5 no-op semantic baseline on the C.4 corpus
with the C.4 toolchain (Apktool 3.0.3, build-tools 35.0.0); see
``tests/corpus/results/c5-semantic-noop-baseline.md``. They are not assumed to hold for
another toolchain.

This module adds classification on top of DiffEngine; it performs no comparison of
its own.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus
from apkforge.diff.models import ChangeType, DiffResult

__all__ = [
    "NOISE_RULES",
    "ClassifiedObservation",
    "ExpectationVerdict",
    "ExpectedChange",
    "Observation",
    "ObservationClass",
    "observe",
    "verify_expectations",
]


class ObservationClass(StrEnum):
    EXPECTED_MODIFICATION = "expected_modification"
    REBUILD_NOISE = "rebuild_noise"
    UNEXPECTED = "unexpected"
    UNKNOWN = "unknown"


class Observation(BaseModel):
    """One atomic difference reported by DiffEngine."""

    category: str
    kind: str  # added | removed | modified | renamed | incomplete
    identifier: str
    detail: dict[str, Any] = Field(default_factory=dict)


class ExpectedChange(BaseModel):
    """A change a modification declares before it is applied.

    ``detail`` must equal the observation's detail exactly, so an expected component
    change also pins *which* attributes change (and nothing else).
    """

    category: str
    kind: str
    identifier: str
    detail: dict[str, Any] = Field(default_factory=dict)
    description: str = ""

    def matches(self, obs: Observation) -> bool:
        return (
            self.category == obs.category
            and self.kind == obs.kind
            and self.identifier == obs.identifier
            and self.detail == obs.detail
        )


class ClassifiedObservation(BaseModel):
    observation: Observation
    classification: ObservationClass
    rule: str | None = None
    reason: str = ""


class ExpectationVerdict(BaseModel):
    """Result of classifying a diff against expected changes and the noise floor."""

    passed: bool
    diff_status: str
    observations: list[ClassifiedObservation] = Field(default_factory=list)
    expected_observed: list[ExpectedChange] = Field(default_factory=list)
    expected_missing: list[ExpectedChange] = Field(default_factory=list)
    noise_rule_counts: dict[str, int] = Field(default_factory=dict)
    failures: list[str] = Field(default_factory=list)

    def of(self, cls: ObservationClass) -> list[ClassifiedObservation]:
        return [o for o in self.observations if o.classification == cls]

    @property
    def counts(self) -> dict[str, int]:
        return {c.value: len(self.of(c)) for c in ObservationClass}


# ---------------------------------------------------------------------------
# Observation extraction
# ---------------------------------------------------------------------------


def _component_detail(c: Any) -> dict[str, Any]:  # noqa: ANN401 - ComponentChange
    """Only the attributes that changed, so an expectation pins the exact delta."""
    detail: dict[str, Any] = {"component_type": c.component_type}
    if c.change_type != ChangeType.MODIFIED:
        return detail
    if c.exported_before != c.exported_after:
        detail["exported"] = [c.exported_before, c.exported_after]
    # ComponentDiffer records each changed attribute as <attr>_before / <attr>_after.
    for key in sorted(
        {k.rsplit("_", 1)[0] for k in c.details if k.endswith(("_before", "_after"))}
    ):
        detail[key] = [c.details.get(f"{key}_before"), c.details.get(f"{key}_after")]
    if c.intent_filter_diff is not None:
        detail["intent_filters"] = c.intent_filter_diff.model_dump(exclude_defaults=True)
    return detail


def observe(diff: DiffResult) -> list[Observation]:
    """Flatten every reported difference in *diff* into observations."""
    obs: list[Observation] = []
    add = obs.append

    for ch in diff.identity.changes:
        add(
            Observation(
                category="identity",
                kind="modified",
                identifier=ch.identifier,
                detail={"before": ch.before, "after": ch.after},
            )
        )
    for ch in [*diff.manifest.attribute_changes, *diff.manifest.sdk_changes]:
        add(
            Observation(
                category="manifest_attribute",
                kind="modified",
                identifier=ch.identifier,
                detail={"before": ch.before, "after": ch.after},
            )
        )

    p = diff.permissions
    for name in p.added:
        add(Observation(category="uses_permission", kind="added", identifier=name))
    for name in p.removed:
        add(Observation(category="uses_permission", kind="removed", identifier=name))
    for name in p.declared_added:
        add(Observation(category="declared_permission", kind="added", identifier=name))
    for name in p.declared_removed:
        add(Observation(category="declared_permission", kind="removed", identifier=name))
    for ch in p.declared_modified:
        add(
            Observation(
                category="declared_permission",
                kind="modified",
                identifier=ch.identifier,
                detail={"before": ch.before, "after": ch.after},
            )
        )

    comps = diff.components
    for c in [*comps.activities, *comps.services, *comps.receivers, *comps.providers]:
        if c.change_type != ChangeType.UNCHANGED:
            add(
                Observation(
                    category="component",
                    kind=str(c.change_type),
                    identifier=c.name,
                    detail=_component_detail(c),
                )
            )

    d = diff.dex
    for name in d.dex_files_added:
        add(Observation(category="dex_file", kind="added", identifier=name))
    for name in d.dex_files_removed:
        add(Observation(category="dex_file", kind="removed", identifier=name))
    for name in d.classes_added:
        add(Observation(category="dex_class", kind="added", identifier=name))
    for name in d.classes_removed:
        add(Observation(category="dex_class", kind="removed", identifier=name))
    for cd in d.classes_modified:
        add(
            Observation(
                category="dex_class",
                kind="modified",
                identifier=cd.class_name,
                detail={
                    "methods_modified": [m.method_name for m in cd.methods_modified],
                    "methods_added": cd.methods_added,
                    "methods_removed": cd.methods_removed,
                },
            )
        )
    for name in d.api_references_added:
        add(Observation(category="dex_api_reference", kind="added", identifier=name))
    for name in d.api_references_removed:
        add(Observation(category="dex_api_reference", kind="removed", identifier=name))

    s = diff.strings
    for value in s.added_sample:
        add(Observation(category="dex_string", kind="added", identifier=value))
    for value in s.removed_sample:
        add(Observation(category="dex_string", kind="removed", identifier=value))
    for kind, total, sample in (
        ("added", s.total_added, s.added_sample),
        ("removed", s.total_removed, s.removed_sample),
    ):
        if total > len(sample):
            add(
                Observation(
                    category="dex_string",
                    kind="incomplete",
                    identifier=kind,
                    detail={"total": total, "enumerated": len(sample)},
                )
            )

    n = diff.network
    for u in n.urls_added:
        add(Observation(category="network_url", kind="added", identifier=u.url))
    for u in n.urls_removed:
        add(Observation(category="network_url", kind="removed", identifier=u.url))
    for kind, values in (
        ("added", [*n.domains_added, *n.ips_added]),
        ("removed", [*n.domains_removed, *n.ips_removed]),
    ):
        for v in values:
            add(Observation(category="network_host", kind=kind, identifier=v))

    nat = diff.native
    for lib in [*nat.libraries_added, *nat.libraries_removed, *nat.libraries_modified]:
        add(Observation(category="native_library", kind=str(lib.change_type), identifier=lib.path))
    for abi in nat.abis_added:
        add(Observation(category="native_abi", kind="added", identifier=abi))
    for abi in nat.abis_removed:
        add(Observation(category="native_abi", kind="removed", identifier=abi))

    e = diff.embedded
    for kind, values in (
        ("added", [*e.apks_added, *e.dex_added, *e.executables_added]),
        ("removed", [*e.apks_removed, *e.dex_removed, *e.executables_removed]),
    ):
        for v in values:
            add(Observation(category="embedded", kind=kind, identifier=v))

    if diff.certificates.status not in ("SAME", "UNCHANGED"):
        add(
            Observation(
                category="certificate",
                kind="modified",
                identifier="signing_certificate",
                detail={"status": diff.certificates.status},
            )
        )

    # File level. resources/assets entries are views over the same file diff, so the
    # file diff is the single source for file observations.
    for f in diff.files.entries:
        if f.change_type == ChangeType.UNCHANGED:
            continue
        detail: dict[str, Any] = {"file_category": f.category}
        if f.change_type == ChangeType.RENAMED:
            detail["old_path"] = f.old_path
            detail["match_basis"] = f.details.get("match_basis")
        if f.change_type in (ChangeType.ADDED, ChangeType.REMOVED):
            detail["size"] = f.size_after if f.change_type == ChangeType.ADDED else f.size_before
        add(Observation(category="file", kind=str(f.change_type), identifier=f.path, detail=detail))

    return obs


# ---------------------------------------------------------------------------
# Noise rules (current toolchain, from the C.5 no-op baseline)
# ---------------------------------------------------------------------------

_SIGNATURE_FILE = re.compile(r"^META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$", re.I)
_DEX_FILE = re.compile(r"^classes\d*\.dex$")
_COMPILER_MARKER = re.compile(r"^~~(?:R8|D8|L8)\{.*\}$", re.S)
_COLLAPSED_RES = re.compile(r"^res/[^/]+\.xml$")

#: rule id -> description. Every REBUILD_NOISE classification names one of these.
NOISE_RULES: dict[str, str] = {
    "signature_replaced": (
        "APK signature files (META-INF/MANIFEST.MF, *.SF, *.RSA/DSA/EC) replaced by "
        "re-signing; other META-INF entries are not covered."
    ),
    "certificate_replaced": "Signing certificate differs because the APK was re-signed.",
    "dex_reencoded": (
        "classesN.dex bytes differ after smali disassembly/reassembly. Class- and method-"
        "level changes are separate observations and are never noise."
    ),
    "dex_compiler_marker_removed": (
        "R8/D8/L8 build-marker string (~~R8{...}) dropped by smali reassembly."
    ),
    "manifest_reencoded": (
        "Binary AndroidManifest.xml bytes differ after AAPT2 recompilation. Its semantic "
        "content (permissions, components, compared attributes) is observed separately."
    ),
    "resource_table_reencoded": (
        "resources.arsc regenerated by AAPT2. Its entries are NOT compared semantically "
        "(known limitation)."
    ),
    "resource_reencoded": (
        "res/ file recompiled by AAPT2 at the same path (binary XML re-encoding); content "
        "is not compared semantically (known limitation)."
    ),
    "resource_path_canonicalized": (
        "Collapsed resource path (res/Xy.xml) restored to its canonical res/<type>/<name> "
        "path; paired by ARSC resource identity or content hash."
    ),
    "manifest_resource_path_canonicalized": (
        "Manifest attribute that references a resource file changes only by the same "
        "res/ path canonicalization, confirmed by a paired file rename."
    ),
}


def _noise_rule(obs: Observation, renames: dict[str, Any]) -> str | None:
    """Return the noise rule matching *obs*, or None."""
    cat, kind, ident = obs.category, obs.kind, obs.identifier
    fcat = obs.detail.get("file_category")
    if cat == "certificate" and kind == "modified":
        return "certificate_replaced"
    if cat == "dex_string" and kind == "removed" and _COMPILER_MARKER.match(ident):
        return "dex_compiler_marker_removed"
    if cat == "manifest_attribute" and kind == "modified":
        before, after = obs.detail.get("before"), obs.detail.get("after")
        if (
            isinstance(before, str)
            and isinstance(after, str)
            and _COLLAPSED_RES.match(before)
            and renames.get(after) == before
        ):
            return "manifest_resource_path_canonicalized"
        return None
    if cat != "file":
        return None
    if _SIGNATURE_FILE.match(ident) and kind in ("added", "removed", "modified"):
        return "signature_replaced"
    if kind == "modified":
        if ident == "AndroidManifest.xml":
            return "manifest_reencoded"
        if ident == "resources.arsc":
            return "resource_table_reencoded"
        if _DEX_FILE.match(ident):
            return "dex_reencoded"
        if fcat == "resource" and ident.startswith("res/"):
            return "resource_reencoded"
    if (
        kind == "renamed"
        and fcat == "resource"
        and ident.startswith("res/")
        and str(obs.detail.get("old_path", "")).startswith("res/")
        and obs.detail.get("match_basis") in ("resource_identity", "content_hash")
    ):
        return "resource_path_canonicalized"
    return None


def verify_expectations(
    diff: DiffResult,
    expected: list[ExpectedChange],
    *,
    allowed_noise_rules: set[str] | None = None,
    allowed_residue: set[tuple[str, str, str]] | None = None,
) -> ExpectationVerdict:
    """Classify every observation in *diff* and decide whether it matches *expected*.

    Args:
        diff: DiffEngine result, original (A) vs. modified (B).
        expected: changes the modification declared before it was applied.
        allowed_noise_rules: if given, noise is only accepted for these rule ids (the
            rules that fired in this APK's no-op baseline); other noise is UNEXPECTED.
        allowed_residue: ``(category, kind, identifier)`` observations recorded in this
            APK's no-op baseline that no rule explains (e.g. unpaired resource renames).
            They are accepted as noise (rule ``baseline_residue``) only on exact match.
    """
    renames = {
        o.identifier: o.detail.get("old_path")
        for o in observe(diff)
        if o.category == "file" and o.kind == "renamed"
    }
    classified: list[ClassifiedObservation] = []
    observed_expected: list[ExpectedChange] = []
    rule_counts: dict[str, int] = {}

    for obs in observe(diff):
        match = next((e for e in expected if e.matches(obs)), None)
        if match is not None:
            if match not in observed_expected:
                observed_expected.append(match)
            classified.append(
                ClassifiedObservation(
                    observation=obs,
                    classification=ObservationClass.EXPECTED_MODIFICATION,
                    reason=match.description or "declared expected change",
                )
            )
            continue
        if obs.kind == "incomplete":
            classified.append(
                ClassifiedObservation(
                    observation=obs,
                    classification=ObservationClass.UNKNOWN,
                    reason="DiffEngine output was truncated; not every change could be classified",
                )
            )
            continue
        rule = _noise_rule(obs, renames)
        if (
            rule is None
            and allowed_residue
            and (obs.category, obs.kind, obs.identifier) in allowed_residue
        ):
            rule = "baseline_residue"
        if rule is None:
            classified.append(
                ClassifiedObservation(
                    observation=obs,
                    classification=ObservationClass.UNEXPECTED,
                    reason="not declared by the modification and not explained by a noise rule",
                )
            )
            continue
        if (
            allowed_noise_rules is not None
            and rule != "baseline_residue"
            and rule not in allowed_noise_rules
        ):
            classified.append(
                ClassifiedObservation(
                    observation=obs,
                    classification=ObservationClass.UNEXPECTED,
                    rule=rule,
                    reason=f"noise rule '{rule}' did not occur in this APK's no-op baseline",
                )
            )
            continue
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        classified.append(
            ClassifiedObservation(
                observation=obs,
                classification=ObservationClass.REBUILD_NOISE,
                rule=rule,
                reason=NOISE_RULES.get(rule, "recorded in this APK's no-op baseline"),
            )
        )

    failures: list[str] = []
    if diff.status != AnalysisStatus.COMPLETE:
        failures.append(f"diff status is {diff.status}, not complete")
    for msg in diff.limitations:
        failures.append(f"diff limitation: {msg}")
    for msg in diff.errors:
        failures.append(f"diff error: {msg}")
    missing = [e for e in expected if e not in observed_expected]
    for e in missing:
        failures.append(f"expected change not observed: {e.category} {e.kind} {e.identifier}")
    unexpected = [c for c in classified if c.classification == ObservationClass.UNEXPECTED]
    unknown = [c for c in classified if c.classification == ObservationClass.UNKNOWN]
    if unexpected:
        failures.append(f"{len(unexpected)} unexpected change(s)")
    if unknown:
        failures.append(f"{len(unknown)} change(s) could not be classified")

    return ExpectationVerdict(
        passed=not failures,
        diff_status=str(diff.status),
        observations=classified,
        expected_observed=observed_expected,
        expected_missing=missing,
        noise_rule_counts=rule_counts,
        failures=failures,
    )
