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
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus
from apkforge.diff.manifest_tree import explained_by
from apkforge.diff.models import ChangeType, DiffResult

if TYPE_CHECKING:
    from apkforge.diff.normalization import NoiseFingerprint

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
    #: An archive entry (AndroidManifest.xml, classesN.dex) whose bytes change because a
    #: planned modification edits the source it is compiled from. Its *meaning* is
    #: checked by the semantic observations (which must be expected); the entry itself
    #: is accepted only when that semantic comparison is complete.
    PLANNED_ENTRY = "planned_entry"
    REBUILD_NOISE = "rebuild_noise"
    UNEXPECTED = "unexpected"
    UNKNOWN = "unknown"


class Observation(BaseModel):
    """One atomic difference reported by DiffEngine.

    ``content_before`` / ``content_after`` identify the content on each side (SHA-256 of
    an archive entry, certificate fingerprints); they are not part of ``detail`` so an
    expectation that does not pin content still matches.
    """

    category: str
    kind: str  # added | removed | modified | renamed | incomplete
    identifier: str
    detail: dict[str, Any] = Field(default_factory=dict)
    content_before: str | None = None
    content_after: str | None = None


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
    #: Optional content pins (e.g. SHA-256 of an added file). When set they must match.
    content_before: str | None = None
    content_after: str | None = None

    def matches(self, obs: Observation) -> bool:
        return (
            self.category == obs.category
            and self.kind == obs.kind
            and self.identifier == obs.identifier
            and self.detail == obs.detail
            and (self.content_before is None or self.content_before == obs.content_before)
            and (self.content_after is None or self.content_after == obs.content_after)
        )


class ClassifiedObservation(BaseModel):
    observation: Observation
    classification: ObservationClass
    rule: str | None = None
    reason: str = ""
    #: How the classification was established: ``declared`` (expected change),
    #: ``content`` / ``signer`` / ``path_only`` (fingerprint policy), ``path_rule``
    #: (legacy path rule, content not compared), ``semantic`` (planned entry).
    assurance: str | None = None


class ExpectationVerdict(BaseModel):
    """Result of classifying a diff against expected changes and the noise floor."""

    passed: bool
    diff_status: str
    #: ``content_fingerprint`` (Phase E) or ``path_rules`` (Phase C.5/D)
    mode: str = "path_rules"
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
        add(
            Observation(
                category="native_library",
                kind=str(lib.change_type),
                identifier=lib.path,
                content_before=lib.sha256_before,
                content_after=lib.sha256_after,
            )
        )
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
                content_before=_fingerprints(diff.certificates.certificates_before),
                content_after=_fingerprints(diff.certificates.certificates_after),
            )
        )

    # Full manifest tree: only differences no specialised differ reports (Phase E).
    for tc in diff.manifest_tree.changes:
        if explained_by(tc, diff) is None:
            add(
                Observation(
                    category="manifest_element",
                    kind=tc.kind,
                    identifier=tc.identifier,
                    detail=tc.detail(),
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
        add(
            Observation(
                category="file",
                kind=str(f.change_type),
                identifier=f.path,
                detail=detail,
                content_before=f.sha256_before,
                content_after=f.sha256_after,
            )
        )

    return obs


def _fingerprints(certs: list[dict[str, Any]]) -> str | None:
    fps = sorted(
        re.sub(r"[^0-9a-f]", "", str(c.get("sha256_fingerprint") or "").lower()) for c in certs
    )
    return ",".join(f for f in fps if f) or None


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
    "manifest_reference_inlined": (
        "Manifest attribute (full manifest tree) whose @XXXXXXXX resource reference was "
        "replaced by its literal value, or vice versa; accepted only when the reference "
        "resolves to that same value in every resource configuration. Observed: "
        "AntennaPod FileProvider android:authorities (Apktool 3.0.3)."
    ),
}


def _noise_rule(obs: Observation, renames: dict[str, Any]) -> str | None:
    """Return the noise rule matching *obs*, or None."""
    cat, kind, ident = obs.category, obs.kind, obs.identifier
    fcat = obs.detail.get("file_category")
    if cat == "certificate" and kind == "modified":
        return "certificate_replaced"
    if cat == "manifest_element" and kind == "modified":
        d = obs.detail
        if "before_resolved" not in d and "after_resolved" not in d:
            return None
        before = d.get("before_resolved", d.get("before"))
        after = d.get("after_resolved", d.get("after"))
        return "manifest_reference_inlined" if before is not None and before == after else None
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
    fingerprint: NoiseFingerprint | None = None,
    planned_entries: set[str] | None = None,
    expected_signer: str | None = None,
    content_mismatch: ObservationClass = ObservationClass.UNEXPECTED,
) -> ExpectationVerdict:
    """Classify every observation in *diff* and decide whether it matches *expected*.

    Two modes:

    - **content fingerprint** (Phase E, *fingerprint* given): noise is accepted only when
      the APK's no-op baseline fingerprint holds the same difference with the same
      content (:mod:`apkforge.diff.normalization`). *allowed_noise_rules* and
      *allowed_residue* are ignored.
    - **path rules** (Phase C.5/D, no fingerprint): noise is accepted by the documented
      path rules, optionally limited to *allowed_noise_rules* / *allowed_residue*.
      Content is not compared (``assurance="path_rule"``).

    Args:
        diff: DiffEngine result, original (A) vs. modified (B).
        expected: changes the modification declared before it was applied.
        allowed_noise_rules: path-rules mode: noise is only accepted for these rule ids.
        allowed_residue: path-rules mode: ``(category, kind, identifier)`` observations
            from this APK's no-op baseline that no rule explains; accepted on exact match.
        fingerprint: content-fingerprint mode: this APK's accepted no-op differences.
        planned_entries: archive entries the applied plans compile into
            (:func:`~apkforge.diff.normalization.archive_entries_for`). A modified entry
            in this set is ``PLANNED_ENTRY`` when its semantic comparison is complete,
            ``UNKNOWN`` otherwise.
        expected_signer: SHA-256 of the certificate the rebuilt APK was signed with.
        content_mismatch: class for a difference whose path the fingerprint knows but
            whose content differs (``UNEXPECTED`` when the toolchain is the baseline's;
            ``UNKNOWN`` when the build toolchain could not be established).
    """
    from apkforge.diff.normalization import accepts

    observations = observe(diff)
    renames = {
        o.identifier: o.detail.get("old_path")
        for o in observations
        if o.category == "file" and o.kind == "renamed"
    }
    classified: list[ClassifiedObservation] = []
    observed_expected: list[ExpectedChange] = []
    rule_counts: dict[str, int] = {}
    planned = planned_entries or set()

    def put(obs: Observation, cls: ObservationClass, reason: str, **kw: str | None) -> None:
        classified.append(
            ClassifiedObservation(observation=obs, classification=cls, reason=reason, **kw)
        )

    def noise(obs: Observation, rule: str, reason: str, assurance: str) -> None:
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        put(obs, ObservationClass.REBUILD_NOISE, reason, rule=rule, assurance=assurance)

    for obs in observations:
        match = next((e for e in expected if e.matches(obs)), None)
        if match is not None:
            if match not in observed_expected:
                observed_expected.append(match)
            put(
                obs,
                ObservationClass.EXPECTED_MODIFICATION,
                match.description or "declared expected change",
                assurance="declared",
            )
            continue
        if obs.kind == "incomplete":
            put(
                obs,
                ObservationClass.UNKNOWN,
                "DiffEngine output was truncated; not every change could be classified",
            )
            continue
        rule = _noise_rule(obs, renames)

        if fingerprint is not None:
            entry = fingerprint.lookup(obs)
            if entry is not None:
                ok, why = accepts(entry, obs, expected_signer)
                if ok:
                    assurance = "content" if entry.policy == "exact" else str(entry.policy)
                    noise(obs, entry.rule, why, assurance)
                    continue
            if obs.category == "file" and obs.kind == "modified" and obs.identifier in planned:
                cls, why = _planned_entry(obs, diff)
                put(obs, cls, why, rule=entry.rule if entry else rule, assurance="semantic")
                continue
            if entry is not None:
                put(obs, content_mismatch, f"{why} (rule '{entry.rule}')", rule=entry.rule)
            elif rule is not None:
                put(
                    obs,
                    content_mismatch,
                    f"matches path rule '{rule}' but this difference does not occur in the "
                    "no-op rebuild of this APK",
                    rule=rule,
                )
            else:
                put(
                    obs,
                    ObservationClass.UNEXPECTED,
                    "not declared by the modification and not in this APK's no-op baseline",
                )
            continue

        # Path-rules mode (Phase C.5/D behaviour).
        if (
            rule is None
            and allowed_residue
            and (obs.category, obs.kind, obs.identifier) in allowed_residue
        ):
            rule = "baseline_residue"
        if rule is None:
            put(
                obs,
                ObservationClass.UNEXPECTED,
                "not declared by the modification and not explained by a noise rule",
            )
            continue
        if (
            allowed_noise_rules is not None
            and rule != "baseline_residue"
            and rule not in allowed_noise_rules
        ):
            put(
                obs,
                ObservationClass.UNEXPECTED,
                f"noise rule '{rule}' did not occur in this APK's no-op baseline",
                rule=rule,
            )
            continue
        noise(
            obs,
            rule,
            NOISE_RULES.get(rule, "recorded in this APK's no-op baseline"),
            "path_rule",
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
        mode="content_fingerprint" if fingerprint is not None else "path_rules",
        observations=classified,
        expected_observed=observed_expected,
        expected_missing=missing,
        noise_rule_counts=rule_counts,
        failures=failures,
    )


#: planned archive entry -> comparators whose completeness establishes its meaning
_PLANNED_ENTRY_COVERAGE: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (
        re.compile(r"^AndroidManifest\.xml$"),
        ("manifest_tree", "identity", "manifest", "permissions", "components", "intent_filters"),
    ),
    (_DEX_FILE, ("dex", "strings")),
)


def _planned_entry(obs: Observation, diff: DiffResult) -> tuple[ObservationClass, str]:
    for pattern, comparators in _PLANNED_ENTRY_COVERAGE:
        if not pattern.match(obs.identifier):
            continue
        incomplete = [
            c for c in comparators if c not in diff.comparisons or not diff.comparisons[c].complete
        ]
        if incomplete:
            return ObservationClass.UNKNOWN, (
                "planned entry, but its semantic comparison is incomplete "
                f"({', '.join(incomplete)})"
            )
        return ObservationClass.PLANNED_ENTRY, (
            "bytes change because a planned modification edits its source; its meaning is "
            f"compared by {', '.join(comparators)}"
        )
    return ObservationClass.UNKNOWN, (
        "planned entry whose content cannot be compared semantically (e.g. resources); "
        "the change cannot be verified"
    )
