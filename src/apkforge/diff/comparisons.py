"""Per-comparator status of a semantic diff (Phase E3).

``DiffResult.status`` says whether the whole diff is complete. That is not enough to
reason about a single area: a large DEX may be truncated while the manifest compares
fully, and the resource table is never compared semantically at all. Each comparator
therefore gets an explicit :class:`ComparatorResult`:

- ``unchanged`` / ``added`` / ``removed`` / ``modified``: the comparison completed and
  this is what it found
- ``partial``: some of the data was compared, not all (truncated extraction, an
  inspector reported warnings); a ``partial`` comparator that reports nothing is *not*
  evidence that nothing changed
- ``not_comparable``: the comparison is not implemented at this level (by design);
  the reason says what is compared instead
- ``undetermined``: the comparison failed or its inputs are missing

Inability to compare is never reported as ``unchanged``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, ComparatorResult, ComparisonStatus

if TYPE_CHECKING:
    from apkforge.diff.models import DiffResult
    from apkforge.inspection.models import InspectionResult

__all__ = [
    "COMPARATORS",
    "ComparatorResult",
    "ComparisonStatus",
    "assess_comparators",
]


#: comparator -> (inspectors it depends on, comparison level)
COMPARATORS: dict[str, tuple[tuple[str, ...], str]] = {
    "identity": (("manifest",), "semantic: package, version, SDK levels"),
    "manifest": (("manifest",), "semantic: selected <application> attributes, SDK levels"),
    "manifest_tree": ((), "structural: every manifest element and attribute (decoded XML)"),
    "permissions": (("manifest",), "semantic: uses-permission and declared permissions"),
    "components": (
        ("manifest",),
        "semantic: activities, services, receivers, providers (activity-alias: tree only)",
    ),
    "intent_filters": (("manifest",), "semantic: actions, categories, data per component"),
    "certificate": ((), "signing certificate fingerprints (SHA-256)"),
    "dex": (("dex",), "semantic: DEX files, classes, methods (code hash), fields"),
    "strings": (("dex",), "semantic: DEX string pool values"),
    "network": (("dex", "native", "manifest", "network"), "extracted URLs, domains, IPs"),
    "native": (("native",), "content-hash and ELF metadata per lib/<abi>/<name>.so"),
    "resources": ((), "content-hash per res/ entry (binary XML is not decoded)"),
    "resource_table": ((), "content-hash of resources.arsc; entries are not compared"),
    "assets": ((), "content-hash per assets/ entry"),
    "embedded": (("embedded",), "embedded APK/DEX/executable presence"),
    "files": ((), "content-hash per archive entry, with rename pairing"),
}


def _inspector_problems(
    a: InspectionResult | None, b: InspectionResult | None, inspectors: tuple[str, ...]
) -> tuple[list[str], bool]:
    """(problems, failed) for the inspectors a comparator depends on."""
    problems: list[str] = []
    failed = False
    for side, insp in (("A", a), ("B", b)):
        if insp is None:
            continue
        for name in inspectors:
            st = insp.inspector_statuses.get(name)
            if st is None:
                problems.append(f"{side}: {name} inspector did not run")
                failed = True
            elif st == "failed":
                problems.append(f"{side}: {name} inspector failed")
                failed = True
            elif st == "partial":
                problems.append(f"{side}: {name} inspector reported warnings (partial)")
    return problems, failed


def _status_for(changes: int) -> ComparisonStatus:
    return ComparisonStatus.MODIFIED if changes else ComparisonStatus.UNCHANGED


def assess_comparators(
    diff: DiffResult,
    insp_a: InspectionResult | None = None,
    insp_b: InspectionResult | None = None,
    failed: set[str] | None = None,
) -> dict[str, ComparatorResult]:
    """Derive a :class:`ComparatorResult` for every comparator in :data:`COMPARATORS`.

    Args:
        diff: the assembled diff.
        insp_a, insp_b: the inspections it was built from (inspector statuses). When
            absent (a diff built from pre-made data), inspector state is unknown and
            dependent comparators are ``undetermined``.
        failed: comparators whose differ raised (``DiffEngine._safe_run``).
    """
    failed = failed or set()
    p, comps, d = diff.permissions, diff.components, diff.dex
    all_comps = [*comps.activities, *comps.services, *comps.receivers, *comps.providers]
    changed_comps = [c for c in all_comps if c.change_type != ChangeType.UNCHANGED]
    files = [f for f in diff.files.entries if f.change_type != ChangeType.UNCHANGED]

    def n_files(category: str) -> int:
        return sum(1 for f in files if f.category == category)

    counts: dict[str, int] = {
        "identity": len(diff.identity.changes),
        "manifest": len(diff.manifest.attribute_changes) + len(diff.manifest.sdk_changes),
        "manifest_tree": len(diff.manifest_tree.changes),
        "permissions": len(p.added)
        + len(p.removed)
        + len(p.declared_added)
        + len(p.declared_removed)
        + len(p.declared_modified),
        "components": len(changed_comps),
        "intent_filters": sum(1 for c in all_comps if c.intent_filter_diff is not None),
        "certificate": len(diff.certificates.fingerprint_changes)
        or int(diff.certificates.status == "CHANGED"),
        "dex": len(d.dex_files_added)
        + len(d.dex_files_removed)
        + len(d.classes_added)
        + len(d.classes_removed)
        + len(d.classes_modified),
        "strings": diff.strings.total_added + diff.strings.total_removed,
        "network": len(diff.network.urls_added)
        + len(diff.network.urls_removed)
        + len(diff.network.domains_added)
        + len(diff.network.domains_removed)
        + len(diff.network.ips_added)
        + len(diff.network.ips_removed),
        "native": len(diff.native.libraries_added)
        + len(diff.native.libraries_removed)
        + len(diff.native.libraries_modified),
        "resources": n_files("resource"),
        "resource_table": n_files("resource_table"),
        "assets": n_files("asset"),
        "embedded": len(diff.embedded.apks_added)
        + len(diff.embedded.apks_removed)
        + len(diff.embedded.dex_added)
        + len(diff.embedded.dex_removed)
        + len(diff.embedded.executables_added)
        + len(diff.embedded.executables_removed),
        "files": len(files),
    }

    out: dict[str, ComparatorResult] = {}
    for name, (inspectors, level) in COMPARATORS.items():
        changes = counts[name]
        limitations: list[str] = []
        if name in failed:
            out[name] = ComparatorResult(
                comparator=name,
                status=ComparisonStatus.UNDETERMINED,
                complete=False,
                changes=changes,
                level=level,
                reason="the differ raised an exception; see diff limitations",
            )
            continue
        if insp_a is None or insp_b is None:
            problems, hard = (["inspection state unknown (diff built from data)"], True)
            if not inspectors:
                problems, hard = [], False
        else:
            problems, hard = _inspector_problems(insp_a, insp_b, inspectors)

        status = _status_for(changes)
        complete = True
        reason: str | None = None

        if name == "manifest_tree" and diff.manifest_tree.status != "complete":
            hard = True
            problems.append(diff.manifest_tree.reason or "manifest tree not compared")
        if name == "certificate":
            st = diff.certificates.status
            if st == "ADDED":
                status = ComparisonStatus.ADDED
            elif st == "REMOVED":
                status = ComparisonStatus.REMOVED
            elif diff.certificates.count_before == 0 and diff.certificates.count_after == 0:
                status, complete = ComparisonStatus.UNDETERMINED, False
                reason = "no certificate could be read from either APK"
        if name == "strings":
            s = diff.strings
            if s.total_added > len(s.added_sample) or s.total_removed > len(s.removed_sample):
                complete = False
                status = ComparisonStatus.PARTIAL
                reason = (
                    f"string enumeration truncated ({len(s.added_sample)}/{s.total_added} "
                    f"added, {len(s.removed_sample)}/{s.total_removed} removed listed)"
                )
        if name == "components":
            limitations.append(
                "<activity-alias> is not modelled as a component; alias changes are "
                "reported by manifest_tree only"
            )
        if name == "resources":
            limitations.append(
                "res/ binary XML and images are compared by content hash, not decoded; "
                "a same-path content change cannot be interpreted semantically"
            )
        if name == "resource_table" and changes:
            status = ComparisonStatus.NOT_COMPARABLE
            complete = False
            reason = (
                "resources.arsc differs; its entries are not compared semantically "
                "(only byte identity is established)"
            )
        if name == "native":
            limitations.append("native code is not analysed; hash and ELF metadata only")
        if name == "files" and diff.raw is None:
            limitations.append("raw archive diff not available (inputs were not APK files)")

        if hard:
            status, complete = ComparisonStatus.UNDETERMINED, False
            reason = "; ".join(problems)
        elif problems and complete:
            status, complete = ComparisonStatus.PARTIAL, False
            reason = "; ".join(problems)
        out[name] = ComparatorResult(
            comparator=name,
            status=status,
            complete=complete,
            changes=changes,
            level=level,
            reason=reason,
            limitations=limitations,
        )
    return out
