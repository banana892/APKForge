"""Security-relevant diff (Phase E4).

A presentation layer over the semantic diff that answers "which security-relevant
things changed?" instead of "how many files changed?". It is **descriptive**: every
item states an observed change, where it was observed and whether that area could be
compared completely. It never infers intent, risk or maliciousness — a new domain or
permission is reported as exactly that.

When an :class:`~apkforge.diff.expectations.ExpectationVerdict` is supplied, each item
also carries the classification of the corresponding observation (expected, planned
entry, rebuild noise, unexpected, unknown), so a reader can see at a glance whether a
security-relevant change was planned.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.diff.manifest_tree import explained_by
from apkforge.diff.models import ChangeType, ComparisonStatus

if TYPE_CHECKING:
    from apkforge.diff.expectations import ExpectationVerdict
    from apkforge.diff.models import ComponentChange, DiffResult

__all__ = [
    "SECURITY_CATEGORIES",
    "SECURITY_DIFF_SCHEMA_VERSION",
    "SecurityChange",
    "SecurityDiff",
    "SecuritySection",
    "build_security_diff",
]

SECURITY_DIFF_SCHEMA_VERSION = 1

#: category -> (title, comparators whose completeness determines availability)
SECURITY_CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "permissions": ("Permissions", ("permissions",)),
    "components": ("Components", ("components",)),
    "intent_filters": ("Intent filters", ("intent_filters",)),
    "certificate": ("Certificate", ("certificate",)),
    "network_domains": ("Network domains and IPs", ("network",)),
    "urls": ("URLs", ("network",)),
    "native_libraries": ("Native libraries", ("native",)),
    "dex": ("DEX classes", ("dex",)),
    "embedded_executables": ("Embedded executables/archives", ("embedded", "files")),
    "sensitive_manifest": ("Sensitive manifest changes", ("manifest", "identity")),
    "manifest_other": ("Other manifest elements", ("manifest_tree",)),
}

_SENSITIVE_APP_ATTRS = {
    "debuggable",
    "allowBackup",
    "usesCleartextTraffic",
    "networkSecurityConfig",
    "minSdkVersion",
    "targetSdkVersion",
}


class SecurityChange(BaseModel):
    category: str
    change: str  # added | removed | modified
    subject: str
    detail: dict[str, Any] = Field(default_factory=dict)
    evidence: str  # where the change was observed
    observation: list[str] = Field(default_factory=list)  # [category, kind, identifier]
    classification: str | None = None  # set when a verdict is supplied


class SecuritySection(BaseModel):
    title: str
    availability: str  # complete | partial | not_comparable | undetermined
    comparators: dict[str, str] = Field(default_factory=dict)
    items: list[SecurityChange] = Field(default_factory=list)


class SecurityDiff(BaseModel):
    """Security-relevant changes, grouped by category. Descriptive only."""

    schema_version: int = SECURITY_DIFF_SCHEMA_VERSION
    status: str  # complete | partial
    incomplete_categories: list[str] = Field(default_factory=list)
    sections: dict[str, SecuritySection] = Field(default_factory=dict)
    disclaimer: str = (
        "Observed changes only. A change in a security-relevant area is not evidence of "
        "malicious behaviour, and an empty section is not evidence of safety."
    )

    def items(self) -> list[SecurityChange]:
        return [i for s in self.sections.values() for i in s.items]

    def counts(self) -> dict[str, int]:
        return {k: len(s.items) for k, s in self.sections.items()}


def _availability(diff: DiffResult, comparators: tuple[str, ...]) -> tuple[str, dict[str, str]]:
    states = {}
    worst = "complete"
    order = ["complete", "partial", "not_comparable", "undetermined"]
    for c in comparators:
        res = diff.comparisons.get(c)
        if res is None:
            states[c] = "undetermined"
            worst = "undetermined"
            continue
        states[c] = str(res.status)
        if res.complete:
            continue
        level = {
            ComparisonStatus.PARTIAL: "partial",
            ComparisonStatus.NOT_COMPARABLE: "not_comparable",
        }.get(res.status, "undetermined")
        if order.index(level) > order.index(worst):
            worst = level
    return worst, states


def _comp_items(c: ComponentChange) -> list[SecurityChange]:
    from apkforge.diff.expectations import _component_detail

    obs = ["component", str(c.change_type), c.name]
    subject = f"{c.component_type} {c.name}"
    detail: dict[str, Any] = {"component_type": c.component_type}
    if c.change_type == ChangeType.ADDED:
        detail.update(
            exported=c.exported_after, enabled=c.enabled_after, permission=c.permission_after
        )
    elif c.change_type == ChangeType.REMOVED:
        detail.update(
            exported=c.exported_before, enabled=c.enabled_before, permission=c.permission_before
        )
    else:
        detail = {k: v for k, v in _component_detail(c).items() if k != "intent_filters"}
    items: list[SecurityChange] = []
    if c.change_type != ChangeType.MODIFIED or len(detail) > 1:
        items.append(
            SecurityChange(
                category="components",
                change=str(c.change_type),
                subject=subject,
                detail=detail,
                evidence="AndroidManifest.xml <application> component",
                observation=obs,
            )
        )
    ifd = c.intent_filter_diff
    if ifd is not None and ifd.has_changes:
        items.append(
            SecurityChange(
                category="intent_filters",
                change="modified",
                subject=subject,
                detail=ifd.model_dump(exclude_defaults=True),
                evidence="AndroidManifest.xml <intent-filter>",
                observation=obs,
            )
        )
    return items


def build_security_diff(
    diff: DiffResult, verdict: ExpectationVerdict | None = None
) -> SecurityDiff:
    """Group the security-relevant changes of *diff* (optionally classified)."""
    items: dict[str, list[SecurityChange]] = {k: [] for k in SECURITY_CATEGORIES}

    def add(
        cat: str,
        change: str,
        subject: str,
        evidence: str,
        obs: list[str],
        detail: dict[str, Any] | None = None,
    ) -> None:
        items[cat].append(
            SecurityChange(
                category=cat,
                change=change,
                subject=subject,
                detail=detail or {},
                evidence=evidence,
                observation=obs,
            )
        )

    p = diff.permissions
    for name in p.added:
        add("permissions", "added", name, "<uses-permission>", ["uses_permission", "added", name])
    for name in p.removed:
        add(
            "permissions",
            "removed",
            name,
            "<uses-permission>",
            ["uses_permission", "removed", name],
        )
    for name in p.declared_added:
        add(
            "permissions",
            "added",
            f"declared {name}",
            "<permission>",
            ["declared_permission", "added", name],
        )
    for name in p.declared_removed:
        add(
            "permissions",
            "removed",
            f"declared {name}",
            "<permission>",
            ["declared_permission", "removed", name],
        )
    for ch in p.declared_modified:
        add(
            "permissions",
            "modified",
            f"declared {ch.identifier}",
            "<permission>",
            ["declared_permission", "modified", ch.identifier],
            {"before": ch.before, "after": ch.after},
        )

    comps = diff.components
    for c in [*comps.activities, *comps.services, *comps.receivers, *comps.providers]:
        if c.change_type != ChangeType.UNCHANGED:
            for it in _comp_items(c):
                items[it.category].append(it)

    cert = diff.certificates
    if cert.status not in ("SAME", "UNCHANGED"):
        add(
            "certificate",
            "modified" if cert.status == "CHANGED" else cert.status.lower(),
            "signing certificate",
            "APK signature block / META-INF",
            ["certificate", "modified", "signing_certificate"],
            {
                "status": cert.status,
                "before": [c.get("sha256_fingerprint") for c in cert.certificates_before],
                "after": [c.get("sha256_fingerprint") for c in cert.certificates_after],
            },
        )

    n = diff.network
    for kind, values in (
        ("added", [*n.domains_added, *n.ips_added]),
        ("removed", [*n.domains_removed, *n.ips_removed]),
    ):
        for v in values:
            add(
                "network_domains",
                kind,
                v,
                "strings extracted from DEX/native/manifest",
                ["network_host", kind, v],
            )
    for kind, urls in (("added", n.urls_added), ("removed", n.urls_removed)):
        for u in urls:
            add(
                "urls",
                kind,
                u.url,
                u.source_file or "extracted strings",
                ["network_url", kind, u.url],
                {
                    k: v
                    for k, v in (
                        ("source_class", u.source_class),
                        ("source_method", u.source_method),
                    )
                    if v
                },
            )

    nat = diff.native
    for lib in [*nat.libraries_added, *nat.libraries_removed, *nat.libraries_modified]:
        add(
            "native_libraries",
            str(lib.change_type),
            lib.path,
            lib.path,
            ["native_library", str(lib.change_type), lib.path],
            {"abi": lib.abi, "sha256_before": lib.sha256_before, "sha256_after": lib.sha256_after},
        )
    for abi in nat.abis_added:
        add("native_libraries", "added", f"ABI {abi}", f"lib/{abi}/", ["native_abi", "added", abi])
    for abi in nat.abis_removed:
        add(
            "native_libraries",
            "removed",
            f"ABI {abi}",
            f"lib/{abi}/",
            ["native_abi", "removed", abi],
        )

    d = diff.dex
    for name in d.dex_files_added:
        add("dex", "added", f"DEX file {name}", name, ["dex_file", "added", name])
    for name in d.dex_files_removed:
        add("dex", "removed", f"DEX file {name}", name, ["dex_file", "removed", name])
    for name in d.classes_added:
        add("dex", "added", name, "DEX class definitions", ["dex_class", "added", name])
    for name in d.classes_removed:
        add("dex", "removed", name, "DEX class definitions", ["dex_class", "removed", name])
    for cd in d.classes_modified:
        add(
            "dex",
            "modified",
            cd.class_name,
            "DEX class definitions",
            ["dex_class", "modified", cd.class_name],
            {
                "methods_added": cd.methods_added,
                "methods_removed": cd.methods_removed,
                "methods_modified": [m.method_name for m in cd.methods_modified],
            },
        )

    e = diff.embedded
    for kind, values in (
        ("added", [*e.apks_added, *e.dex_added, *e.executables_added]),
        ("removed", [*e.apks_removed, *e.dex_removed, *e.executables_removed]),
    ):
        for v in values:
            add("embedded_executables", kind, v, v, ["embedded", kind, v])
    if diff.raw is not None:
        seen = {i.subject for i in items["embedded_executables"]}
        for r in diff.raw.changed():
            if str(r.kind) == "embedded_archive" and r.path not in seen:
                add(
                    "embedded_executables",
                    str(r.change),
                    r.path,
                    r.path,
                    ["file", str(r.change), r.path],
                    {"sha256_before": r.sha256_before, "sha256_after": r.sha256_after},
                )

    for ch in diff.identity.changes:
        add(
            "sensitive_manifest",
            "modified",
            f"identity {ch.identifier}",
            "<manifest>",
            ["identity", "modified", ch.identifier],
            {"before": ch.before, "after": ch.after},
        )
    for ch in [*diff.manifest.attribute_changes, *diff.manifest.sdk_changes]:
        if ch.identifier in _SENSITIVE_APP_ATTRS:
            add(
                "sensitive_manifest",
                "modified",
                ch.identifier,
                "<application>/<uses-sdk>",
                ["manifest_attribute", "modified", ch.identifier],
                {"before": ch.before, "after": ch.after},
            )
    for tc in diff.manifest_tree.changes:
        if explained_by(tc, diff) is None:
            add(
                "manifest_other",
                tc.kind,
                tc.identifier,
                f"AndroidManifest.xml <{tc.tag}>",
                ["manifest_element", tc.kind, tc.identifier],
                tc.detail() if tc.kind != "modified" else {"before": tc.before, "after": tc.after},
            )

    if verdict is not None:
        cls = {
            (c.observation.category, c.observation.kind, c.observation.identifier): str(
                c.classification
            )
            for c in verdict.observations
        }
        for lst in items.values():
            for it in lst:
                if len(it.observation) == 3:
                    it.classification = cls.get(
                        (it.observation[0], it.observation[1], it.observation[2])
                    )

    sections: dict[str, SecuritySection] = {}
    incomplete: list[str] = []
    for cat, (title, comparators) in SECURITY_CATEGORIES.items():
        availability, states = _availability(diff, comparators)
        if availability != "complete":
            incomplete.append(cat)
        sections[cat] = SecuritySection(
            title=title,
            availability=availability,
            comparators=states,
            items=sorted(items[cat], key=lambda i: (i.change, i.subject)),
        )
    return SecurityDiff(
        status="partial" if incomplete else "complete",
        incomplete_categories=incomplete,
        sections=sections,
    )
