"""Full manifest tree comparison (Phase E3).

The specialised manifest differs (identity, permissions, components, intent filters, a
handful of ``<application>`` attributes) compare the fields the inspection model
extracts. Anything outside those fields — ``<queries>``, ``<meta-data>``,
``<uses-feature>``, ``<activity-alias>``, most attributes — was invisible to them.

This module compares the *whole* binary manifest instead. Both ``AndroidManifest.xml``
entries are decoded with Androguard's ``AXMLPrinter`` and flattened into elements keyed
by a stable path (``application/receiver[name=X]/intent-filter#0/action[name=Y]``).
Every attribute of every element is compared; values are compared exactly as decoded
(resource references stay ``@7F0A0001``, they are not resolved).

Each difference is a :class:`ManifestTreeChange`. :func:`explained_by` decides whether a
specialised differ already reports that exact fact; the remaining *residual* changes
become ``manifest_element`` observations in :mod:`apkforge.diff.expectations`, so a
manifest difference can no longer pass verification merely because no specialised
differ looks at it.

Element identity:

- ``android:name`` (most elements), ``android:authorities`` (``<queries><provider>``),
  ``android:glEsVersion`` (``<uses-feature>`` without a name)
- ``<data>``: all of its attributes
- anything else (``intent-filter``, ``intent``, ``uses-sdk``, ``application``...): its
  position among same-tag siblings (``#0``, ``#1``...)

Repeated identities among siblings get an occurrence suffix (``~1``). Positional keys
mean that inserting an unnamed element before a sibling shifts the later ones; that is
reported as changes (never hidden).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.diff.models import DiffResult

__all__ = [
    "REFERENCE",
    "ManifestTree",
    "ManifestTreeChange",
    "ManifestTreeDiff",
    "diff_manifest_trees",
    "explained_by",
    "load_manifest_tree",
    "parse_manifest_xml",
    "resolve_references",
]

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
# ComponentDiffer attribute -> key in the observation detail (expectations._component_detail)
_COMPONENT_ATTR_DETAIL = {
    "android:exported": "exported",
    "android:enabled": "enabled",
    "android:permission": "permission",
    "android:process": "process",
    "android:directBootAware": "direct_boot_aware",
    "android:foregroundServiceType": "foreground_service_type",
    "android:authorities": "authorities",
    "android:readPermission": "read_permission",
    "android:writePermission": "write_permission",
}
_APPLICATION_ATTRS = {
    "android:debuggable": "debuggable",
    "android:allowBackup": "allowBackup",
    "android:usesCleartextTraffic": "usesCleartextTraffic",
    "android:networkSecurityConfig": "networkSecurityConfig",
    "android:label": "label",
}
_SDK_ATTRS = {
    "android:minSdkVersion": "minSdkVersion",
    "android:targetSdkVersion": "targetSdkVersion",
}
_ROOT_IDENTITY_ATTRS = {
    "package": "package_name",
    "android:versionName": "version_name",
    "android:versionCode": "version_code",
}


class ManifestTree(BaseModel):
    """A flattened manifest: element key -> {tag, attributes}."""

    elements: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def subtree(self, key: str) -> dict[str, dict[str, Any]]:
        prefix = key + "/"
        return {k: v for k, v in self.elements.items() if k == key or k.startswith(prefix)}


class ManifestTreeChange(BaseModel):
    """One manifest difference: an element added/removed, or one attribute modified."""

    kind: str  # added | removed | modified
    element: str
    tag: str
    attribute: str | None = None
    before: str | None = None
    after: str | None = None
    #: added/removed: every element of the subtree (key -> attributes)
    subtree: dict[str, dict[str, str]] = Field(default_factory=dict)
    #: modified: value of a ``@7Fxxxxxx`` reference, set only when every resource
    #: configuration of that APK holds the same single string (see resolve_references)
    before_resolved: str | None = None
    after_resolved: str | None = None

    @property
    def identifier(self) -> str:
        return f"{self.element}@{self.attribute}" if self.attribute else self.element

    def detail(self) -> dict[str, Any]:
        if self.kind == "modified":
            d: dict[str, Any] = {"tag": self.tag, "before": self.before, "after": self.after}
            if self.before_resolved is not None:
                d["before_resolved"] = self.before_resolved
            if self.after_resolved is not None:
                d["after_resolved"] = self.after_resolved
            return d
        digest = hashlib.sha256(
            json.dumps(self.subtree, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return {"tag": self.tag, "elements": len(self.subtree), "subtree_sha256": digest}


class ManifestTreeDiff(BaseModel):
    """Result of the full manifest comparison."""

    status: str = "not_comparable"  # complete | not_comparable | failed
    reason: str | None = None
    elements_before: int = 0
    elements_after: int = 0
    changes: list[ManifestTreeChange] = Field(default_factory=list)


def _attr_name(raw: str) -> str:
    if raw.startswith(_ANDROID_NS):
        return "android:" + raw[len(_ANDROID_NS) :]
    if raw.startswith("{"):
        return raw.split("}", 1)[1]
    return raw


def _identity(tag: str, attrs: dict[str, str], parent_tag: str | None) -> str | None:
    if tag == "data":
        return ",".join(f"{k}={v}" for k, v in sorted(attrs.items()))
    if "android:name" in attrs:
        return "name=" + attrs["android:name"]
    if tag == "provider" and parent_tag == "queries" and "android:authorities" in attrs:
        return "authorities=" + attrs["android:authorities"]
    if tag == "uses-feature" and "android:glEsVersion" in attrs:
        return "glEsVersion=" + attrs["android:glEsVersion"]
    return None


def parse_manifest_xml(xml: bytes | str) -> ManifestTree:
    """Flatten a (text) manifest XML document into a :class:`ManifestTree`."""
    root = ET.fromstring(xml)  # noqa: S314 - decoded from a local APK, no entity expansion
    elements: dict[str, dict[str, Any]] = {}

    def walk(el: ET.Element, key: str) -> None:
        attrs = {_attr_name(k): v for k, v in el.attrib.items()}
        elements[key] = {"tag": el.tag, "attributes": dict(sorted(attrs.items()))}
        positions: dict[str, int] = {}
        seen: dict[str, int] = {}
        for child in el:
            if not isinstance(child.tag, str):  # comments / processing instructions
                continue
            c_attrs = {_attr_name(k): v for k, v in child.attrib.items()}
            ident = _identity(child.tag, c_attrs, el.tag)
            if ident is None:
                pos = positions.get(child.tag, 0)
                positions[child.tag] = pos + 1
                seg = f"{child.tag}#{pos}"
            else:
                seg = f"{child.tag}[{ident}]"
            n = seen.get(seg, 0)
            seen[seg] = n + 1
            if n:
                seg = f"{seg}~{n}"
            walk(child, seg if key == "manifest" else f"{key}/{seg}")

    walk(root, "manifest")
    return ManifestTree(elements=elements)


def load_manifest_tree(apk: Path) -> ManifestTree:
    """Decode ``AndroidManifest.xml`` from *apk*. Raises on any failure."""
    from androguard.core.axml import AXMLPrinter

    with contextlib.suppress(ImportError):
        from loguru import logger

        logger.disable("androguard")
    with zipfile.ZipFile(apk) as z:
        raw = z.read("AndroidManifest.xml")
    printer = AXMLPrinter(raw)
    xml = printer.get_xml()
    if not xml or not printer.is_valid():
        raise ValueError("AndroidManifest.xml could not be decoded as binary XML")
    return parse_manifest_xml(xml)


def diff_manifest_trees(a: ManifestTree, b: ManifestTree) -> list[ManifestTreeChange]:
    """Every element and attribute difference between *a* and *b*."""
    changes: list[ManifestTreeChange] = []
    keys_a, keys_b = set(a.elements), set(b.elements)

    def top_level(keys: set[str]) -> list[str]:
        # Report an added/removed subtree once, at its top-most element.
        return sorted(k for k in keys if not any(k.startswith(p + "/") for p in keys if p != k))

    def flat(tree: ManifestTree, key: str) -> dict[str, dict[str, str]]:
        return {k: v["attributes"] for k, v in tree.subtree(key).items()}

    for key in top_level(keys_a - keys_b):
        changes.append(
            ManifestTreeChange(
                kind="removed", element=key, tag=a.elements[key]["tag"], subtree=flat(a, key)
            )
        )
    for key in top_level(keys_b - keys_a):
        changes.append(
            ManifestTreeChange(
                kind="added", element=key, tag=b.elements[key]["tag"], subtree=flat(b, key)
            )
        )
    for key in sorted(keys_a & keys_b):
        at_a, at_b = a.elements[key]["attributes"], b.elements[key]["attributes"]
        for attr in sorted(set(at_a) | set(at_b)):
            if at_a.get(attr) != at_b.get(attr):
                changes.append(
                    ManifestTreeChange(
                        kind="modified",
                        element=key,
                        tag=a.elements[key]["tag"],
                        attribute=attr,
                        before=at_a.get(attr),
                        after=at_b.get(attr),
                    )
                )
    return sorted(changes, key=lambda c: (c.element, c.attribute or "", c.kind))


REFERENCE = re.compile(r"^@(?:0x)?([0-9A-Fa-f]{8})$")


def resolve_references(apk: Path, refs: set[str]) -> dict[str, str]:
    """Resolve ``@XXXXXXXX`` references with *apk*'s ``resources.arsc``.

    A reference is resolved only when every configuration of the resource holds the same
    single string value. A reference with configuration-dependent values (e.g. a
    translated string) is left unresolved, because replacing it with one literal would
    change behaviour for the other configurations.
    """
    ids = {r: int(m.group(1), 16) for r in refs if (m := REFERENCE.match(r))}
    if not ids:
        return {}
    from androguard.core.axml import ARSCParser

    with contextlib.suppress(ImportError):
        from loguru import logger

        logger.disable("androguard")
    out: dict[str, str] = {}
    try:
        with zipfile.ZipFile(apk) as z:
            parser = ARSCParser(z.read("resources.arsc"))
    except Exception:
        return out
    for ref, res_id in ids.items():
        try:
            values = {v for _, v in parser.get_resolved_res_configs(res_id)}
        except Exception:  # noqa: S112 - unresolvable stays unresolved (never assumed equal)
            continue
        if len(values) == 1:
            (value,) = values
            if isinstance(value, str):
                out[ref] = value
    return out


# ---------------------------------------------------------------------------
# Coverage by the specialised differs
# ---------------------------------------------------------------------------


def _segments(key: str) -> list[tuple[str, str | None]]:
    """``a/b[name=x]/c#0`` -> [(a, None), (b, 'x'), (c, None)] (name identities only)."""
    out: list[tuple[str, str | None]] = []
    for seg in key.split("/"):
        base = seg.split("~", 1)[0]
        if "[" in base and base.endswith("]"):
            tag, ident = base[:-1].split("[", 1)
            out.append((tag, ident[5:] if ident.startswith("name=") else None))
        else:
            out.append((base.split("#", 1)[0], None))
    return out


def _component_obs(diff: DiffResult) -> dict[str, Any]:
    comps = diff.components
    return {
        c.name: c
        for c in [*comps.activities, *comps.services, *comps.receivers, *comps.providers]
        if str(c.change_type) != "unchanged"
    }


def _filter_values(subtree: dict[str, dict[str, str]], tag: str) -> set[str]:
    return {
        attrs.get("android:name", "")
        for key, attrs in subtree.items()
        if key.rsplit("/", 1)[-1].startswith(f"{tag}[")
    }


def explained_by(change: ManifestTreeChange, diff: DiffResult) -> str | None:
    """The specialised observation that already reports *change*, or None (residual).

    Explanation is precise: an attribute counts as explained only when the specialised
    differ reported a change of that very attribute on that very element.
    """
    segs = _segments(change.element)
    tag, name = segs[-1]
    depth = len(segs)
    perms = diff.permissions

    # <manifest> root
    if change.element == "manifest" and change.kind == "modified":
        ident = _ROOT_IDENTITY_ATTRS.get(change.attribute or "")
        if ident and any(c.identifier == ident for c in diff.identity.changes):
            return f"identity {ident}"
        return None

    # <uses-permission>, <permission>
    if depth == 1 and tag in ("uses-permission", "uses-permission-sdk-23") and name:
        if change.kind == "added" and name in perms.added:
            return f"uses_permission added {name}"
        if change.kind == "removed" and name in perms.removed:
            return f"uses_permission removed {name}"
        return None
    if depth == 1 and tag == "permission" and name:
        if change.kind == "added" and name in perms.declared_added:
            return f"declared_permission added {name}"
        if change.kind == "removed" and name in perms.declared_removed:
            return f"declared_permission removed {name}"
        if change.kind == "modified" and any(c.identifier == name for c in perms.declared_modified):
            return f"declared_permission modified {name}"
        return None

    # <uses-sdk>
    if depth == 1 and tag == "uses-sdk" and change.kind == "modified":
        ident = _SDK_ATTRS.get(change.attribute or "")
        if ident and any(c.identifier == ident for c in diff.manifest.sdk_changes):
            return f"manifest_attribute {ident}"
        return None

    # <application> attributes
    if depth == 1 and tag == "application" and change.kind == "modified":
        ident = _APPLICATION_ATTRS.get(change.attribute or "")
        if ident and any(c.identifier == ident for c in diff.manifest.attribute_changes):
            return f"manifest_attribute {ident}"
        return None

    # Components (activity-alias is not modelled by ComponentDiffer: never explained)
    if depth >= 2 and segs[0][0] == "application" and segs[1][0] in _COMPONENT_TAGS:
        comp_tag, comp_name = segs[1]
        if comp_tag == "activity-alias" or comp_name is None:
            return None
        comp = _component_obs(diff).get(comp_name)
        if comp is None:
            return None
        if depth == 2:
            if change.kind in ("added", "removed"):
                return (
                    f"component {change.kind} {comp_name}"
                    if str(comp.change_type) == change.kind
                    else None
                )
            key = _COMPONENT_ATTR_DETAIL.get(change.attribute or "")
            if key is None:
                return None
            if key == "exported":
                changed = comp.exported_before != comp.exported_after
            else:
                changed = f"{key}_before" in comp.details or f"{key}_after" in comp.details
            return f"component modified {comp_name} ({key})" if changed else None
        # Inside an intent filter of the component.
        if segs[2][0] != "intent-filter" or comp.intent_filter_diff is None:
            return None
        ifd = comp.intent_filter_diff
        if change.kind == "modified":
            return None  # e.g. priority/autoVerify: not compared by IntentFilterDiff
        added = change.kind == "added"
        actions = set(ifd.actions_added if added else ifd.actions_removed)
        categories = set(ifd.categories_added if added else ifd.categories_removed)
        data_changed = bool(ifd.data_added if added else ifd.data_removed)
        sub_actions = _filter_values(change.subtree, "action")
        sub_categories = _filter_values(change.subtree, "category")
        has_data = any(k.rsplit("/", 1)[-1].startswith("data[") for k in change.subtree)
        other = [
            k
            for k in change.subtree
            if k.rsplit("/", 1)[-1].split("[", 1)[0].split("#", 1)[0]
            not in ("intent-filter", "action", "category", "data")
        ]
        if (
            not other
            and sub_actions <= actions
            and sub_categories <= categories
            and (not has_data or data_changed)
        ):
            return f"component modified {comp_name} (intent_filters)"
        return None
    return None
