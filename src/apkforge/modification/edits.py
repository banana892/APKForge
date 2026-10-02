"""Structural edits of a decoded (Apktool) ``AndroidManifest.xml``.

Shared by the C.5 boot-receiver modifier and the Phase D modification pipeline: a
plan declares the edits it will make as :class:`SourceEdit` objects, and after the
modifier ran, :func:`manifest_edits` computes the edits that actually happened so
the two can be compared exactly (:func:`same_edits`).

Every element and attribute is covered, including intent filters, ``<queries>`` and
``<meta-data>``, so this check also sees manifest content that DiffEngine does not
compare after the rebuild.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from pydantic import BaseModel

__all__ = ["SourceEdit", "manifest_edits", "same_edits"]

_A = "{http://schemas.android.com/apk/res/android}"


class SourceEdit(BaseModel):
    """One structural edit of the decoded manifest."""

    kind: str  # remove_element | add_element | set_attribute
    element: str  # stable element key, e.g. manifest/receiver[name=a.B]
    attribute: str | None = None
    before: str | None = None
    after: str | None = None


def _element_index(manifest_xml: str) -> dict[str, dict[str, str]]:
    """Map a stable key per element to its attributes (android: prefix restored)."""
    root = ET.fromstring(manifest_xml)  # noqa: S314 - Apktool output from our workspace
    index: dict[str, dict[str, str]] = {}

    def attrs(el: ET.Element) -> dict[str, str]:
        out = {k.replace(_A, "android:"): v for k, v in el.attrib.items()}
        if (el.text or "").strip():
            out["#text"] = (el.text or "").strip()
        return out

    def walk(el: ET.Element, prefix: str) -> None:
        unnamed: dict[str, int] = {}
        for child in el:
            name = child.get(f"{_A}name")
            if name is not None:
                key = f"{prefix}/{child.tag}[name={name}]"
            else:
                n = unnamed.get(child.tag, 0)
                unnamed[child.tag] = n + 1
                key = f"{prefix}/{child.tag}[{n}]"
            while key in index:  # duplicate names: disambiguate deterministically
                key += "+"
            index[key] = attrs(child)
            walk(child, key)

    index[root.tag] = attrs(root)
    walk(root, root.tag)
    return index


def manifest_edits(before_xml: str, after_xml: str) -> list[SourceEdit]:
    """Structural difference between two decoded manifests."""
    a, b = _element_index(before_xml), _element_index(after_xml)
    edits: list[SourceEdit] = []
    for key in sorted(a.keys() - b.keys()):
        edits.append(SourceEdit(kind="remove_element", element=key))
    for key in sorted(b.keys() - a.keys()):
        edits.append(SourceEdit(kind="add_element", element=key))
    for key in sorted(a.keys() & b.keys()):
        for attr in sorted(a[key].keys() | b[key].keys()):
            if a[key].get(attr) != b[key].get(attr):
                edits.append(
                    SourceEdit(
                        kind="set_attribute",
                        element=key,
                        attribute=attr,
                        before=a[key].get(attr),
                        after=b[key].get(attr),
                    )
                )
    return edits


def same_edits(a: list[SourceEdit], b: list[SourceEdit]) -> bool:
    """True if *a* and *b* contain the same edits, in any order."""

    def key(e: SourceEdit) -> tuple[Any, ...]:
        return (e.kind, e.element, e.attribute, e.before, e.after)

    return sorted(map(key, a), key=repr) == sorted(map(key, b), key=repr)
