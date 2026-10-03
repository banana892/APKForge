"""Read-only DEX state used by H.3: class census, string-pool attribution, API attribution.

H.3 must declare, *before* mutating anything, every semantic change Phase E will
observe when one class is removed. Removing a class removes its definition and every
DEX string-pool entry / framework API reference that no remaining class uses. This
module derives those consequences from the decoded smali (string pool) and from the
original DEX (API references, mirroring :class:`~apkforge.inspection.dex.DEXInspector`);
an incorrect prediction in either direction makes the verification fail (an unpredicted
change is UNEXPECTED, a predicted change that does not happen is a missing expectation).

Nothing here writes a file.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkforge.inspection.dex import _DEX_PATTERN, _FRAMEWORK_PREFIXES, _dalvik_to_java
from apkforge.reference.smali import (
    _read_string,
    _strip_comment,
    class_name_from_descriptor,
    dex_name_for_smali_root,
    split_proto,
)

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "ClassCensus",
    "class_api_references",
    "pool_tokens",
    "take_census",
]

_DESC = re.compile(r"\[*L[^;\s\"]+;|\[+[ZBSCIJFDV]")
_TYPE = r"\[*(?:L[^;\s\"]+;|[ZBSCIJFDV])"
_PROTO = re.compile(rf"\(((?:{_TYPE})*)\)({_TYPE})")
_MEMBER = re.compile(r"->([^\s(:\"]+)")
_METHOD_DEF = re.compile(r"^\.method\s+(?:[a-z-]+\s+)*([^\s(]+)\(")
_FIELD_DEF = re.compile(r"^\.field\s+(?:[a-z-]+\s+)*([^\s:]+):")
_ELEMENT = re.compile(r"^([\w$]+)\s*=")
_SPLIT = re.compile(r"[\s,{}()]+|->|:")


@dataclass
class ClassCensus:
    """Every class definition in a decoded project (by the ``.class`` directive)."""

    #: class name -> project-relative smali paths defining it (sorted)
    classes: dict[str, list[str]] = field(default_factory=dict)
    #: project-relative smali path -> DEX it is assembled into
    dex_of: dict[str, str] = field(default_factory=dict)
    #: smali files without a readable ``.class`` directive
    unparsed: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(len(v) for v in self.classes.values())

    def classes_in(self, dex: str) -> int:
        return sum(1 for p, d in self.dex_of.items() if d == dex and p not in self.unparsed)

    def digest(self) -> str:
        """SHA-256 over the sorted (class, path) list."""
        h = hashlib.sha256()
        for name in sorted(self.classes):
            for path in self.classes[name]:
                h.update(f"{name}\t{path}\n".encode())
        return h.hexdigest()


def _class_directive(text: str) -> str | None:
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if line.startswith(".class"):
            parts = line.split()
            name, dims = class_name_from_descriptor(parts[-1]) if len(parts) > 1 else (None, 0)
            return name if dims == 0 else None
        if line and not line.startswith("#"):
            return None
    return None


def take_census(decoded_dir: Path) -> ClassCensus:
    census = ClassCensus()
    roots = sorted(
        p for p in decoded_dir.iterdir() if p.is_dir() and dex_name_for_smali_root(p.name)
    )
    for root in roots:
        dex = dex_name_for_smali_root(root.name)
        assert dex is not None
        for path in sorted(root.rglob("*.smali")):
            rel = path.relative_to(decoded_dir).as_posix()
            census.dex_of[rel] = dex
            try:
                name = _class_directive(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                name = None
            if name is None:
                census.unparsed.append(rel)
            else:
                census.classes.setdefault(name, []).append(rel)
    for paths in census.classes.values():
        paths.sort()
    return census


def _quoted(line: str) -> tuple[list[str], str]:
    """String literals in *line* and the line with the literals blanked out."""
    values: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(line):
        if line[i] == '"':
            parsed = _read_string(line[i:])
            if parsed is None:
                rest.append(line[i:])
                break
            value, tail = parsed
            values.append(value)
            rest.append(" ")
            i = len(line) - len(tail)
            continue
        rest.append(line[i])
        i += 1
    return values, "".join(rest)


def _shorty(params: str, ret: str) -> str | None:
    types = split_proto(params)
    if types is None:
        return None
    return "".join("L" if t[0] in "L[" else t for t in (ret, *types))


def pool_tokens(text: str, *, generous: bool = False) -> set[str]:
    """Strings one smali class contributes to its DEX string pool.

    Covers type descriptors, member and declaration names, prototype shorties, string
    literals (``const-string``, ``.source``, debug names, annotation values) and
    annotation element names. ``generous`` also adds every bare token and the element
    type of array descriptors: used for the classes that stay, so that a string they
    may still use is never predicted to disappear.
    """
    out: set[str] = set()
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        literals, code = _quoted(line)
        out.update(literals)
        for m in _DESC.finditer(code):
            out.add(m.group(0))
            if generous:
                out.add(m.group(0).lstrip("["))
        for m in _PROTO.finditer(code):
            shorty = _shorty(m.group(1), m.group(2))
            if shorty:
                out.add(shorty)
        out.update(m.group(1) for m in _MEMBER.finditer(code))
        for rx in (_METHOD_DEF, _FIELD_DEF, _ELEMENT):
            if found := rx.match(code):
                out.add(found.group(1))
        if generous:
            out.update(t for t in _SPLIT.split(code) if t)
    return out


def class_api_references(apk: Path) -> dict[str, set[str]]:
    """Class name -> framework API references, exactly as the Phase E DEX inspector
    collects them (per DEX file, from each method's instruction output)."""
    from androguard.core.dex import DEX

    out: dict[str, set[str]] = {}
    with zipfile.ZipFile(apk) as z:
        names = sorted(
            i.filename for i in z.infolist() if not i.is_dir() and _DEX_PATTERN.search(i.filename)
        )
        for name in names:
            dex = DEX(z.read(name))
            for cls in dex.get_classes():
                refs = out.setdefault(_dalvik_to_java(cls.get_name()), set())
                for method in cls.get_methods():
                    with contextlib.suppress(Exception):
                        code = method.get_code()
                        bc = code.get_bc() if code else None
                        if not bc:
                            continue
                        for inst in bc.get_instructions():
                            output = inst.get_output()
                            if not output:
                                continue
                            for prefix in _FRAMEWORK_PREFIXES:
                                if prefix in output:
                                    for part in output.split():
                                        if part.startswith("L") and part.endswith(";"):
                                            refs.add(_dalvik_to_java(part))
    return out
