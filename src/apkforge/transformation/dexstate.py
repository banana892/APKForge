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

from apkforge.inspection.dex import (
    _DEX_PATTERN,
    _FRAMEWORK_PREFIXES,
    _dalvik_to_java,
    _parse_params,
)
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
    "CallSiteApiState",
    "ClassCensus",
    "MethodBlock",
    "call_site_api_state",
    "class_api_references",
    "method_api_references",
    "method_census",
    "method_key",
    "pool_tokens",
    "split_method_block",
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


def method_key(name: str, descriptor: str) -> str:
    """The method identity the Phase E DEX differ uses: ``name(p1,p2)ret``.

    Built from the smali proto (``(I)V`` -> ``foo(int)V``, ``()Ljava/lang/String;`` ->
    ``bar()java.lang.String``) exactly as :class:`~apkforge.inspection.dex.DEXInspector`
    builds :class:`~apkforge.inspection.dex.MethodInfo`: parameter types through
    :func:`_parse_params` + :func:`_dalvik_to_java` (primitives spelled out, ``I`` ->
    ``int``), the return type through :func:`_dalvik_to_java` only (``V`` stays ``V``).
    So a value this function returns matches the key the differ reports for the method.
    """
    close = descriptor.index(")")
    params = [_dalvik_to_java(p) for p in _parse_params(descriptor[1:close])]
    ret = _dalvik_to_java(descriptor[close + 1 :])
    return f"{name}({','.join(params)}){ret}"


@dataclass
class MethodBlock:
    """One ``.method`` block of a decoded smali file, located by name + descriptor."""

    signature: str
    #: smali text of the block (``.method`` header through ``.end method``, inclusive)
    text: str
    #: the file with the block (and the newline after it) removed
    without: str
    #: project-relative smali path the block lives in
    source_file: str


_METHOD_HEADER = re.compile(r"^\.method\b")


def split_method_block(text: str, signature: str) -> MethodBlock | None:
    """Locate the single ``.method`` block whose signature (``name`` + smali proto) is
    *signature* and split *text* into (block, text without the block). ``None`` if the
    block is absent; the caller treats more than one match as ambiguous."""
    lines = text.splitlines(keepends=True)
    starts = [
        i
        for i, raw in enumerate(lines)
        if _METHOD_HEADER.match(_strip_comment(raw).strip())
        and (parts := _strip_comment(raw).split())
        and parts[-1] == signature
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    end = next(
        (
            j
            for j in range(start + 1, len(lines))
            if _strip_comment(lines[j]).strip() == ".end method"
        ),
        None,
    )
    if end is None:
        return None
    block = "".join(lines[start : end + 1])
    without = "".join(lines[:start] + lines[end + 1 :])
    return MethodBlock(signature=signature, text=block, without=without, source_file="")


def method_census(text: str) -> list[str]:
    """Signatures (``name`` + smali proto) of every ``.method`` declared in *text*,
    in source order (duplicates kept)."""
    out: list[str] = []
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if _METHOD_HEADER.match(line):
            parts = line.split()
            if len(parts) > 1:
                out.append(parts[-1])
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


def _output_api_references(output: str) -> set[str]:
    """Framework API references of one instruction's output, exactly as
    :class:`~apkforge.inspection.dex.DEXInspector` extracts them."""
    refs: set[str] = set()
    for prefix in _FRAMEWORK_PREFIXES:
        if prefix in output:
            for part in output.split():
                if part.startswith("L") and part.endswith(";"):
                    refs.add(_dalvik_to_java(part))
    return refs


def _instruction_api_references(method: object) -> set[str]:
    refs: set[str] = set()
    with contextlib.suppress(Exception):
        code = method.get_code()  # type: ignore[attr-defined]
        bc = code.get_bc() if code else None
        if not bc:
            return refs
        for inst in bc.get_instructions():
            output = inst.get_output()
            if output:
                refs |= _output_api_references(output)
    return refs


def method_api_references(apk: Path) -> dict[tuple[str, str], set[str]]:
    """(class name, :func:`method_key`) -> framework API references of that one method,
    collected exactly as :func:`class_api_references` collects them per class. The union
    of the values is identical to the per-class attribution and to the DEX inventory, so
    the API references a method removal makes disappear are the target method's references
    minus every other method's."""
    from androguard.core.dex import DEX

    out: dict[tuple[str, str], set[str]] = {}
    with zipfile.ZipFile(apk) as z:
        names = sorted(
            i.filename for i in z.infolist() if not i.is_dir() and _DEX_PATTERN.search(i.filename)
        )
        for name in names:
            dex = DEX(z.read(name))
            for cls in dex.get_classes():
                cname = _dalvik_to_java(cls.get_name())
                for method in cls.get_methods():
                    key = method_key(method.get_name(), method.get_descriptor())
                    bucket = out.setdefault((cname, key), set())
                    bucket |= _instruction_api_references(method)
    return out


def _androguard_ref(smali_ref: str) -> str:
    """``Lx/A;->f(IJLy;)V`` as androguard prints it in an instruction's output
    (``Lx/A;->f(I J Ly;)V``: parameter types separated by spaces)."""
    head, _, rest = smali_ref.partition("(")
    params, _, ret = rest.partition(")")
    return f"{head}({' '.join(split_proto(params) or [])}){ret}"


@dataclass
class CallSiteApiState:
    """Framework API references of an APK before and after one call-site replacement.

    ``after`` is derived from the original DEX: every instruction's references, with the
    one located invocation's output rewritten from the original to the replacement method
    reference (the same extraction Phase E applies to the rebuilt DEX)."""

    inventory: set[str]
    after: set[str]
    #: the instruction output of the located invocation, before / after
    output_before: str = ""
    output_after: str = ""

    @property
    def removed(self) -> set[str]:
        return self.inventory - self.after

    @property
    def added(self) -> set[str]:
        return self.after - self.inventory


def call_site_api_state(
    apk: Path,
    caller_class: str,
    caller_method: str,
    original: str,
    replacement: str,
    occurrence: int,
) -> CallSiteApiState | None:
    """Locate the *occurrence*-th invocation of *original* (smali ``Lx/A;->f(I)V``) in
    *caller_method* (``name`` + smali proto) of *caller_class* and predict the API
    reference inventory after it invokes *replacement* instead. None when the invocation
    cannot be located exactly (the expected change then cannot be declared)."""
    from androguard.core.dex import DEX

    name, _, proto = caller_method.partition("(")
    proto = "(" + proto
    want_orig = _androguard_ref(original)
    want_repl = _androguard_ref(replacement)
    inventory: set[str] = set()
    after: set[str] = set()
    located: list[tuple[str, str]] = []
    with zipfile.ZipFile(apk) as z:
        names = sorted(
            i.filename for i in z.infolist() if not i.is_dir() and _DEX_PATTERN.search(i.filename)
        )
        for dex_name in names:
            dex = DEX(z.read(dex_name))
            for cls in dex.get_classes():
                is_caller_class = _dalvik_to_java(cls.get_name()) == caller_class
                for method in cls.get_methods():
                    is_caller = (
                        is_caller_class
                        and method.get_name() == name
                        and method.get_descriptor().replace(" ", "") == proto
                    )
                    seen = 0
                    with contextlib.suppress(Exception):
                        code = method.get_code()
                        bc = code.get_bc() if code else None
                        if not bc:
                            continue
                        for inst in bc.get_instructions():
                            output = inst.get_output()
                            if not output:
                                continue
                            refs = _output_api_references(output)
                            inventory |= refs
                            if (
                                is_caller
                                and inst.get_name().startswith("invoke-")
                                and output.endswith(want_orig)
                            ):
                                seen += 1
                                if seen == occurrence:
                                    rewritten = output[: -len(want_orig)] + want_repl
                                    located.append((output, rewritten))
                                    after |= _output_api_references(rewritten)
                                    continue
                            after |= refs
    if len(located) != 1:
        return None
    return CallSiteApiState(
        inventory=inventory, after=after, output_before=located[0][0], output_after=located[0][1]
    )


def replace_invocation(text: str, line: int, original: str, replacement: str) -> str | None:
    """*text* with the method reference *original* on the 1-based smali *line* replaced by
    *replacement*. The reference must end the instruction exactly once on that line and be
    preceded by the register list (``invoke-x {..}, <ref>``); None otherwise. Nothing else
    of the file (indentation, other lines, line endings) changes."""
    lines = text.splitlines(keepends=True)
    if not 1 <= line <= len(lines):
        return None
    raw = lines[line - 1]
    body = raw.rstrip("\r\n")
    ending = raw[len(body) :]
    code = _strip_comment(body)
    if code != body or code.count(original) != 1 or not code.endswith("}, " + original):
        return None
    lines[line - 1] = code[: -len(original)] + replacement + ending
    return "".join(lines)
