"""Parsing and resolution of H.2 transformation targets.

Accepted forms::

    class   com.example.Foo | com/example/Foo | Lcom/example/Foo;
    method  com.example.Foo->bar(I)V | Lcom/example/Foo;->bar(I)V | com.example.Foo->bar

A method without a proto matches every overload; more than one is ``TARGET_AMBIGUOUS``.
Names are never guessed: an unqualified class name is ``TARGET_NOT_FULLY_QUALIFIED``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkforge.reference.smali import normalize_class_name, split_proto
from apkforge.transformation.models import (
    DecisionReason,
    TargetKind,
    TransformationTarget,
)

if TYPE_CHECKING:
    from apkforge.reference.models import DefinedClass, DefinedMethod

__all__ = ["ParseError", "Resolution", "parse_target", "resolve_class", "resolve_method"]

_IDENT = r"[A-Za-z_$][\w$-]*"
_CLASS_RE = re.compile(rf"{_IDENT}(?:\.{_IDENT})*")
_PROTO_RE = re.compile(r"\((?P<params>[^)]*)\)(?P<ret>\[*(?:L[^;\s]+;|[ZBSCIJFDV]))")
_METHOD_NAME_RE = re.compile(r"<init>|<clinit>|[^\s(<>;/.\[]+")


@dataclass(frozen=True)
class ParseError:
    code: DecisionReason
    message: str


def _class(raw: str) -> str | None:
    text = raw.strip()
    if text.startswith("["):
        return None  # arrays are not class definitions
    cls = normalize_class_name(text)
    return cls if _CLASS_RE.fullmatch(cls) else None


def parse_target(kind: TargetKind, raw: str) -> TransformationTarget | ParseError:
    """Normalise *raw* for a transformation whose target type is *kind*."""
    text = raw.strip()
    if "->" in text:
        owner, _, member = text.partition("->")
        if kind is not TargetKind.METHOD:
            return ParseError(
                DecisionReason.UNSUPPORTED_TARGET_TYPE,
                f"{raw!r} is a member target; this transformation targets a class",
            )
        cls = _class(owner)
        paren = member.find("(")
        name, proto = (member, None) if paren < 0 else (member[:paren], member[paren:])
        if cls is None or not _METHOD_NAME_RE.fullmatch(name):
            return ParseError(
                DecisionReason.UNSUPPORTED_TARGET_TYPE,
                f"{raw!r} is not a method target (expected com.example.Foo->name(Proto))",
            )
        if proto is not None:
            m = _PROTO_RE.fullmatch(proto)
            if m is None or split_proto(m.group("params")) is None:
                return ParseError(
                    DecisionReason.UNSUPPORTED_TARGET_TYPE,
                    f"{proto!r} is not a smali method descriptor such as (ILjava/lang/String;)V",
                )
        return TransformationTarget(
            kind=TargetKind.METHOD, class_name=cls, method_name=name, descriptor=proto, raw=raw
        )
    if kind is not TargetKind.CLASS:
        return ParseError(
            DecisionReason.UNSUPPORTED_TARGET_TYPE,
            f"{raw!r} is a class target; this transformation targets a method "
            "(com.example.Foo->name(Proto))",
        )
    cls = _class(text)
    if cls is None:
        return ParseError(
            DecisionReason.UNSUPPORTED_TARGET_TYPE,
            f"{raw!r} is not a class name (primitive/array types and malformed names are "
            "not class targets)",
        )
    return TransformationTarget(kind=TargetKind.CLASS, class_name=cls, raw=raw)


@dataclass(frozen=True)
class Resolution:
    """Outcome of resolving a target against the defined classes."""

    defined: DefinedClass | None = None
    method: DefinedMethod | None = None
    code: DecisionReason | None = None
    message: str = ""
    candidates: tuple[str, ...] = ()


def resolve_class(
    target: TransformationTarget,
    classes: dict[str, DefinedClass],
    simple_names: dict[str, list[str]],
) -> Resolution:
    cls = target.class_name
    found = classes.get(cls)
    if found is not None:
        if found.duplicate_sources:
            sources = (found.source_file, *found.duplicate_sources)
            return Resolution(
                code=DecisionReason.TARGET_AMBIGUOUS,
                message=f"{cls} is defined {len(sources)} times ({', '.join(sources)})",
                candidates=sources,
            )
        return Resolution(defined=found)
    if "." not in cls:
        candidates = tuple(sorted(simple_names.get(cls, ())))
        if len(candidates) > 1:
            return Resolution(
                code=DecisionReason.TARGET_AMBIGUOUS,
                message=f"{cls!r} matches {len(candidates)} classes: {', '.join(candidates[:10])}",
                candidates=candidates,
            )
        if candidates:
            return Resolution(
                code=DecisionReason.TARGET_NOT_FULLY_QUALIFIED,
                message=f"{cls!r} is not fully qualified (did you mean {candidates[0]}?)",
                candidates=candidates,
            )
    return Resolution(
        code=DecisionReason.TARGET_NOT_FOUND, message=f"{cls} is not defined in the analysed DEX"
    )


def resolve_method(target: TransformationTarget, defined: DefinedClass) -> Resolution:
    matches = [
        m
        for m in defined.methods
        if m.name == target.method_name
        and (target.descriptor is None or m.descriptor == target.descriptor)
    ]
    label = f"{defined.name}->{target.method_name}{target.descriptor or ''}"
    if not matches:
        return Resolution(
            defined=defined,
            code=DecisionReason.TARGET_NOT_FOUND,
            message=f"{label} is not declared by {defined.name}",
        )
    if len(matches) > 1:
        sigs = tuple(sorted(m.signature for m in matches))
        return Resolution(
            defined=defined,
            code=DecisionReason.TARGET_AMBIGUOUS,
            message=f"{label} matches {len(sigs)} overloads: {', '.join(sigs)}",
            candidates=sigs,
        )
    return Resolution(defined=defined, method=matches[0])
