"""Conflict detection within one H.2 request set.

Requests are evaluated independently against the original APK, so a set that targets
the same artifact twice is contradictory (the second change would operate on a result
the first already altered). Every request involved in an overlap is REFUSED with
``CONFLICTING_TRANSFORMATION``; no plan is generated for it.

Overlaps:

- ``duplicate_class_target``   two class transformations on the same class
- ``duplicate_method_target``  two method transformations on the same method (a method
                               without a proto overlaps every overload of that name)
- ``class_method_overlap``     a class transformation and a method transformation on a
                               method of that class
- ``duplicate_call_site_method`` two call-site replacements inside the same caller method
                               (both rewrite that method's code)
- ``call_site_overlap``        a call-site replacement and a class / method transformation
                               of its caller, its invoked method or its replacement (H.6)
"""

from __future__ import annotations

from apkforge.transformation.models import ConflictRecord, TargetKind, TransformationTarget

__all__ = ["detect_conflicts", "request_label"]


def request_label(transformation_id: str, target: TransformationTarget) -> str:
    return f"{transformation_id}:{target.canonical}"


def _same_method(a: TransformationTarget, cls: str, name: str | None, desc: str | None) -> bool:
    """Does method target *a* (descriptor optional) designate ``cls->name desc``?"""
    return (
        a.class_name == cls
        and a.method_name == name
        and (a.descriptor is None or desc is None or a.descriptor == desc)
    )


def _call_site_methods(
    t: TransformationTarget, replacement: TransformationTarget | None
) -> list[tuple[str, str | None, str | None]]:
    """(class, name, descriptor) of the caller, invoked and replacement methods."""
    out = [
        (t.class_name, t.method_name, t.descriptor),
        (t.invoked_class or "", t.invoked_name, t.invoked_descriptor),
    ]
    if replacement is not None:
        out.append((replacement.class_name, replacement.method_name, replacement.descriptor))
    return out


def _call_site_overlap(
    a: TransformationTarget,
    ra: TransformationTarget | None,
    b: TransformationTarget,
    rb: TransformationTarget | None,
) -> str | None:
    if a.kind is not TargetKind.CALL_SITE:
        a, ra, b, rb = b, rb, a, ra
    if b.kind is TargetKind.CALL_SITE:
        same = a.class_name == b.class_name and _same_method(
            b, a.class_name, a.method_name, a.descriptor
        )
        return "duplicate_call_site_method" if same else None
    methods = _call_site_methods(a, ra)
    if b.kind is TargetKind.CLASS:
        return "call_site_overlap" if any(cls == b.class_name for cls, _, _ in methods) else None
    if any(_same_method(b, cls, name, desc) for cls, name, desc in methods):
        return "call_site_overlap"
    return None


def _overlap(
    a: TransformationTarget,
    b: TransformationTarget,
    ra: TransformationTarget | None = None,
    rb: TransformationTarget | None = None,
) -> str | None:
    if TargetKind.CALL_SITE in (a.kind, b.kind):
        return _call_site_overlap(a, ra, b, rb)
    if a.class_name != b.class_name:
        return None
    if a.kind is TargetKind.CLASS and b.kind is TargetKind.CLASS:
        return "duplicate_class_target"
    if a.kind is TargetKind.METHOD and b.kind is TargetKind.METHOD:
        if a.method_name != b.method_name:
            return None
        if a.descriptor is None or b.descriptor is None or a.descriptor == b.descriptor:
            return "duplicate_method_target"
        return None
    return "class_method_overlap"


def detect_conflicts(
    requests: list[tuple[str, TransformationTarget | None]],
    *,
    replacements: list[TransformationTarget | None] | None = None,
) -> dict[int, list[ConflictRecord]]:
    """Map request position -> conflicts it participates in (unparseable targets skip).

    *replacements* (aligned with *requests*) holds the parsed replacement method of each
    H-TRANS-003 request (None otherwise)."""
    repl = replacements or [None] * len(requests)
    out: dict[int, list[ConflictRecord]] = {}
    for i, (id_a, a) in enumerate(requests):
        for j in range(i + 1, len(requests)):
            id_b, b = requests[j]
            if a is None or b is None:
                continue
            kind = _overlap(a, b, repl[i], repl[j])
            if kind is None:
                continue
            la, lb = request_label(id_a, a), request_label(id_b, b)
            rec = ConflictRecord(
                kind=kind,
                requests=sorted([la, lb]),
                message=f"{la} and {lb} target overlapping artifacts ({kind})",
            )
            out.setdefault(i, []).append(rec)
            out.setdefault(j, []).append(rec)
    return out
