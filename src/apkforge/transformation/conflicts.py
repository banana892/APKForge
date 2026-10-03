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
"""

from __future__ import annotations

from apkforge.transformation.models import ConflictRecord, TargetKind, TransformationTarget

__all__ = ["detect_conflicts", "request_label"]


def request_label(transformation_id: str, target: TransformationTarget) -> str:
    return f"{transformation_id}:{target.canonical}"


def _overlap(a: TransformationTarget, b: TransformationTarget) -> str | None:
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
) -> dict[int, list[ConflictRecord]]:
    """Map request position -> conflicts it participates in (unparseable targets skip)."""
    out: dict[int, list[ConflictRecord]] = {}
    for i, (id_a, a) in enumerate(requests):
        for j in range(i + 1, len(requests)):
            id_b, b = requests[j]
            if a is None or b is None:
                continue
            kind = _overlap(a, b)
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
