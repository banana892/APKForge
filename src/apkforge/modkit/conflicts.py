"""Phase H.10 - conflict reporting between the steps of a ModKit chain.

Each step's change set is the Phase E observation list (:func:`apkforge.diff.expectations.
observe`) of DiffEngine on *step input -> step output*; no new comparison is done here.
Two steps conflict when they change the same ``(category, identifier)``:

- ``reverted``: a later step puts back the earlier step's *before* state (an entry added
  then removed, removed then re-added, or a value/content changed back).
- ``overlap``: any other repeated change to the same thing.

Archive containers that nearly every patch rewrites (``classesN.dex``, ``resources.arsc``,
``AndroidManifest.xml``, signature files, the signing certificate) are flagged
``container=True``: their overlap is expected whenever two steps both edit code or
resources, and the semantic observations (dex classes, manifest attributes, components,
...) are where a real collision shows. Conflicts are reported, never resolved, and never
fail a chain.
"""

from __future__ import annotations

import re
from collections import defaultdict
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from apkforge.modkit.models import _Frozen

if TYPE_CHECKING:
    from apkforge.diff.expectations import Observation

__all__ = ["ChainConflict", "ConflictKind", "ConflictStatus", "find_conflicts", "is_container"]

_CONTAINER_FILE = re.compile(
    r"^(?:classes\d*\.dex|resources\.arsc|AndroidManifest\.xml"
    r"|META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC)))$",
    re.IGNORECASE,
)
_ABSENT, _PRESENT = "<absent>", "<present>"


class ConflictKind(StrEnum):
    OVERLAP = "overlap"
    REVERTED = "reverted"


class ConflictStatus(StrEnum):
    NOT_CHECKED = "NOT_CHECKED"
    NONE = "NONE"
    #: Only container entries overlap (expected for steps that both edit code/resources).
    CONTAINER_ONLY = "CONTAINER_ONLY"
    CONFLICTS = "CONFLICTS"
    #: A step's diff was not COMPLETE: conflicts may be missing.
    INCOMPLETE = "INCOMPLETE"


class ChainConflict(_Frozen):
    category: str
    identifier: str
    kind: ConflictKind
    #: Indexes of the chain steps that changed it, in order.
    steps: tuple[int, ...]
    #: Each step's observation kind (added/removed/modified/...), aligned with ``steps``.
    changes: tuple[str, ...]
    container: bool = False


def is_container(obs: Observation) -> bool:
    if obs.category == "certificate":
        return True
    return obs.category == "file" and bool(_CONTAINER_FILE.match(obs.identifier))


def _state(obs: Observation, side: str) -> Any:  # noqa: ANN401 - opaque comparable state
    """What *obs* says the thing looked like before/after its step (None: unknown)."""
    # Identifier-only observations (permissions, classes, ...) carry no content: there,
    # presence is the whole state, so removed-then-added counts as reverted.
    if obs.kind == "added":
        return _ABSENT if side == "before" else (obs.content_after or _PRESENT)
    if obs.kind == "removed":
        return _ABSENT if side == "after" else (obs.content_before or _PRESENT)
    content = obs.content_before if side == "before" else obs.content_after
    if content is not None:
        return content
    value = obs.detail.get(side)
    return None if value is None else repr(value)


def find_conflicts(changes: list[tuple[int, list[Observation]]]) -> list[ChainConflict]:
    """*changes*: ``(step index, observations)`` per step that changed the APK, in order."""
    touched: dict[tuple[str, str], list[tuple[int, Observation]]] = defaultdict(list)
    for step, observations in changes:
        for obs in observations:
            touched[(obs.category, obs.identifier)].append((step, obs))
    conflicts = []
    for (category, identifier), hits in touched.items():
        if len({step for step, _ in hits}) < 2:
            continue
        first, last = hits[0][1], hits[-1][1]
        before, after = _state(first, "before"), _state(last, "after")
        reverted = before is not None and before == after
        conflicts.append(
            ChainConflict(
                category=category,
                identifier=identifier,
                kind=ConflictKind.REVERTED if reverted else ConflictKind.OVERLAP,
                steps=tuple(step for step, _ in hits),
                changes=tuple(obs.kind for _, obs in hits),
                container=is_container(first),
            )
        )
    return sorted(conflicts, key=lambda c: (c.container, c.category, c.identifier))
