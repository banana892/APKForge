"""Phase 7 ModifierRegistry — maps ChangeType → Modifier.

The registry is the single point of dispatch that the framework uses to
find the correct Modifier implementation for each PlannedChange.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkforge.modification.modifiers.base import Modifier

_log = logging.getLogger(__name__)


class ModifierRegistry:
    """Registry that maps change-type strings to Modifier instances.

    Usage::

        registry = ModifierRegistry()
        registry.register(ManifestModifier())
        registry.register(TrackerModifier())

        modifier = registry.get_modifier("remove_permission")
        if modifier:
            result = modifier.apply(change, context)
    """

    def __init__(self) -> None:
        self._modifiers: dict[str, Modifier] = {}
        self._by_change_type: dict[str, Modifier] = {}

    def register(self, modifier: Modifier) -> None:
        """Register a modifier and index it by all its supported change types."""
        self._modifiers[modifier.modifier_id] = modifier
        for ct in modifier.supported_change_types:
            if ct in self._by_change_type:
                _log.warning(
                    "ChangeType '%s' already registered to '%s', overwriting with '%s'",
                    ct,
                    self._by_change_type[ct].modifier_id,
                    modifier.modifier_id,
                )
            self._by_change_type[ct] = modifier
            _log.debug(
                "Registered modifier '%s' for change type '%s'",
                modifier.modifier_id,
                ct,
            )

    def get_modifier(self, change_type: str) -> Modifier | None:
        """Look up a modifier by change-type string."""
        return self._by_change_type.get(change_type)

    def get_modifier_by_id(self, modifier_id: str) -> Modifier | None:
        """Look up a modifier by its modifier_id."""
        return self._modifiers.get(modifier_id)

    @property
    def registered_modifiers(self) -> list[Modifier]:
        """Return all registered modifier instances (deduplicated)."""
        return list(self._modifiers.values())

    @property
    def supported_change_types(self) -> list[str]:
        """Return all change types that have a registered modifier."""
        return sorted(self._by_change_type.keys())

    def has_modifier_for(self, change_type: str) -> bool:
        """Return True if a modifier exists for the given change type."""
        return change_type in self._by_change_type
