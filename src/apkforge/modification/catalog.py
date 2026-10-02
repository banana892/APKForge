"""Registry of Phase D modifiers (:class:`~apkforge.modification.contract.APKModifier`).

Separate from the legacy :class:`~apkforge.modification.modifiers.registry.ModifierRegistry`,
which dispatches planner ``PlannedChange`` objects by change type. This catalog is keyed
by stable modifier id, rejects duplicates instead of overwriting, and lists modifiers in
id order, so nothing depends on registration or discovery order.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.exceptions import ModificationError

if TYPE_CHECKING:
    from apkforge.modification.contract import APKModifier, ModifierInfo

__all__ = ["DuplicateModifierError", "ModifierCatalog", "UnknownModifierError", "default_catalog"]


class DuplicateModifierError(ModificationError):
    """A modifier id is registered twice."""


class UnknownModifierError(ModificationError):
    """No modifier is registered under the requested id."""


class ModifierCatalog:
    def __init__(self, modifiers: list[APKModifier] | None = None) -> None:
        self._modifiers: dict[str, APKModifier] = {}
        for m in modifiers or []:
            self.register(m)

    def register(self, modifier: APKModifier) -> None:
        mid = getattr(modifier, "id", None)
        if not isinstance(mid, str) or not mid.strip():
            raise ModificationError("A modifier needs a non-empty string id", context="catalog")
        if mid in self._modifiers:
            raise DuplicateModifierError(
                f"Modifier id {mid!r} is already registered", context="catalog"
            )
        self._modifiers[mid] = modifier

    def get(self, modifier_id: str) -> APKModifier:
        try:
            return self._modifiers[modifier_id]
        except KeyError:
            known = ", ".join(self.ids()) or "none"
            raise UnknownModifierError(
                f"Unknown modifier {modifier_id!r} (registered: {known})", context="catalog"
            ) from None

    def __contains__(self, modifier_id: object) -> bool:
        return modifier_id in self._modifiers

    def ids(self) -> list[str]:
        return sorted(self._modifiers)

    def list(self) -> list[ModifierInfo]:
        return [self._modifiers[i].info() for i in self.ids()]


def default_catalog() -> ModifierCatalog:
    """The built-in Phase D modifiers."""
    from apkforge.modification.builtin import BootReceiverModifier, MarkerAssetModifier

    return ModifierCatalog([BootReceiverModifier(), MarkerAssetModifier()])
