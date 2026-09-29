"""Registry for modification proposal rules."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.modification.rules import (
    DiffRegressionMitigationRule,
    EmbeddedPayloadRemovalRule,
    InsecureManifestHardeningRule,
    ModificationContext,
    ModificationRule,
    TrackerRemovalRule,
    UnprotectedExportedComponentRule,
    UnusedPermissionRule,
)

if TYPE_CHECKING:
    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class ModificationRuleRegistry:
    """Maintains registered modification rules and executes them against analysis contexts."""

    def __init__(self, include_builtins: bool = True) -> None:
        self._rules: list[ModificationRule] = []
        if include_builtins:
            self.register(UnusedPermissionRule())
            self.register(TrackerRemovalRule())
            self.register(InsecureManifestHardeningRule())
            self.register(UnprotectedExportedComponentRule())
            self.register(EmbeddedPayloadRemovalRule())
            self.register(DiffRegressionMitigationRule())

    def register(self, rule: ModificationRule) -> None:
        """Register a new modification rule."""
        for r in self._rules:
            if r.rule_id == rule.rule_id:
                _log.debug("Rule %s already registered; replacing.", rule.rule_id)
                self._rules.remove(r)
                break
        self._rules.append(rule)

    @property
    def rules(self) -> list[ModificationRule]:
        """Return registered rules."""
        return list(self._rules)

    def evaluate_all(self, context: ModificationContext) -> list[PlannedChange]:
        """Execute all registered rules against the context and return deduplicated changes."""
        all_changes: list[PlannedChange] = []
        seen_targets: set[tuple[str, str]] = set()

        for rule in self._rules:
            try:
                proposals = rule.identify(context)
                for change in proposals:
                    key = (change.change_type.value, change.target.lower())
                    if key not in seen_targets:
                        seen_targets.add(key)
                        all_changes.append(change)
                    else:
                        _log.debug(
                            "Skipping duplicate proposal (%s, %s) from rule %s",
                            change.change_type.value,
                            change.target,
                            rule.rule_id,
                        )
            except Exception as e:
                _log.warning("Rule %s raised exception during evaluation: %s", rule.rule_id, e)

        return all_changes
