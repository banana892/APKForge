"""Dependency analysis and execution ordering for planned modifications."""

from __future__ import annotations

from typing import ClassVar

from apkforge.modification.models import (
    ChangeDependency,
    ChangeType,
    DependencyType,
    PlannedChange,
)


class DependencyAnalyzer:
    """Analyzes relationships between proposed changes and computes execution ordering."""

    # Baseline logical order for change types
    TYPE_EXECUTION_ORDER: ClassVar[dict[ChangeType, int]] = {
        ChangeType.MODIFY_CONFIGURATION: 10,
        ChangeType.MODIFY_MANIFEST: 20,
        ChangeType.REMOVE_PERMISSION: 30,
        ChangeType.MODIFY_PERMISSION: 35,
        ChangeType.MODIFY_COMPONENT: 40,
        ChangeType.DISABLE_COMPONENT: 45,
        ChangeType.REMOVE_COMPONENT: 50,
        ChangeType.REMOVE_TRACKER: 60,
        ChangeType.REMOVE_AD_COMPONENT: 65,
        ChangeType.REMOVE_EMBEDDED_PAYLOAD: 70,
        ChangeType.REMOVE_RESOURCE: 80,
        ChangeType.REMOVE_ASSET: 85,
        ChangeType.DEX_MODIFICATION: 90,
        ChangeType.NATIVE_MODIFICATION: 95,
        ChangeType.EXTERNAL_TOOL_PATCH: 100,
    }

    @classmethod
    def discover_dependencies(
        cls,
        changes: list[PlannedChange],
    ) -> list[ChangeDependency]:
        """Identify dependency relationships among proposed changes."""
        deps: list[ChangeDependency] = []

        for change in changes:
            # Case 1: Tracker removal depends on component removal of initialization providers
            if change.change_type == ChangeType.REMOVE_TRACKER:
                for other in changes:
                    if other.id == change.id:
                        continue
                    # If other is a component associated with this tracker
                    if (
                        other.change_type
                        in (ChangeType.REMOVE_COMPONENT, ChangeType.DISABLE_COMPONENT)
                        and change.target.lower() in other.target.lower()
                    ):
                        deps.append(
                            ChangeDependency(
                                change_id=change.id,
                                depends_on_id=other.id,
                                dependency_type=DependencyType.RECOMMENDED_COMPANION,
                                description=(
                                    f"Removing tracker '{change.target}' is accompanied by "
                                    f"removing associated component '{other.target}'."
                                ),
                            )
                        )
                        if other.id not in change.dependencies:
                            change.dependencies.append(other.id)

            # Case 2: Component removal where another change modifies the same or parent target
            if change.change_type == ChangeType.REMOVE_COMPONENT:
                for other in changes:
                    if (
                        other.id != change.id
                        and other.target == change.target
                        and other.change_type == ChangeType.MODIFY_COMPONENT
                    ):
                        deps.append(
                            ChangeDependency(
                                change_id=other.id,
                                depends_on_id=change.id,
                                dependency_type=DependencyType.REQUIRED,
                                description=(
                                    f"Modifying '{other.target}' depends on component removal "
                                    f"resolution for '{change.target}'."
                                ),
                            )
                        )

        return sorted(deps, key=lambda d: (d.change_id, d.depends_on_id))

    @classmethod
    def order_changes(
        cls,
        changes: list[PlannedChange],
        dependencies: list[ChangeDependency] | None = None,
    ) -> list[PlannedChange]:
        """Deterministically sort planned changes by logical phase and dependency order."""
        if not changes:
            return []

        deps = dependencies or []
        # Graph of must-run-before: depends_on -> change
        in_degree: dict[str, int] = {c.id: 0 for c in changes}
        graph: dict[str, list[str]] = {c.id: [] for c in changes}

        for d in deps:
            if (
                d.dependency_type == DependencyType.REQUIRED
                and d.depends_on_id in graph
                and d.change_id in in_degree
            ):
                graph[d.depends_on_id].append(d.change_id)
                in_degree[d.change_id] += 1

        # Stable tie-breaker: type ordering priority, then target name, then id
        def sort_key(c: PlannedChange) -> tuple[int, str, str]:
            order = cls.TYPE_EXECUTION_ORDER.get(c.change_type, 50)
            return (order, c.target, c.id)

        # Topological sorting with priority queue / deterministic sorting
        ready = [c for c in changes if in_degree[c.id] == 0]
        ready.sort(key=sort_key)

        ordered: list[PlannedChange] = []
        change_map = {c.id: c for c in changes}

        while ready:
            curr = ready.pop(0)
            ordered.append(curr)

            for neighbor_id in graph.get(curr.id, []):
                in_degree[neighbor_id] -= 1
                if in_degree[neighbor_id] == 0:
                    ready.append(change_map[neighbor_id])
                    ready.sort(key=sort_key)

        # Append any remaining items (e.g. if cycle occurred, though unlikely)
        if len(ordered) < len(changes):
            remaining = [c for c in changes if c not in ordered]
            remaining.sort(key=sort_key)
            ordered.extend(remaining)

        return ordered
