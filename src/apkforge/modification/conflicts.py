"""Conflict detection engine for planned modifications."""

from __future__ import annotations

from apkforge.modification.models import (
    ChangeConflict,
    ChangeType,
    ConflictType,
    PlannedChange,
)


class ConflictDetector:
    """Detects incompatible or mutually exclusive proposed modifications."""

    @classmethod
    def detect_conflicts(cls, changes: list[PlannedChange]) -> list[ChangeConflict]:
        """Scan list of planned changes and return identified conflicts."""
        conflicts: list[ChangeConflict] = []
        n = len(changes)

        for i in range(n):
            for j in range(i + 1, n):
                c1 = changes[i]
                c2 = changes[j]

                conflict = cls._check_pair_conflict(c1, c2)
                if conflict:
                    conflicts.append(conflict)
                    # Cross-reference IDs in both planned changes
                    if c2.id not in c1.conflicts:
                        c1.conflicts.append(c2.id)
                    if c1.id not in c2.conflicts:
                        c2.conflicts.append(c1.id)

        return sorted(conflicts, key=lambda x: (x.change_id_a, x.change_id_b))

    @classmethod
    def _check_pair_conflict(
        cls,
        c1: PlannedChange,
        c2: PlannedChange,
    ) -> ChangeConflict | None:
        """Check if two specific planned changes conflict."""
        # 1. Target conflicts: same target, incompatible operations
        if c1.target.lower() == c2.target.lower():
            # Remove component vs Modify/Disable component
            if {c1.change_type, c2.change_type} == {
                ChangeType.REMOVE_COMPONENT,
                ChangeType.MODIFY_COMPONENT,
            }:
                return ChangeConflict(
                    change_id_a=c1.id,
                    change_id_b=c2.id,
                    conflict_type=ConflictType.TARGET_CONFLICT,
                    reason=(
                        f"Both changes target component '{c1.target}': one proposes complete "
                        f"removal while the other proposes attribute modification."
                    ),
                    resolution_guidance=(
                        f"Choose either '{c1.id}' (remove component) or '{c2.id}' (modify "
                        f"exported attributes). Do not apply both."
                    ),
                )

            if {c1.change_type, c2.change_type} == {
                ChangeType.REMOVE_COMPONENT,
                ChangeType.DISABLE_COMPONENT,
            }:
                return ChangeConflict(
                    change_id_a=c1.id,
                    change_id_b=c2.id,
                    conflict_type=ConflictType.TARGET_CONFLICT,
                    reason=(
                        f"Both changes target component '{c1.target}': one proposes removal "
                        f"while the other proposes disabling via android:enabled='false'."
                    ),
                    resolution_guidance=(
                        f"Choose either '{c1.id}' (remove component) or '{c2.id}' (disable). "
                        f"Removal is more complete; disabling is less intrusive."
                    ),
                )

            # Remove permission vs Modify permission
            if {c1.change_type, c2.change_type} == {
                ChangeType.REMOVE_PERMISSION,
                ChangeType.MODIFY_PERMISSION,
            }:
                return ChangeConflict(
                    change_id_a=c1.id,
                    change_id_b=c2.id,
                    conflict_type=ConflictType.TARGET_CONFLICT,
                    reason=(
                        f"Both changes target permission '{c1.target}': one proposes removal "
                        f"while the other proposes modification."
                    ),
                    resolution_guidance=(
                        f"Select either complete removal ({c1.id}) or scoped "
                        f"modification ({c2.id})."
                    ),
                )

        # 2. Dependency conflicts: removing an SDK while another change modifies its component
        if (
            c1.change_type == ChangeType.REMOVE_TRACKER
            and c2.change_type == ChangeType.MODIFY_COMPONENT
            and c1.target.lower() in c2.target.lower()
        ):
            return ChangeConflict(
                change_id_a=c1.id,
                change_id_b=c2.id,
                conflict_type=ConflictType.DEPENDENCY_CONFLICT,
                reason=(
                    f"Change '{c1.id}' removes tracker SDK '{c1.target}', but change "
                    f"'{c2.id}' modifies component '{c2.target}' belonging to that SDK."
                ),
                resolution_guidance=(
                    f"If removing the tracker entirely, drop '{c2.id}' in favor of removing "
                    f"the component alongside the SDK."
                ),
            )

        if (
            c2.change_type == ChangeType.REMOVE_TRACKER
            and c1.change_type == ChangeType.MODIFY_COMPONENT
            and c2.target.lower() in c1.target.lower()
        ):
            return ChangeConflict(
                change_id_a=c1.id,
                change_id_b=c2.id,
                conflict_type=ConflictType.DEPENDENCY_CONFLICT,
                reason=(
                    f"Change '{c2.id}' removes tracker SDK '{c2.target}', but change "
                    f"'{c1.id}' modifies component '{c1.target}' belonging to that SDK."
                ),
                resolution_guidance=(
                    f"If removing the tracker entirely, drop '{c1.id}' in favor of removing "
                    f"the component alongside the SDK."
                ),
            )

        return None
