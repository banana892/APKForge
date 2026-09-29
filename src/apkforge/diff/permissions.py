"""Permission differ — compares requested and custom declared permissions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, DiffChange, PermissionDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult, PermissionInfo

__all__ = ["PermissionDiffer"]


class PermissionDiffer:
    """Compares requested (<uses-permission>) and declared (<permission>) permissions."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> PermissionDiff:
        """Execute permission comparison between Inspection A and Inspection B."""
        perms_a = {p.name for p in (insp_a.manifest.permissions if insp_a.manifest else [])}
        perms_b = {p.name for p in (insp_b.manifest.permissions if insp_b.manifest else [])}

        added = sorted(perms_b - perms_a)
        removed = sorted(perms_a - perms_b)
        unchanged = sorted(perms_a & perms_b)

        # Declared custom permissions
        dec_a_map: dict[str, PermissionInfo] = {
            p.name: p for p in (insp_a.manifest.declared_permissions if insp_a.manifest else [])
        }
        dec_b_map: dict[str, PermissionInfo] = {
            p.name: p for p in (insp_b.manifest.declared_permissions if insp_b.manifest else [])
        }

        dec_a_names = set(dec_a_map.keys())
        dec_b_names = set(dec_b_map.keys())

        dec_added = sorted(dec_b_names - dec_a_names)
        dec_removed = sorted(dec_a_names - dec_b_names)
        dec_common = sorted(dec_a_names & dec_b_names)

        dec_modified: list[DiffChange] = []
        for name in dec_common:
            p_a = dec_a_map[name]
            p_b = dec_b_map[name]
            if p_a.protection_level != p_b.protection_level:
                dec_modified.append(
                    DiffChange(
                        change_type=ChangeType.MODIFIED,
                        category="declared_permission",
                        identifier=name,
                        before=p_a.protection_level,
                        after=p_b.protection_level,
                        details={
                            "protection_level_before": p_a.protection_level,
                            "protection_level_after": p_b.protection_level,
                        },
                    )
                )

        return PermissionDiff(
            added=added,
            removed=removed,
            unchanged=unchanged,
            declared_added=dec_added,
            declared_removed=dec_removed,
            declared_modified=dec_modified,
        )
