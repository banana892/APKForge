"""Resource differ — compares resources.arsc and res/ directory assets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apkforge.diff.models import ChangeType, FileEntryDiff, ResourceDiff

if TYPE_CHECKING:
    from apkforge.diff.models import FileDiff
    from apkforge.inspection.models import InspectionResult

__all__ = ["ResourceDiffer"]


class ResourceDiffer:
    """Compares compiled resources and resource directory contents."""

    def diff(
        self,
        insp_a: InspectionResult,
        insp_b: InspectionResult,
        file_diff: FileDiff | None = None,
    ) -> ResourceDiff:
        """Execute resource comparison between Inspection A and Inspection B."""
        res_a = insp_a.resources
        res_b = insp_b.resources

        # 1. Compare resources.arsc
        arsc_entry = (
            next((e for e in file_diff.entries if e.path == "resources.arsc"), None)
            if file_diff
            else None
        )
        if arsc_entry:
            arsc_change = arsc_entry.change_type
            size_a = arsc_entry.size_before
            size_b = arsc_entry.size_after
        else:
            has_a = bool(res_a.has_resources_arsc if res_a else False)
            has_b = bool(res_b.has_resources_arsc if res_b else False)
            size_a = None
            size_b = None
            arsc_change = ChangeType.UNCHANGED
            if not has_a and has_b:
                arsc_change = ChangeType.ADDED
            elif has_a and not has_b:
                arsc_change = ChangeType.REMOVED

        arsc_details: dict[str, Any] = {
            "size_before": size_a,
            "size_after": size_b,
        }

        # 2. Extract resource entries under res/ from file_diff if provided
        res_entries: list[FileEntryDiff] = []
        by_type: dict[str, dict[str, int]] = {}

        if file_diff:
            for entry in file_diff.entries:
                if entry.path.startswith("res/"):
                    res_entries.append(entry)
                    # Extract type from path (e.g. res/drawable-hdpi/icon.png -> drawable)
                    parts = entry.path.split("/")
                    rtype = "other"
                    if len(parts) >= 2:
                        rtype = parts[1].split("-")[0]

                    by_type.setdefault(
                        rtype, {"added": 0, "removed": 0, "modified": 0, "unchanged": 0}
                    )
                    if entry.change_type == ChangeType.ADDED:
                        by_type[rtype]["added"] += 1
                    elif entry.change_type == ChangeType.REMOVED:
                        by_type[rtype]["removed"] += 1
                    elif entry.change_type == ChangeType.MODIFIED:
                        by_type[rtype]["modified"] += 1
                    elif entry.change_type == ChangeType.UNCHANGED:
                        by_type[rtype]["unchanged"] += 1

        total_added = sum(1 for e in res_entries if e.change_type == ChangeType.ADDED)
        total_removed = sum(1 for e in res_entries if e.change_type == ChangeType.REMOVED)
        total_modified = sum(1 for e in res_entries if e.change_type == ChangeType.MODIFIED)
        total_unchanged = sum(1 for e in res_entries if e.change_type == ChangeType.UNCHANGED)

        return ResourceDiff(
            resources_arsc_change=arsc_change,
            resources_arsc_details=arsc_details,
            total_added=total_added,
            total_removed=total_removed,
            total_modified=total_modified,
            total_unchanged=total_unchanged,
            by_type=by_type,
            entries=res_entries,
        )
