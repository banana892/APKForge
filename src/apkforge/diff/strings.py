"""String differ — compares extracted printable strings between two APK packages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import StringDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult

__all__ = ["StringDiffer"]

_SAMPLE_LIMIT = 50


class StringDiffer:
    """Compares strings extracted from DEX string pools."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> StringDiff:
        """Execute string comparison between Inspection A and Inspection B."""
        strs_a = {s.value for s in (insp_a.dex.strings if insp_a.dex else []) if s.value}
        strs_b = {s.value for s in (insp_b.dex.strings if insp_b.dex else []) if s.value}

        added = sorted(strs_b - strs_a)
        removed = sorted(strs_a - strs_b)
        unchanged_count = len(strs_a & strs_b)

        return StringDiff(
            total_added=len(added),
            total_removed=len(removed),
            total_unchanged=unchanged_count,
            added_sample=added[:_SAMPLE_LIMIT],
            removed_sample=removed[:_SAMPLE_LIMIT],
        )
