"""Asset differ — compares non-code assets and Shannon entropy changes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import (
    AssetDiff,
    AssetEntropyChange,
    ChangeType,
    FileEntryDiff,
)

if TYPE_CHECKING:
    from apkforge.diff.models import FileDiff
    from apkforge.inspection.models import InspectionResult

__all__ = ["AssetDiffer"]


class AssetDiffer:
    """Compares assets/ entries and Shannon entropy deltas."""

    def diff(
        self,
        insp_a: InspectionResult,
        insp_b: InspectionResult,
        file_diff: FileDiff | None = None,
    ) -> AssetDiff:
        """Execute asset comparison between Inspection A and Inspection B."""
        assets_a = {a.path: a for a in (insp_a.assets.assets if insp_a.assets else [])}
        assets_b = {b.path: b for b in (insp_b.assets.assets if insp_b.assets else [])}

        all_paths = sorted(set(assets_a.keys()) | set(assets_b.keys()))

        entries: list[FileEntryDiff] = []
        entropy_changes: list[AssetEntropyChange] = []

        total_added = 0
        total_removed = 0
        total_modified = 0
        total_unchanged = 0

        # Build quick hash lookup from file_diff if available
        fd_map = {e.path: e for e in (file_diff.entries if file_diff else [])}

        for path in all_paths:
            if path in assets_b and path not in assets_a:
                b = assets_b[path]
                total_added += 1
                entries.append(
                    FileEntryDiff(
                        path=path,
                        change_type=ChangeType.ADDED,
                        size_after=b.size,
                        sha256_after=fd_map.get(path).sha256_after if fd_map.get(path) else None,
                        category="asset",
                    )
                )
                entropy_changes.append(
                    AssetEntropyChange(
                        path=path,
                        entropy_before=None,
                        entropy_after=b.entropy,
                        delta=b.entropy,
                    )
                )
            elif path in assets_a and path not in assets_b:
                a = assets_a[path]
                total_removed += 1
                entries.append(
                    FileEntryDiff(
                        path=path,
                        change_type=ChangeType.REMOVED,
                        size_before=a.size,
                        sha256_before=fd_map.get(path).sha256_before if fd_map.get(path) else None,
                        category="asset",
                    )
                )
            else:
                a = assets_a[path]
                b = assets_b[path]

                fd_entry = fd_map.get(path)
                is_mod = False
                if fd_entry:
                    is_mod = fd_entry.change_type == ChangeType.MODIFIED
                else:
                    is_mod = a.size != b.size or abs((b.entropy or 0.0) - (a.entropy or 0.0)) > 0.05

                if is_mod:
                    total_modified += 1
                    entries.append(
                        FileEntryDiff(
                            path=path,
                            change_type=ChangeType.MODIFIED,
                            size_before=a.size,
                            size_after=b.size,
                            sha256_before=fd_entry.sha256_before if fd_entry else None,
                            sha256_after=fd_entry.sha256_after if fd_entry else None,
                            category="asset",
                        )
                    )
                    delta = (b.entropy or 0.0) - (a.entropy or 0.0)
                    entropy_changes.append(
                        AssetEntropyChange(
                            path=path,
                            entropy_before=a.entropy,
                            entropy_after=b.entropy,
                            delta=round(delta, 4),
                        )
                    )
                else:
                    total_unchanged += 1
                    entries.append(
                        FileEntryDiff(
                            path=path,
                            change_type=ChangeType.UNCHANGED,
                            size_before=a.size,
                            size_after=b.size,
                            sha256_before=fd_entry.sha256_before if fd_entry else None,
                            sha256_after=fd_entry.sha256_after if fd_entry else None,
                            category="asset",
                        )
                    )

        return AssetDiff(
            total_added=total_added,
            total_removed=total_removed,
            total_modified=total_modified,
            total_unchanged=total_unchanged,
            entries=entries,
            entropy_changes=entropy_changes,
        )
