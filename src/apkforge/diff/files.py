"""File differ — compares archive entries between two APK packages."""

from __future__ import annotations

import contextlib
import zipfile
from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, FileDiff, FileEntryDiff
from apkforge.intake.hashing import compute_sha256
from apkforge.intake.inventory import classify_entry

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult

__all__ = ["FileDiffer"]


def _normalize_path(p: str) -> str:
    """Normalize file path for cross-platform deterministic comparison."""
    norm = p.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.lstrip("/")


class FileDiffer:
    """Compares file-level entries between two APK packages."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> FileDiff:
        """Execute file-level diff between Inspection A and Inspection B."""
        files_a = self._extract_file_map(insp_a)
        files_b = self._extract_file_map(insp_b)

        all_paths = sorted(set(files_a.keys()) | set(files_b.keys()))

        added_count = 0
        removed_count = 0
        modified_count = 0
        unchanged_count = 0

        entries: list[FileEntryDiff] = []

        for path in all_paths:
            in_a = path in files_a
            in_b = path in files_b

            if in_b and not in_a:
                f_b = files_b[path]
                added_count += 1
                entries.append(
                    FileEntryDiff(
                        path=path,
                        change_type=ChangeType.ADDED,
                        size_after=f_b["size"],
                        sha256_after=f_b["sha256"],
                        category=f_b["category"],
                    )
                )
            elif in_a and not in_b:
                f_a = files_a[path]
                removed_count += 1
                entries.append(
                    FileEntryDiff(
                        path=path,
                        change_type=ChangeType.REMOVED,
                        size_before=f_a["size"],
                        sha256_before=f_a["sha256"],
                        category=f_a["category"],
                    )
                )
            else:
                f_a = files_a[path]
                f_b = files_b[path]

                is_modified = False
                if f_a["sha256"] and f_b["sha256"]:
                    is_modified = f_a["sha256"] != f_b["sha256"]
                else:
                    is_modified = f_a["size"] != f_b["size"]

                if is_modified:
                    modified_count += 1
                    entries.append(
                        FileEntryDiff(
                            path=path,
                            change_type=ChangeType.MODIFIED,
                            size_before=f_a["size"],
                            size_after=f_b["size"],
                            sha256_before=f_a["sha256"],
                            sha256_after=f_b["sha256"],
                            category=f_b["category"],
                        )
                    )
                else:
                    unchanged_count += 1
                    entries.append(
                        FileEntryDiff(
                            path=path,
                            change_type=ChangeType.UNCHANGED,
                            size_before=f_a["size"],
                            size_after=f_b["size"],
                            sha256_before=f_a["sha256"],
                            sha256_after=f_b["sha256"],
                            category=f_b["category"],
                        )
                    )

        return FileDiff(
            total_added=added_count,
            total_removed=removed_count,
            total_modified=modified_count,
            total_unchanged=unchanged_count,
            entries=entries,
        )

    def _extract_file_map(self, insp: InspectionResult) -> dict[str, dict[str, str | int]]:
        """Extract file metadata map keyed by normalized path."""
        res: dict[str, dict[str, str | int]] = {}

        # 1. First check if package files were populated by intake
        if insp.package and insp.package.files:
            for pf in insp.package.files:
                norm_p = _normalize_path(pf.path)
                cat_str = str(pf.category.value if hasattr(pf.category, "value") else pf.category)
                res[norm_p] = {
                    "size": pf.size,
                    "sha256": pf.sha256 or "",
                    "category": cat_str,
                }
            return res

        # 2. Fallback: inspect the zip container directly if input_path exists
        if insp.input_path and insp.input_path.is_file():
            with (
                contextlib.suppress(Exception),
                zipfile.ZipFile(insp.input_path, "r") as zf,
            ):
                for zinfo in zf.infolist():
                    if zinfo.is_dir():
                        continue
                    norm_p = _normalize_path(zinfo.filename)
                    data = zf.read(zinfo)
                    res[norm_p] = {
                        "size": zinfo.file_size,
                        "sha256": compute_sha256(data),
                        "category": str(classify_entry(norm_p).value),
                    }

        return res
