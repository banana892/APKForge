"""File differ — compares archive entries between two APK packages."""

from __future__ import annotations

import contextlib
import zipfile
from pathlib import Path
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

        common_paths = sorted(set(files_a.keys()) & set(files_b.keys()))
        rem_paths = sorted(set(files_a.keys()) - set(files_b.keys()))
        add_paths = sorted(set(files_b.keys()) - set(files_a.keys()))

        # Match renames: byte-for-byte identical content between removed and added paths
        sha_to_rem: dict[str, list[str]] = {}
        for p in rem_paths:
            sha = str(files_a[p]["sha256"] or "")
            if sha:
                sha_to_rem.setdefault(sha, []).append(p)

        sha_to_add: dict[str, list[str]] = {}
        for p in add_paths:
            sha = str(files_b[p]["sha256"] or "")
            if sha:
                sha_to_add.setdefault(sha, []).append(p)

        matched_rem: set[str] = set()
        matched_add: set[str] = set()
        renamed_entries: list[FileEntryDiff] = []

        for sha, a_paths in sha_to_add.items():
            if sha in sha_to_rem:
                r_paths = sha_to_rem[sha]
                rem_avail = [p for p in r_paths if p not in matched_rem]
                add_avail = [p for p in a_paths if p not in matched_add]

                # Pass 1: exact basename match (e.g. res/layout-v21/foo.xml -> res/layout/foo.xml)
                for ap in list(add_avail):
                    a_base = ap.rsplit("/", 1)[-1]
                    for rp in list(rem_avail):
                        if rp.rsplit("/", 1)[-1] == a_base:
                            matched_rem.add(rp)
                            matched_add.add(ap)
                            rem_avail.remove(rp)
                            add_avail.remove(ap)
                            renamed_entries.append(
                                FileEntryDiff(
                                    path=ap,
                                    old_path=rp,
                                    change_type=ChangeType.RENAMED,
                                    size_before=int(files_a[rp]["size"]) if files_a[rp]["size"] is not None else None,
                                    size_after=int(files_b[ap]["size"]) if files_b[ap]["size"] is not None else None,
                                    sha256_before=str(files_a[rp]["sha256"]) if files_a[rp]["sha256"] else None,
                                    sha256_after=str(files_b[ap]["sha256"]) if files_b[ap]["sha256"] else None,
                                    category=str(files_b[ap]["category"]),
                                    details={"old_path": rp, "new_path": ap},
                                )
                            )
                            break

                # Pass 2: pair remaining in order
                for rp, ap in zip(rem_avail, add_avail):
                    matched_rem.add(rp)
                    matched_add.add(ap)
                    renamed_entries.append(
                        FileEntryDiff(
                            path=ap,
                            old_path=rp,
                            change_type=ChangeType.RENAMED,
                            size_before=int(files_a[rp]["size"]) if files_a[rp]["size"] is not None else None,
                            size_after=int(files_b[ap]["size"]) if files_b[ap]["size"] is not None else None,
                            sha256_before=str(files_a[rp]["sha256"]) if files_a[rp]["sha256"] else None,
                            sha256_after=str(files_b[ap]["sha256"]) if files_b[ap]["sha256"] else None,
                            category=str(files_b[ap]["category"]),
                            details={"old_path": rp, "new_path": ap},
                        )
                    )

        entries: list[FileEntryDiff] = list(renamed_entries)
        added_count = 0
        removed_count = 0
        modified_count = 0
        unchanged_count = 0

        for p in add_paths:
            if p not in matched_add:
                f_b = files_b[p]
                added_count += 1
                entries.append(
                    FileEntryDiff(
                        path=p,
                        change_type=ChangeType.ADDED,
                        size_after=int(f_b["size"]) if f_b["size"] is not None else None,
                        sha256_after=str(f_b["sha256"]) if f_b["sha256"] else None,
                        category=str(f_b["category"]),
                    )
                )

        for p in rem_paths:
            if p not in matched_rem:
                f_a = files_a[p]
                removed_count += 1
                entries.append(
                    FileEntryDiff(
                        path=p,
                        change_type=ChangeType.REMOVED,
                        size_before=int(f_a["size"]) if f_a["size"] is not None else None,
                        sha256_before=str(f_a["sha256"]) if f_a["sha256"] else None,
                        category=str(f_a["category"]),
                    )
                )

        for path in common_paths:
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
                        size_before=int(f_a["size"]) if f_a["size"] is not None else None,
                        size_after=int(f_b["size"]) if f_b["size"] is not None else None,
                        sha256_before=str(f_a["sha256"]) if f_a["sha256"] else None,
                        sha256_after=str(f_b["sha256"]) if f_b["sha256"] else None,
                        category=str(f_b["category"]),
                    )
                )
            else:
                unchanged_count += 1
                entries.append(
                    FileEntryDiff(
                        path=path,
                        change_type=ChangeType.UNCHANGED,
                        size_before=int(f_a["size"]) if f_a["size"] is not None else None,
                        size_after=int(f_b["size"]) if f_b["size"] is not None else None,
                        sha256_before=str(f_a["sha256"]) if f_a["sha256"] else None,
                        sha256_after=str(f_b["sha256"]) if f_b["sha256"] else None,
                        category=str(f_b["category"]),
                    )
                )

        return FileDiff(
            total_added=added_count,
            total_removed=removed_count,
            total_modified=modified_count,
            total_renamed=len(renamed_entries),
            total_unchanged=unchanged_count,
            entries=sorted(entries, key=lambda e: e.path),
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

        # 2. If sha256 is missing for entries, compute from the zip container if available
        needs_hashes = not res or not any(entry["sha256"] for entry in res.values())
        zip_path = insp.input_path or (insp.package.input_path if insp.package else None)
        if needs_hashes and zip_path and Path(zip_path).is_file():
            with (
                contextlib.suppress(Exception),
                zipfile.ZipFile(zip_path, "r") as zf,
            ):
                for zinfo in zf.infolist():
                    if zinfo.is_dir():
                        continue
                    norm_p = _normalize_path(zinfo.filename)
                    data = zf.read(zinfo)
                    sha = compute_sha256(data)
                    if norm_p in res:
                        res[norm_p]["sha256"] = sha
                    else:
                        res[norm_p] = {
                            "size": zinfo.file_size,
                            "sha256": sha,
                            "category": str(classify_entry(norm_p).value),
                        }

        return res
