"""Resource inspector — APK resource structure inventory.

Inspects the ``res/`` directory and ``resources.arsc`` to produce a
structural inventory of resource types and counts.

Does NOT build a complete Android resource decompiler.
"""

from __future__ import annotations

import zipfile
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    ResourceInspection,
    ResourceTypeCount,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["ResourceInspector"]

_log = get_logger(__name__)

# Known resource subdirectory types
_RESOURCE_TYPES = {
    "drawable",
    "layout",
    "values",
    "xml",
    "raw",
    "mipmap",
    "font",
    "anim",
    "animator",
    "menu",
    "color",
    "interpolator",
    "transition",
    "navigation",
}


class ResourceInspector:
    """Inspects the resource structure of an APK."""

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[ResourceInspection, list[str]]:
        """Inspect the resource structure of the APK.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage.

        Returns:
            Tuple of (ResourceInspection, warnings).
        """
        warnings: list[str] = []
        result = ResourceInspection()
        type_counts: dict[str, int] = {}
        resource_files: list[str] = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    path = info.filename

                    if path == "resources.arsc":
                        result.has_resources_arsc = True
                        continue

                    if path.startswith("res/"):
                        result.resource_file_count += 1
                        resource_files.append(path)

                        # Classify by resource type (first directory under res/)
                        parts = PurePosixPath(path).parts
                        if len(parts) >= 2:
                            # Resource type is the first component after "res/"
                            # e.g. "res/drawable-hdpi/icon.png" -> "drawable"
                            res_dir = parts[1]
                            # Strip qualifier (e.g. "drawable-hdpi" -> "drawable")
                            base_type = res_dir.split("-")[0]
                            type_counts[base_type] = type_counts.get(base_type, 0) + 1

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Could not open APK for resource inspection: {exc}")

        result.resource_types = [
            ResourceTypeCount(resource_type=rt, count=count)
            for rt, count in sorted(type_counts.items())
        ]
        result.resource_files = sorted(resource_files)

        return result, warnings
