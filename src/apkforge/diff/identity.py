"""Identity differ — compares application identity between two packages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, DiffChange, IdentityDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult

__all__ = ["IdentityDiffer"]


class IdentityDiffer:
    """Compares package name, version, and SDK levels."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> IdentityDiff:
        """Execute identity comparison between Inspection A and Inspection B."""
        pkg_a = insp_a.metadata.package_name or ""
        pkg_b = insp_b.metadata.package_name or ""
        is_same = pkg_a == pkg_b

        changes: list[DiffChange] = []

        # Package name
        pkg_change = None
        if pkg_a != pkg_b:
            pkg_change = DiffChange(
                change_type=ChangeType.MODIFIED,
                category="identity",
                identifier="package_name",
                before=pkg_a or None,
                after=pkg_b or None,
            )
            changes.append(pkg_change)

        # Version name
        vname_a = insp_a.metadata.version_name
        vname_b = insp_b.metadata.version_name
        vname_change = None
        if vname_a != vname_b:
            vname_change = DiffChange(
                change_type=ChangeType.MODIFIED,
                category="identity",
                identifier="version_name",
                before=vname_a,
                after=vname_b,
            )
            changes.append(vname_change)

        # Version code
        vcode_a = insp_a.metadata.version_code
        vcode_b = insp_b.metadata.version_code
        vcode_change = None
        if vcode_a != vcode_b:
            vcode_change = DiffChange(
                change_type=ChangeType.MODIFIED,
                category="identity",
                identifier="version_code",
                before=vcode_a,
                after=vcode_b,
            )
            changes.append(vcode_change)

        # Min SDK
        min_sdk_a = insp_a.manifest.min_sdk if insp_a.manifest else insp_a.metadata.min_sdk
        min_sdk_b = insp_b.manifest.min_sdk if insp_b.manifest else insp_b.metadata.min_sdk
        min_sdk_change = None
        if min_sdk_a != min_sdk_b:
            min_sdk_change = DiffChange(
                change_type=ChangeType.MODIFIED,
                category="identity",
                identifier="min_sdk",
                before=min_sdk_a,
                after=min_sdk_b,
            )
            changes.append(min_sdk_change)

        # Target SDK
        target_sdk_a = insp_a.manifest.target_sdk if insp_a.manifest else insp_a.metadata.target_sdk
        target_sdk_b = insp_b.manifest.target_sdk if insp_b.manifest else insp_b.metadata.target_sdk
        target_sdk_change = None
        if target_sdk_a != target_sdk_b:
            target_sdk_change = DiffChange(
                change_type=ChangeType.MODIFIED,
                category="identity",
                identifier="target_sdk",
                before=target_sdk_a,
                after=target_sdk_b,
            )
            changes.append(target_sdk_change)

        return IdentityDiff(
            is_same_package=is_same,
            package_name_change=pkg_change,
            version_name_change=vname_change,
            version_code_change=vcode_change,
            min_sdk_change=min_sdk_change,
            target_sdk_change=target_sdk_change,
            changes=changes,
        )
