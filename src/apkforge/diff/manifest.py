"""Manifest differ — compares application attributes and SDK levels."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import ChangeType, DiffChange, ManifestDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import ApplicationInfo, InspectionResult

__all__ = ["ManifestDiffer", "is_semantically_equivalent"]


def is_semantically_equivalent(
    val_a: object,
    val_b: object,
    map_a: dict[str, str] | None = None,
    map_b: dict[str, str] | None = None,
) -> bool:
    """Check if two manifest values are equal or represent the same resolved resource."""
    if val_a == val_b:
        return True
    if val_a is None or val_b is None:
        return False
    if not isinstance(val_a, str) or not isinstance(val_b, str):
        return False
    ma = map_a or {}
    mb = map_b or {}
    norm_a = ma.get(val_a, val_a)
    norm_b = mb.get(val_b, val_b)
    return norm_a == norm_b or norm_a == val_b or norm_b == val_a


_APPLICATION_ATTRIBUTE_NAMES = (
    "debuggable",
    "allowBackup",
    "usesCleartextTraffic",
    "networkSecurityConfig",
    "label",
)


def _application_attributes(app: ApplicationInfo | None) -> dict[str, object | None]:
    """Map the compared `<application>` attributes to their manifest-facing names."""
    if app is None:
        return {}
    return {
        "debuggable": app.debuggable,
        "allowBackup": app.allow_backup,
        "usesCleartextTraffic": app.uses_cleartext_traffic,
        "networkSecurityConfig": app.network_security_config,
        "label": app.label,
    }


class ManifestDiffer:
    """Compares application attributes and SDK specifications."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> ManifestDiff:
        """Execute manifest comparison between Inspection A and Inspection B."""
        attr_changes: list[DiffChange] = []
        sdk_changes: list[DiffChange] = []

        app_a: ApplicationInfo | None = insp_a.manifest.application if insp_a.manifest else None
        app_b: ApplicationInfo | None = insp_b.manifest.application if insp_b.manifest else None
        res_map_a = insp_a.manifest.resource_map if insp_a.manifest else {}
        res_map_b = insp_b.manifest.resource_map if insp_b.manifest else {}

        # 1. Application attributes.
        #
        # Read with direct typed access off ApplicationInfo rather than by
        # dynamic attribute name, so a renamed or removed model field is a
        # type error instead of a silently-skipped comparison.
        attrs_a = _application_attributes(app_a)
        attrs_b = _application_attributes(app_b)

        for attr_name in _APPLICATION_ATTRIBUTE_NAMES:
            val_a = attrs_a.get(attr_name)
            val_b = attrs_b.get(attr_name)

            if is_semantically_equivalent(val_a, val_b, res_map_a, res_map_b):
                continue

            change = self._compare_scalar(
                val_a, val_b, category="manifest.application", identifier=attr_name
            )
            if change:
                attr_changes.append(change)

        # 2. SDK specifications
        min_sdk_a = insp_a.manifest.min_sdk if insp_a.manifest else insp_a.metadata.min_sdk
        min_sdk_b = insp_b.manifest.min_sdk if insp_b.manifest else insp_b.metadata.min_sdk
        min_change = self._compare_scalar(
            min_sdk_a, min_sdk_b, category="manifest.sdk", identifier="minSdkVersion"
        )
        if min_change:
            sdk_changes.append(min_change)

        target_sdk_a = insp_a.manifest.target_sdk if insp_a.manifest else insp_a.metadata.target_sdk
        target_sdk_b = insp_b.manifest.target_sdk if insp_b.manifest else insp_b.metadata.target_sdk
        target_change = self._compare_scalar(
            target_sdk_a,
            target_sdk_b,
            category="manifest.sdk",
            identifier="targetSdkVersion",
        )
        if target_change:
            sdk_changes.append(target_change)

        return ManifestDiff(
            attribute_changes=attr_changes,
            sdk_changes=sdk_changes,
        )

    @staticmethod
    def _compare_scalar(
        val_a: object,
        val_b: object,
        category: str,
        identifier: str,
    ) -> DiffChange | None:
        """Helper to create DiffChange for scalar differences."""
        if val_a == val_b:
            return None

        if val_a is None and val_b is not None:
            return DiffChange(
                change_type=ChangeType.ADDED,
                category=category,
                identifier=identifier,
                before=None,
                after=val_b,
            )
        if val_a is not None and val_b is None:
            return DiffChange(
                change_type=ChangeType.REMOVED,
                category=category,
                identifier=identifier,
                before=val_a,
                after=None,
            )
        return DiffChange(
            change_type=ChangeType.MODIFIED,
            category=category,
            identifier=identifier,
            before=val_a,
            after=val_b,
        )
