"""Component differ — compares Android components (activities, services, receivers, providers)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apkforge.diff.manifest import is_semantically_equivalent
from apkforge.diff.models import (
    ChangeType,
    ComponentChange,
    ComponentDiff,
    IntentFilterDiff,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import (
        ActivityInfo,
        BroadcastReceiverInfo,
        ContentProviderInfo,
        InspectionResult,
        IntentDataInfo,
        IntentFilterInfo,
        ServiceInfo,
    )

__all__ = ["ComponentDiffer"]


def _effective_enabled(value: bool | None) -> bool:
    """Resolve the Android-semantic enabled state.

    Android treats an absent ``android:enabled`` attribute as enabled by
    default (matching the platform's ``PackageManager`` component-state
    semantics). Inspection represents "attribute absent" as ``None``, which
    must compare equal to an explicit ``True`` -- only an explicit
    ``False`` disables a component.
    """
    return True if value is None else value


def _describe_intent_data(data: IntentDataInfo) -> dict[str, Any]:
    """Serialise an intent-filter <data> element for diff reporting."""
    return {
        "scheme": data.scheme,
        "host": data.host,
        "port": data.port,
        "path": data.path_prefix or data.path or data.path_pattern,
        "mime_type": data.mime_type,
    }


class ComponentDiffer:
    """Compares activities, services, broadcast receivers, and content providers."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> ComponentDiff:
        """Execute component comparison between Inspection A and Inspection B."""
        res_map_a = insp_a.manifest.resource_map if insp_a.manifest else {}
        res_map_b = insp_b.manifest.resource_map if insp_b.manifest else {}

        act_changes = self._diff_activities(
            insp_a.manifest.activities if insp_a.manifest else [],
            insp_b.manifest.activities if insp_b.manifest else [],
            res_map_a,
            res_map_b,
        )
        svc_changes = self._diff_services(
            insp_a.manifest.services if insp_a.manifest else [],
            insp_b.manifest.services if insp_b.manifest else [],
            res_map_a,
            res_map_b,
        )
        rec_changes = self._diff_receivers(
            insp_a.manifest.receivers if insp_a.manifest else [],
            insp_b.manifest.receivers if insp_b.manifest else [],
            res_map_a,
            res_map_b,
        )
        prov_changes = self._diff_providers(
            insp_a.manifest.providers if insp_a.manifest else [],
            insp_b.manifest.providers if insp_b.manifest else [],
            res_map_a,
            res_map_b,
        )

        all_changes = act_changes + svc_changes + rec_changes + prov_changes
        total_added = sum(1 for c in all_changes if c.change_type == ChangeType.ADDED)
        total_removed = sum(1 for c in all_changes if c.change_type == ChangeType.REMOVED)
        total_modified = sum(1 for c in all_changes if c.change_type == ChangeType.MODIFIED)
        total_unchanged = sum(1 for c in all_changes if c.change_type == ChangeType.UNCHANGED)

        return ComponentDiff(
            activities=act_changes,
            services=svc_changes,
            receivers=rec_changes,
            providers=prov_changes,
            total_added=total_added,
            total_removed=total_removed,
            total_modified=total_modified,
            total_unchanged=total_unchanged,
        )

    def _diff_activities(
        self,
        acts_a: list[ActivityInfo],
        acts_b: list[ActivityInfo],
        res_map_a: dict[str, str] | None = None,
        res_map_b: dict[str, str] | None = None,
    ) -> list[ComponentChange]:
        map_a = {a.name: a for a in acts_a}
        map_b = {b.name: b for b in acts_b}
        names = sorted(set(map_a.keys()) | set(map_b.keys()))

        changes: list[ComponentChange] = []
        for name in names:
            if name in map_b and name not in map_a:
                b = map_b[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="activity",
                        change_type=ChangeType.ADDED,
                        exported_after=b.exported,
                        permission_after=b.permission,
                        enabled_after=b.enabled,
                    )
                )
            elif name in map_a and name not in map_b:
                a = map_a[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="activity",
                        change_type=ChangeType.REMOVED,
                        exported_before=a.exported,
                        permission_before=a.permission,
                        enabled_before=a.enabled,
                    )
                )
            else:
                a = map_a[name]
                b = map_b[name]
                filter_diff = self._diff_intent_filters(a.intent_filters, b.intent_filters)
                en_changed = _effective_enabled(a.enabled) != _effective_enabled(b.enabled)
                perm_changed = not is_semantically_equivalent(
                    a.permission, b.permission, res_map_a, res_map_b
                )
                dba_changed = a.direct_boot_aware != b.direct_boot_aware
                proc_changed = a.process != b.process
                is_mod = (
                    a.exported != b.exported
                    or perm_changed
                    or en_changed
                    or dba_changed
                    or proc_changed
                    or filter_diff.has_changes
                )
                details: dict[str, Any] = {}
                if en_changed:
                    details["enabled_before"] = a.enabled
                    details["enabled_after"] = b.enabled
                if perm_changed:
                    details["permission_before"] = a.permission
                    details["permission_after"] = b.permission
                if dba_changed:
                    details["direct_boot_aware_before"] = a.direct_boot_aware
                    details["direct_boot_aware_after"] = b.direct_boot_aware
                if proc_changed:
                    details["process_before"] = a.process
                    details["process_after"] = b.process
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="activity",
                        change_type=ChangeType.MODIFIED if is_mod else ChangeType.UNCHANGED,
                        exported_before=a.exported,
                        exported_after=b.exported,
                        permission_before=a.permission,
                        permission_after=b.permission,
                        enabled_before=a.enabled,
                        enabled_after=b.enabled,
                        intent_filter_diff=filter_diff if filter_diff.has_changes else None,
                        details=details,
                    )
                )
        return changes

    def _diff_services(
        self,
        svcs_a: list[ServiceInfo],
        svcs_b: list[ServiceInfo],
        res_map_a: dict[str, str] | None = None,
        res_map_b: dict[str, str] | None = None,
    ) -> list[ComponentChange]:
        map_a = {s.name: s for s in svcs_a}
        map_b = {s.name: s for s in svcs_b}
        names = sorted(set(map_a.keys()) | set(map_b.keys()))

        changes: list[ComponentChange] = []
        for name in names:
            if name in map_b and name not in map_a:
                b = map_b[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="service",
                        change_type=ChangeType.ADDED,
                        exported_after=b.exported,
                        permission_after=b.permission,
                        enabled_after=b.enabled,
                        details={"foreground_service_type": b.foreground_service_type},
                    )
                )
            elif name in map_a and name not in map_b:
                a = map_a[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="service",
                        change_type=ChangeType.REMOVED,
                        exported_before=a.exported,
                        permission_before=a.permission,
                        enabled_before=a.enabled,
                        details={"foreground_service_type": a.foreground_service_type},
                    )
                )
            else:
                a = map_a[name]
                b = map_b[name]
                filter_diff = self._diff_intent_filters(a.intent_filters, b.intent_filters)
                fg_changed = a.foreground_service_type != b.foreground_service_type
                en_changed = _effective_enabled(a.enabled) != _effective_enabled(b.enabled)
                perm_changed = not is_semantically_equivalent(
                    a.permission, b.permission, res_map_a, res_map_b
                )
                proc_changed = a.process != b.process
                is_mod = (
                    a.exported != b.exported
                    or perm_changed
                    or en_changed
                    or fg_changed
                    or proc_changed
                    or filter_diff.has_changes
                )
                details: dict[str, Any] = {}
                if fg_changed:
                    details["foreground_service_type_before"] = a.foreground_service_type
                    details["foreground_service_type_after"] = b.foreground_service_type
                if proc_changed:
                    details["process_before"] = a.process
                    details["process_after"] = b.process
                if en_changed:
                    details["enabled_before"] = a.enabled
                    details["enabled_after"] = b.enabled
                if perm_changed:
                    details["permission_before"] = a.permission
                    details["permission_after"] = b.permission
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="service",
                        change_type=ChangeType.MODIFIED if is_mod else ChangeType.UNCHANGED,
                        exported_before=a.exported,
                        exported_after=b.exported,
                        permission_before=a.permission,
                        permission_after=b.permission,
                        enabled_before=a.enabled,
                        enabled_after=b.enabled,
                        intent_filter_diff=filter_diff if filter_diff.has_changes else None,
                        details=details,
                    )
                )
        return changes

    def _diff_receivers(
        self,
        recs_a: list[BroadcastReceiverInfo],
        recs_b: list[BroadcastReceiverInfo],
        res_map_a: dict[str, str] | None = None,
        res_map_b: dict[str, str] | None = None,
    ) -> list[ComponentChange]:
        map_a = {r.name: r for r in recs_a}
        map_b = {r.name: r for r in recs_b}
        names = sorted(set(map_a.keys()) | set(map_b.keys()))

        changes: list[ComponentChange] = []
        for name in names:
            if name in map_b and name not in map_a:
                b = map_b[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="receiver",
                        change_type=ChangeType.ADDED,
                        exported_after=b.exported,
                        permission_after=b.permission,
                        enabled_after=b.enabled,
                    )
                )
            elif name in map_a and name not in map_b:
                a = map_a[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="receiver",
                        change_type=ChangeType.REMOVED,
                        exported_before=a.exported,
                        permission_before=a.permission,
                        enabled_before=a.enabled,
                    )
                )
            else:
                a = map_a[name]
                b = map_b[name]
                filter_diff = self._diff_intent_filters(a.intent_filters, b.intent_filters)
                en_changed = _effective_enabled(a.enabled) != _effective_enabled(b.enabled)
                perm_changed = not is_semantically_equivalent(
                    a.permission, b.permission, res_map_a, res_map_b
                )
                proc_changed = a.process != b.process
                is_mod = (
                    a.exported != b.exported
                    or perm_changed
                    or en_changed
                    or proc_changed
                    or filter_diff.has_changes
                )
                details: dict[str, Any] = {}
                if en_changed:
                    details["enabled_before"] = a.enabled
                    details["enabled_after"] = b.enabled
                if perm_changed:
                    details["permission_before"] = a.permission
                    details["permission_after"] = b.permission
                if proc_changed:
                    details["process_before"] = a.process
                    details["process_after"] = b.process
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="receiver",
                        change_type=ChangeType.MODIFIED if is_mod else ChangeType.UNCHANGED,
                        exported_before=a.exported,
                        exported_after=b.exported,
                        permission_before=a.permission,
                        permission_after=b.permission,
                        enabled_before=a.enabled,
                        enabled_after=b.enabled,
                        intent_filter_diff=filter_diff if filter_diff.has_changes else None,
                        details=details,
                    )
                )
        return changes

    def _diff_providers(
        self,
        provs_a: list[ContentProviderInfo],
        provs_b: list[ContentProviderInfo],
        res_map_a: dict[str, str] | None = None,
        res_map_b: dict[str, str] | None = None,
    ) -> list[ComponentChange]:
        map_a = {p.name: p for p in provs_a}
        map_b = {p.name: p for p in provs_b}
        names = sorted(set(map_a.keys()) | set(map_b.keys()))

        changes: list[ComponentChange] = []
        for name in names:
            if name in map_b and name not in map_a:
                b = map_b[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="provider",
                        change_type=ChangeType.ADDED,
                        exported_after=b.exported,
                        permission_after=b.read_permission or b.write_permission,
                        enabled_after=b.enabled,
                        details={"authorities": b.authorities},
                    )
                )
            elif name in map_a and name not in map_b:
                a = map_a[name]
                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="provider",
                        change_type=ChangeType.REMOVED,
                        exported_before=a.exported,
                        permission_before=a.read_permission or a.write_permission,
                        enabled_before=a.enabled,
                        details={"authorities": a.authorities},
                    )
                )
            else:
                a = map_a[name]
                b = map_b[name]
                en_a = a.enabled
                en_b = b.enabled
                en_changed = _effective_enabled(en_a) != _effective_enabled(en_b)
                auth_changed = not is_semantically_equivalent(
                    a.authorities, b.authorities, res_map_a, res_map_b
                )
                perm_changed = not is_semantically_equivalent(
                    a.permission, b.permission, res_map_a, res_map_b
                )
                read_perm_changed = not is_semantically_equivalent(
                    a.read_permission, b.read_permission, res_map_a, res_map_b
                )
                write_perm_changed = not is_semantically_equivalent(
                    a.write_permission, b.write_permission, res_map_a, res_map_b
                )
                proc_changed = a.process != b.process
                is_mod = (
                    a.exported != b.exported
                    or auth_changed
                    or en_changed
                    or perm_changed
                    or read_perm_changed
                    or write_perm_changed
                    or proc_changed
                    or a.grant_uri_permissions != b.grant_uri_permissions
                )
                details: dict[str, Any] = {}
                if auth_changed:
                    details["authorities_before"] = a.authorities
                    details["authorities_after"] = b.authorities
                if en_changed:
                    details["enabled_before"] = en_a
                    details["enabled_after"] = en_b
                if perm_changed:
                    details["permission_before"] = a.permission
                    details["permission_after"] = b.permission
                if read_perm_changed:
                    details["read_permission_before"] = a.read_permission
                    details["read_permission_after"] = b.read_permission
                if write_perm_changed:
                    details["write_permission_before"] = a.write_permission
                    details["write_permission_after"] = b.write_permission
                if proc_changed:
                    details["process_before"] = a.process
                    details["process_after"] = b.process

                changes.append(
                    ComponentChange(
                        name=name,
                        component_type="provider",
                        change_type=ChangeType.MODIFIED if is_mod else ChangeType.UNCHANGED,
                        exported_before=a.exported,
                        exported_after=b.exported,
                        permission_before=a.read_permission or a.write_permission,
                        permission_after=b.read_permission or b.write_permission,
                        enabled_before=en_a,
                        enabled_after=en_b,
                        details=details,
                    )
                )
        return changes

    def _diff_intent_filters(
        self,
        filters_a: list[IntentFilterInfo],
        filters_b: list[IntentFilterInfo],
    ) -> IntentFilterDiff:
        actions_a = {act for f in filters_a for act in f.actions}
        actions_b = {act for f in filters_b for act in f.actions}
        actions_added = sorted(actions_b - actions_a)
        actions_removed = sorted(actions_a - actions_b)

        cats_a = {cat for f in filters_a for cat in f.categories}
        cats_b = {cat for f in filters_b for cat in f.categories}
        cats_added = sorted(cats_b - cats_a)
        cats_removed = sorted(cats_a - cats_b)

        # Data serialization comparison
        def _data_key(d: IntentDataInfo) -> str:
            path_part = d.path_prefix or d.path or d.path_pattern or ""
            return f"{d.scheme}://{d.host}:{d.port}{path_part}#{d.mime_type}"

        data_a_keys = {_data_key(d) for f in filters_a for d in f.data}
        data_b_map = {_data_key(d): d for f in filters_b for d in f.data}
        data_a_map = {_data_key(d): d for f in filters_a for d in f.data}

        data_added: list[dict[str, Any]] = [
            _describe_intent_data(data_b_map[k])
            for k in sorted(set(data_b_map.keys()) - data_a_keys)
        ]
        data_removed: list[dict[str, Any]] = [
            _describe_intent_data(data_a_map[k])
            for k in sorted(data_a_keys - set(data_b_map.keys()))
        ]

        return IntentFilterDiff(
            actions_added=actions_added,
            actions_removed=actions_removed,
            categories_added=cats_added,
            categories_removed=cats_removed,
            data_added=data_added,
            data_removed=data_removed,
        )
