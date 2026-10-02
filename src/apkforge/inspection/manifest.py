"""Manifest inspector — detailed AndroidManifest.xml inspection.

Extracts permissions, components (activities, services, receivers, providers),
intent filters, and application-level attributes.

Reuses Phase 1 identity values (package name, versions, SDKs) where already
available rather than duplicating parsing logic.

Security invariant: This inspector only records facts.  It does NOT classify
permissions as dangerous or activities as malicious.
"""

from __future__ import annotations

import contextlib
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    ActivityInfo,
    ApplicationInfo,
    BroadcastReceiverInfo,
    ContentProviderInfo,
    IntentDataInfo,
    IntentFilterInfo,
    ManifestInspection,
    PermissionInfo,
    ServiceInfo,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["ManifestInspector"]

_log = get_logger(__name__)


def _safe_bool(value: object) -> bool | None:
    """Convert an attribute value to bool, or None if absent/unparseable."""
    if value is None:
        return None
    s = str(value).lower().strip()
    if s in ("true", "1"):
        return True
    if s in ("false", "0"):
        return False
    return None


def _safe_int(value: object) -> int | None:
    """Convert a value to int, or None if absent/unparseable."""
    if value is None:
        return None
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def _resolve_resource_value(
    apk: object,
    val: object,
    res_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve an Android resource reference (e.g. @7f130332 or @0x7f130332) to its string value."""
    if val is None:
        return None
    val_str = str(val).strip()
    if not val_str:
        return val_str
    if val_str.startswith("@") and len(val_str) > 1:
        raw_id = val_str[1:]
        res_id = None
        try:
            if raw_id.startswith(("0x", "0X")):
                res_id = int(raw_id, 16)
            elif all(c in "0123456789abcdefABCDEF" for c in raw_id):
                res_id = int(raw_id, 16)
        except (ValueError, TypeError):
            pass

        if res_id is not None and hasattr(apk, "get_android_resources"):
            with contextlib.suppress(Exception):
                arsc = apk.get_android_resources()
                if arsc:
                    configs = arsc.get_resolved_res_configs(res_id)
                    if configs:
                        for _, res_val in configs:
                            if isinstance(res_val, str) and res_val:
                                if res_map is not None:
                                    res_map[val_str] = res_val
                                return res_val
    return val_str


class ManifestInspector:
    """Extracts detailed information from the AndroidManifest.xml.

    Uses Androguard's APK class for binary XML parsing, with a fallback
    to plain XML parsing for text-format manifests.
    """

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[ManifestInspection, list[str]]:
        """Inspect the AndroidManifest.xml of the APK at *apk_path*.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage (reuse identity fields if available).

        Returns:
            Tuple of (ManifestInspection, warnings).
        """
        warnings: list[str] = []
        result = ManifestInspection()

        # Reuse Phase 1 identity fields if available
        if package is not None and package.metadata:
            result.package_name = package.metadata.package_name
            result.version_name = package.metadata.version_name
            result.version_code = package.metadata.version_code
            result.min_sdk = package.metadata.min_sdk
            result.target_sdk = package.metadata.target_sdk

        # Try Androguard for full parsing
        try:
            from androguard.core.apk import APK
        except ImportError:
            warnings.append("Androguard not installed; detailed manifest inspection unavailable.")
            return self._fallback_xml_parse(apk_path, result, warnings)

        try:
            apk = APK(str(apk_path))
            if not apk.is_valid_APK():
                return self._fallback_xml_parse(apk_path, result, warnings)

            # Fill identity if not from Phase 1
            if result.package_name is None:
                with contextlib.suppress(Exception):
                    result.package_name = apk.get_package() or None
            if result.version_name is None:
                with contextlib.suppress(Exception):
                    result.version_name = apk.get_androidversion_name() or None
            if result.version_code is None:
                with contextlib.suppress(Exception):
                    result.version_code = _safe_int(apk.get_androidversion_code())
            if result.min_sdk is None:
                with contextlib.suppress(Exception):
                    result.min_sdk = _safe_int(apk.get_min_sdk_version())
            if result.target_sdk is None:
                with contextlib.suppress(Exception):
                    result.target_sdk = _safe_int(apk.get_target_sdk_version())

            # Permissions
            self._extract_permissions(apk, result, warnings)

            # Components
            self._extract_activities(apk, result, warnings)
            self._extract_services(apk, result, warnings)
            self._extract_receivers(apk, result, warnings)
            self._extract_providers(apk, result, warnings)

            # Application attributes
            self._extract_application_info(apk, result, warnings)

            if not result.package_name or (not result.activities and not result.permissions):
                self._fallback_xml_parse(apk_path, result, warnings)

            return result, warnings
        except Exception as exc:
            _log.warning("Androguard failed to parse APK: %s", exc)
            return self._fallback_xml_parse(apk_path, result, warnings)

    def _extract_permissions(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract all permissions from the manifest."""
        with contextlib.suppress(Exception):
            perms = apk.get_permissions()  # type: ignore[union-attr]
            for p in perms:
                result.permissions.append(PermissionInfo(name=str(p)))

        # Also extract declared permissions (custom permissions defined by the app)
        with contextlib.suppress(Exception):
            declared = apk.get_declared_permissions()  # type: ignore[union-attr]
            declared_names = {p.name for p in result.permissions}
            for p in declared:
                name = str(p)
                if name not in declared_names:
                    result.permissions.append(PermissionInfo(name=name, protection_level=None))

    def _extract_intent_filters(self, component_xml: object) -> list[IntentFilterInfo]:
        """Extract intent filters from a component XML element."""
        filters: list[IntentFilterInfo] = []
        if component_xml is None:
            return filters

        with contextlib.suppress(Exception):
            ns = "{http://schemas.android.com/apk/res/android}"

            if not isinstance(component_xml, ET.Element):
                return filters

            for intent_filter in component_xml.findall("intent-filter"):
                actions = []
                categories = []
                data_items: list[IntentDataInfo] = []

                for action in intent_filter.findall("action"):
                    name = action.get(f"{ns}name") or action.get("name")
                    if name:
                        actions.append(name)

                for category in intent_filter.findall("category"):
                    name = category.get(f"{ns}name") or category.get("name")
                    if name:
                        categories.append(name)

                for data_elem in intent_filter.findall("data"):
                    data_items.append(
                        IntentDataInfo(
                            scheme=data_elem.get(f"{ns}scheme") or data_elem.get("scheme"),
                            host=data_elem.get(f"{ns}host") or data_elem.get("host"),
                            port=data_elem.get(f"{ns}port") or data_elem.get("port"),
                            path=data_elem.get(f"{ns}path") or data_elem.get("path"),
                            pathPrefix=(
                                data_elem.get(f"{ns}pathPrefix") or data_elem.get("pathPrefix")
                            ),
                            pathPattern=(
                                data_elem.get(f"{ns}pathPattern") or data_elem.get("pathPattern")
                            ),
                            mimeType=(data_elem.get(f"{ns}mimeType") or data_elem.get("mimeType")),
                        )
                    )

                filters.append(
                    IntentFilterInfo(
                        actions=actions,
                        categories=categories,
                        data=data_items,
                    )
                )

        return filters

    def _extract_activities(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract all activities from the manifest."""
        with contextlib.suppress(Exception):
            activities = apk.get_activities()  # type: ignore[union-attr]
            for act_name in activities:
                exported = None
                permission = None
                enabled = None
                direct_boot = None
                process = None
                intent_filters: list[IntentFilterInfo] = []

                with contextlib.suppress(Exception):
                    exp_val = apk.get_attribute_value("activity", "exported", name=act_name)  # type: ignore[union-attr]
                    exported = _safe_bool(exp_val)

                with contextlib.suppress(Exception):
                    perm_val = apk.get_attribute_value("activity", "permission", name=act_name)  # type: ignore[union-attr]
                    if perm_val:
                        permission = str(perm_val)

                with contextlib.suppress(Exception):
                    en_val = apk.get_attribute_value("activity", "enabled", name=act_name)  # type: ignore[union-attr]
                    enabled = _safe_bool(en_val)

                with contextlib.suppress(Exception):
                    db_val = apk.get_attribute_value("activity", "directBootAware", name=act_name)  # type: ignore[union-attr]
                    direct_boot = _safe_bool(db_val)

                with contextlib.suppress(Exception):
                    proc_val = apk.get_attribute_value("activity", "process", name=act_name)  # type: ignore[union-attr]
                    if proc_val:
                        process = str(proc_val)

                # Try extracting intent filters from the XML tree
                with contextlib.suppress(Exception):
                    xml_obj = apk.get_android_manifest_xml()  # type: ignore[union-attr]
                    if xml_obj is not None:
                        ns = "{http://schemas.android.com/apk/res/android}"
                        app_elem = xml_obj.find("application")
                        if app_elem is not None:
                            for act_elem in app_elem.findall("activity"):
                                name_attr = act_elem.get(f"{ns}name") or act_elem.get("name")
                                if name_attr and (
                                    name_attr == act_name
                                    or name_attr.endswith(f".{act_name.split('.')[-1]}")
                                    or act_name.endswith(name_attr)
                                ):
                                    intent_filters = self._extract_intent_filters(act_elem)
                                    break

                result.activities.append(
                    ActivityInfo(
                        name=str(act_name),
                        exported=exported,
                        permission=permission,
                        enabled=enabled,
                        direct_boot_aware=direct_boot,
                        process=process,
                        intent_filters=intent_filters,
                    )
                )

    def _extract_services(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract all services from the manifest."""
        with contextlib.suppress(Exception):
            services = apk.get_services()  # type: ignore[union-attr]
            for svc_name in services:
                exported = None
                permission = None
                enabled = None
                fg_type = None
                process = None
                intent_filters: list[IntentFilterInfo] = []

                with contextlib.suppress(Exception):
                    exp_val = apk.get_attribute_value("service", "exported", name=svc_name)  # type: ignore[union-attr]
                    exported = _safe_bool(exp_val)

                with contextlib.suppress(Exception):
                    perm_val = apk.get_attribute_value("service", "permission", name=svc_name)  # type: ignore[union-attr]
                    if perm_val:
                        permission = str(perm_val)

                with contextlib.suppress(Exception):
                    en_val = apk.get_attribute_value("service", "enabled", name=svc_name)  # type: ignore[union-attr]
                    enabled = _safe_bool(en_val)

                with contextlib.suppress(Exception):
                    fg_val = apk.get_attribute_value(  # type: ignore[union-attr]
                        "service", "foregroundServiceType", name=svc_name
                    )
                    if fg_val:
                        fg_type = str(fg_val)

                with contextlib.suppress(Exception):
                    proc_val = apk.get_attribute_value("service", "process", name=svc_name)  # type: ignore[union-attr]
                    if proc_val:
                        process = str(proc_val)

                with contextlib.suppress(Exception):
                    xml_obj = apk.get_android_manifest_xml()  # type: ignore[union-attr]
                    if xml_obj is not None:
                        ns = "{http://schemas.android.com/apk/res/android}"
                        app_elem = xml_obj.find("application")
                        if app_elem is not None:
                            for svc_elem in app_elem.findall("service"):
                                name_attr = svc_elem.get(f"{ns}name") or svc_elem.get("name")
                                if name_attr and (
                                    name_attr == svc_name
                                    or name_attr.endswith(f".{svc_name.split('.')[-1]}")
                                    or svc_name.endswith(name_attr)
                                ):
                                    intent_filters = self._extract_intent_filters(svc_elem)
                                    break

                result.services.append(
                    ServiceInfo(
                        name=str(svc_name),
                        exported=exported,
                        permission=permission,
                        enabled=enabled,
                        foreground_service_type=fg_type,
                        process=process,
                        intent_filters=intent_filters,
                    )
                )

    def _extract_receivers(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract all broadcast receivers from the manifest."""
        with contextlib.suppress(Exception):
            receivers = apk.get_receivers()  # type: ignore[union-attr]
            for rec_name in receivers:
                exported = None
                permission = None
                enabled = None
                process = None
                intent_filters: list[IntentFilterInfo] = []

                with contextlib.suppress(Exception):
                    exp_val = apk.get_attribute_value("receiver", "exported", name=rec_name)  # type: ignore[union-attr]
                    exported = _safe_bool(exp_val)

                with contextlib.suppress(Exception):
                    perm_val = apk.get_attribute_value("receiver", "permission", name=rec_name)  # type: ignore[union-attr]
                    if perm_val:
                        permission = str(perm_val)

                with contextlib.suppress(Exception):
                    en_val = apk.get_attribute_value("receiver", "enabled", name=rec_name)  # type: ignore[union-attr]
                    enabled = _safe_bool(en_val)

                with contextlib.suppress(Exception):
                    proc_val = apk.get_attribute_value("receiver", "process", name=rec_name)  # type: ignore[union-attr]
                    if proc_val:
                        process = str(proc_val)

                with contextlib.suppress(Exception):
                    xml_obj = apk.get_android_manifest_xml()  # type: ignore[union-attr]
                    if xml_obj is not None:
                        ns = "{http://schemas.android.com/apk/res/android}"
                        app_elem = xml_obj.find("application")
                        if app_elem is not None:
                            for rec_elem in app_elem.findall("receiver"):
                                name_attr = rec_elem.get(f"{ns}name") or rec_elem.get("name")
                                if name_attr and (
                                    name_attr == rec_name
                                    or name_attr.endswith(f".{rec_name.split('.')[-1]}")
                                    or rec_name.endswith(name_attr)
                                ):
                                    intent_filters = self._extract_intent_filters(rec_elem)
                                    break

                result.receivers.append(
                    BroadcastReceiverInfo(
                        name=str(rec_name),
                        exported=exported,
                        permission=permission,
                        enabled=enabled,
                        process=process,
                        intent_filters=intent_filters,
                    )
                )

    def _extract_providers(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract all content providers from the manifest."""
        with contextlib.suppress(Exception):
            providers = apk.get_providers()  # type: ignore[union-attr]
            for prov_name in providers:
                exported = None
                permission = None
                authorities = None
                read_perm = None
                write_perm = None
                grant_uri = None
                enabled = None
                process = None

                with contextlib.suppress(Exception):
                    exp_val = apk.get_attribute_value("provider", "exported", name=prov_name)  # type: ignore[union-attr]
                    exported = _safe_bool(exp_val)

                with contextlib.suppress(Exception):
                    en_val = apk.get_attribute_value("provider", "enabled", name=prov_name)  # type: ignore[union-attr]
                    enabled = _safe_bool(en_val)

                with contextlib.suppress(Exception):
                    auth_val = apk.get_attribute_value("provider", "authorities", name=prov_name)  # type: ignore[union-attr]
                    if auth_val:
                        authorities = _resolve_resource_value(apk, auth_val, result.resource_map)

                with contextlib.suppress(Exception):
                    perm_val = apk.get_attribute_value("provider", "permission", name=prov_name)  # type: ignore[union-attr]
                    if perm_val:
                        permission = _resolve_resource_value(apk, perm_val, result.resource_map)

                with contextlib.suppress(Exception):
                    rp_val = apk.get_attribute_value("provider", "readPermission", name=prov_name)  # type: ignore[union-attr]
                    if rp_val:
                        read_perm = _resolve_resource_value(apk, rp_val, result.resource_map)

                with contextlib.suppress(Exception):
                    wp_val = apk.get_attribute_value(  # type: ignore[union-attr]
                        "provider", "writePermission", name=prov_name
                    )
                    if wp_val:
                        write_perm = _resolve_resource_value(apk, wp_val, result.resource_map)

                with contextlib.suppress(Exception):
                    gu_val = apk.get_attribute_value(  # type: ignore[union-attr]
                        "provider", "grantUriPermissions", name=prov_name
                    )
                    grant_uri = _safe_bool(gu_val)

                with contextlib.suppress(Exception):
                    proc_val = apk.get_attribute_value("provider", "process", name=prov_name)  # type: ignore[union-attr]
                    if proc_val:
                        process = str(proc_val)

                result.providers.append(
                    ContentProviderInfo(
                        name=str(prov_name),
                        authorities=authorities,
                        exported=exported,
                        enabled=enabled,
                        permission=permission,
                        read_permission=read_perm,
                        write_permission=write_perm,
                        grant_uri_permissions=grant_uri,
                        process=process,
                    )
                )

    def _extract_application_info(
        self,
        apk: object,
        result: ManifestInspection,
        warnings: list[str],
    ) -> None:
        """Extract application-level attributes."""
        app_info = ApplicationInfo()

        with contextlib.suppress(Exception):
            label = apk.get_app_name()  # type: ignore[union-attr]
            if label:
                app_info.label = str(label)

        _app_attrs = {
            "icon": "icon",
            "theme": "theme",
            "debuggable": "debuggable",
            "allowBackup": "allow_backup",
            "usesCleartextTraffic": "uses_cleartext_traffic",
            "networkSecurityConfig": "network_security_config",
            "extractNativeLibs": "extract_native_libs",
            "largeHeap": "large_heap",
            "testOnly": "test_only",
        }

        for xml_attr, model_attr in _app_attrs.items():
            with contextlib.suppress(Exception):
                val = apk.get_attribute_value("application", xml_attr)  # type: ignore[union-attr]
                if val is not None:
                    if model_attr in (
                        "debuggable",
                        "allow_backup",
                        "uses_cleartext_traffic",
                        "extract_native_libs",
                        "large_heap",
                        "test_only",
                    ):
                        setattr(app_info, model_attr, _safe_bool(val))
                    else:
                        setattr(
                            app_info,
                            model_attr,
                            _resolve_resource_value(apk, val, result.resource_map),
                        )

        result.application = app_info

    def _fallback_xml_parse(
        self,
        apk_path: Path,
        result: ManifestInspection,
        warnings: list[str],
    ) -> tuple[ManifestInspection, list[str]]:
        """Fallback: parse the manifest from the ZIP as plain XML."""
        import xml.etree.ElementTree as ET
        import zipfile

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" not in zf.namelist():
                    warnings.append("No AndroidManifest.xml found in APK.")
                    return result, warnings

                raw = zf.read("AndroidManifest.xml")

                # Try AXML first
                try:
                    from androguard.core.axml import AXMLPrinter

                    axml = AXMLPrinter(raw)
                    xml_text = axml.get_xml()
                    if isinstance(xml_text, bytes):
                        xml_text = xml_text.decode("utf-8", errors="replace")
                except Exception:
                    xml_text = raw.decode("utf-8", errors="replace")

                try:
                    root = ET.fromstring(xml_text)  # noqa: S314
                except ET.ParseError as exc:
                    warnings.append(f"Could not parse manifest XML: {exc}")
                    return result, warnings

                ns = "{http://schemas.android.com/apk/res/android}"

                # Identity
                if result.package_name is None:
                    result.package_name = root.get("package")
                if result.version_name is None:
                    result.version_name = root.get(f"{ns}versionName") or root.get("versionName")
                if result.version_code is None:
                    result.version_code = _safe_int(
                        root.get(f"{ns}versionCode") or root.get("versionCode")
                    )

                uses_sdk = root.find("uses-sdk")
                if uses_sdk is not None:
                    if result.min_sdk is None:
                        result.min_sdk = _safe_int(
                            uses_sdk.get(f"{ns}minSdkVersion") or uses_sdk.get("minSdkVersion")
                        )
                    if result.target_sdk is None:
                        result.target_sdk = _safe_int(
                            uses_sdk.get(f"{ns}targetSdkVersion")
                            or uses_sdk.get("targetSdkVersion")
                        )

                # Permissions
                for perm in root.findall("uses-permission"):
                    name = perm.get(f"{ns}name") or perm.get("name")
                    if name:
                        result.permissions.append(PermissionInfo(name=name))

                for perm in root.findall("permission"):
                    name = perm.get(f"{ns}name") or perm.get("name")
                    prot = perm.get(f"{ns}protectionLevel") or perm.get("protectionLevel")
                    if name:
                        result.declared_permissions.append(
                            PermissionInfo(name=name, protection_level=prot)
                        )

                # Application
                app_elem = root.find("application")
                if app_elem is not None:
                    app_info = ApplicationInfo()
                    label = app_elem.get(f"{ns}label") or app_elem.get("label")
                    if label and not label.startswith("@"):
                        app_info.label = label
                    app_info.debuggable = _safe_bool(
                        app_elem.get(f"{ns}debuggable") or app_elem.get("debuggable")
                    )
                    app_info.allow_backup = _safe_bool(
                        app_elem.get(f"{ns}allowBackup") or app_elem.get("allowBackup")
                    )
                    app_info.uses_cleartext_traffic = _safe_bool(
                        app_elem.get(f"{ns}usesCleartextTraffic")
                        or app_elem.get("usesCleartextTraffic")
                    )
                    app_info.network_security_config = app_elem.get(
                        f"{ns}networkSecurityConfig"
                    ) or app_elem.get("networkSecurityConfig")
                    result.application = app_info

                    # Activities
                    for act_elem in app_elem.findall("activity"):
                        name = act_elem.get(f"{ns}name") or act_elem.get("name")
                        if name:
                            result.activities.append(
                                ActivityInfo(
                                    name=name,
                                    exported=_safe_bool(
                                        act_elem.get(f"{ns}exported") or act_elem.get("exported")
                                    ),
                                    intent_filters=self._extract_intent_filters(act_elem),
                                )
                            )

                    # Services
                    for svc_elem in app_elem.findall("service"):
                        name = svc_elem.get(f"{ns}name") or svc_elem.get("name")
                        if name:
                            result.services.append(
                                ServiceInfo(
                                    name=name,
                                    exported=_safe_bool(
                                        svc_elem.get(f"{ns}exported") or svc_elem.get("exported")
                                    ),
                                    permission=(
                                        svc_elem.get(f"{ns}permission")
                                        or svc_elem.get("permission")
                                    ),
                                    intent_filters=self._extract_intent_filters(svc_elem),
                                )
                            )

                    # Receivers
                    for rec_elem in app_elem.findall("receiver"):
                        name = rec_elem.get(f"{ns}name") or rec_elem.get("name")
                        if name:
                            result.receivers.append(
                                BroadcastReceiverInfo(
                                    name=name,
                                    exported=_safe_bool(
                                        rec_elem.get(f"{ns}exported") or rec_elem.get("exported")
                                    ),
                                    intent_filters=self._extract_intent_filters(rec_elem),
                                )
                            )

                    # Providers
                    for prov_elem in app_elem.findall("provider"):
                        name = prov_elem.get(f"{ns}name") or prov_elem.get("name")
                        if name:
                            result.providers.append(
                                ContentProviderInfo(
                                    name=name,
                                    authorities=(
                                        prov_elem.get(f"{ns}authorities")
                                        or prov_elem.get("authorities")
                                    ),
                                    exported=_safe_bool(
                                        prov_elem.get(f"{ns}exported") or prov_elem.get("exported")
                                    ),
                                    read_permission=(
                                        prov_elem.get(f"{ns}readPermission")
                                        or prov_elem.get("readPermission")
                                    ),
                                    write_permission=(
                                        prov_elem.get(f"{ns}writePermission")
                                        or prov_elem.get("writePermission")
                                    ),
                                    grant_uri_permissions=_safe_bool(
                                        prov_elem.get(f"{ns}grantUriPermissions")
                                        or prov_elem.get("grantUriPermissions")
                                    ),
                                )
                            )

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Fallback manifest parsing failed: {exc}")

        return result, warnings
