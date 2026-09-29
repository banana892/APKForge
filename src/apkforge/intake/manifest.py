"""AndroidManifest.xml parsing.

Wraps Androguard's APK class to extract identification-level metadata from
the binary Android XML format.  The wrapper isolates the rest of APKForge
from the Androguard API so that the library can be replaced later without
touching consumers.

Phase 1 extracts only identification fields:
- package name
- version name / version code
- min SDK / target SDK / compile SDK
- application label
- application debuggable flag

Permissions, components, intent filters, etc. belong to Phase 2+.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.intake import APKMetadata

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["parse_apk_manifest", "parse_manifest_from_bytes"]

_log = get_logger(__name__)


def _safe_int(value: object) -> int | None:
    """Try to convert *value* to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def parse_apk_manifest(apk_path: Path) -> tuple[APKMetadata, list[str]]:
    """Parse manifest metadata from an APK file on disk.

    Args:
        apk_path: Path to the APK file.

    Returns:
        A tuple of (APKMetadata, warnings).  *warnings* contains non-fatal
        issues encountered during parsing.
    """
    warnings: list[str] = []

    try:
        from androguard.core.apk import APK
    except ImportError:
        warnings.append("Androguard not installed; manifest parsing unavailable.")
        return APKMetadata(), warnings

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        _log.warning("Androguard failed to parse APK: %s", exc)
        warnings.append(f"Manifest parsing failed: {exc}")
        return APKMetadata(), warnings

    meta = APKMetadata()

    try:
        meta.package_name = apk.get_package() or None
    except Exception:
        warnings.append("Could not extract package name.")

    try:
        meta.version_name = apk.get_androidversion_name() or None
    except Exception:
        warnings.append("Could not extract version name.")

    try:
        meta.version_code = _safe_int(apk.get_androidversion_code())
    except Exception:
        warnings.append("Could not extract version code.")

    try:
        meta.min_sdk = _safe_int(apk.get_min_sdk_version())
    except Exception:
        warnings.append("Could not extract min SDK version.")

    try:
        meta.target_sdk = _safe_int(apk.get_target_sdk_version())
    except Exception:
        warnings.append("Could not extract target SDK version.")

    with contextlib.suppress(Exception):
        effective = apk.get_effective_target_sdk_version()
        if effective is not None:
            meta.compile_sdk = _safe_int(effective)

    with contextlib.suppress(Exception):
        label = apk.get_app_name()
        meta.application_label = label if label else None

    with contextlib.suppress(Exception):
        debuggable = apk.get_attribute_value("application", "debuggable")
        if debuggable is not None:
            meta.application_debuggable = str(debuggable).lower() in ("true", "1")

    # If Androguard could not extract a package name (e.g. plain XML manifest),
    # fall back to direct byte-level parsing.
    if meta.package_name is None:
        import zipfile

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    raw_manifest = zf.read("AndroidManifest.xml")
                    fallback_meta, fallback_warnings = parse_manifest_from_bytes(raw_manifest)
                    if fallback_meta.package_name:
                        return fallback_meta, fallback_warnings
        except Exception as exc:
            _log.debug("Fallback manifest read failed: %s", exc)

    return meta, warnings


def parse_manifest_from_bytes(manifest_bytes: bytes) -> tuple[APKMetadata, list[str]]:
    """Parse manifest metadata from raw AndroidManifest.xml bytes.

    This handles the binary AXML format used inside APK files.  Falls back
    to plain XML parsing if AXML fails.

    Args:
        manifest_bytes: Raw bytes of the AndroidManifest.xml entry.

    Returns:
        A tuple of (APKMetadata, warnings).
    """
    warnings: list[str] = []

    # Try Androguard AXML parser
    try:
        from androguard.core.axml import AXMLPrinter

        axml = AXMLPrinter(manifest_bytes)
        xml_str = axml.get_xml()
    except ImportError:
        warnings.append("Androguard not installed; cannot parse binary manifest.")
        return APKMetadata(), warnings
    except Exception as exc:
        _log.debug("AXML parsing failed, trying plain XML: %s", exc)
        xml_str = manifest_bytes.decode("utf-8", errors="replace")

    # Parse the XML string
    xml_text = xml_str.decode("utf-8", errors="replace") if isinstance(xml_str, bytes) else xml_str
    return _parse_xml_string(xml_text, warnings)


def _parse_xml_string(
    xml_str: str,
    warnings: list[str],
) -> tuple[APKMetadata, list[str]]:
    """Extract metadata from an XML string representation of the manifest."""
    import xml.etree.ElementTree as ET

    meta = APKMetadata()

    try:
        root = ET.fromstring(xml_str)  # noqa: S314
    except ET.ParseError as exc:
        warnings.append(f"XML parse error: {exc}")
        return meta, warnings

    ns = "{http://schemas.android.com/apk/res/android}"

    meta.package_name = root.get("package")
    meta.version_name = root.get(f"{ns}versionName") or root.get("versionName")
    meta.version_code = _safe_int(root.get(f"{ns}versionCode") or root.get("versionCode"))
    meta.compile_sdk = _safe_int(
        root.get(f"{ns}compileSdkVersion") or root.get("compileSdkVersion")
    )

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk_val = uses_sdk.get(f"{ns}minSdkVersion") or uses_sdk.get("minSdkVersion")
        meta.min_sdk = _safe_int(min_sdk_val)
        meta.target_sdk = _safe_int(
            uses_sdk.get(f"{ns}targetSdkVersion") or uses_sdk.get("targetSdkVersion")
        )

    app = root.find("application")
    if app is not None:
        label = app.get(f"{ns}label") or app.get("label")
        if label and not label.startswith("@"):
            meta.application_label = label
        debuggable = app.get(f"{ns}debuggable") or app.get("debuggable")
        if debuggable is not None:
            meta.application_debuggable = debuggable.lower() == "true"

    return meta, warnings
