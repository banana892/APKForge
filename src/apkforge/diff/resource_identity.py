"""ARSC-based resource identity resolution for rename/canonicalization pairing.

Content-hash rename matching (see :mod:`apkforge.diff.files`) only pairs a
removed path with an added path when their bytes are byte-for-byte
identical. That catches a plain file move, but Apktool/aapt2 frequently
*re-encodes* a resource during decode/rebuild (e.g. collapsed/obfuscated
filenames like ``res/bX.xml`` are restored to canonical paths like
``res/drawable/ic_call_answer.xml``, and the binary XML itself may be
re-serialized in the process) -- the bytes differ even though it is the
same logical resource.

This module establishes a resource's *canonical identity* --
``type/name/qualifier`` from the resource table (``resources.arsc``) --
independent of its current file path, so that a removed path and an added
path can be paired when they resolve to the same identity even though their
content hash differs.
"""

from __future__ import annotations

import contextlib
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["build_resource_identity_map"]


def build_resource_identity_map(apk_path: Path) -> dict[str, str]:
    """Map each file-backed resource path inside *apk_path* to a canonical identity.

    The identity is ``"{type}/{name}/{qualifier}"`` (e.g.
    ``"drawable/ic_call_answer/hdpi"``), derived from the resource table
    entry that owns the path -- not from the path's text. Two APKs built
    from the same underlying app will assign the same identity to "the same"
    resource even if its numeric resource ID or on-disk filename changed
    between builds.

    Only resources whose resolved value is itself a file path (the value
    string starts with ``"res/"``) are included -- inline-valued resources
    (strings, dimens, colors-as-ints, booleans, ...) have no file identity
    to rename.

    Returns an empty mapping (never raises) if the APK has no usable
    ``resources.arsc``, or if Androguard cannot parse it -- callers must
    treat an empty/partial mapping as "identity unknown" and fall back to
    treating the path as a plain add/remove rather than guessing a pairing.
    """
    identity_map: dict[str, str] = {}

    try:
        from androguard.core.apk import APK
    except ImportError:
        return identity_map

    with contextlib.suppress(Exception):
        apk = APK(str(apk_path))
        arsc = apk.get_android_resources()
        if arsc is None:
            return identity_map

        for package_name in arsc.get_packages_names():
            with contextlib.suppress(Exception):
                _collect_package_identities(arsc, package_name, identity_map)

    return identity_map


def _collect_package_identities(
    arsc: object,
    package_name: str,
    identity_map: dict[str, str],
) -> None:
    """Populate *identity_map* with the file-backed resources of one ARSC package."""
    pub_xml = arsc.get_public_resources(package_name)  # type: ignore[attr-defined]
    root = ET.fromstring(pub_xml)  # noqa: S314 -- trusted output of our own ARSC parser

    for entry in root.findall("public"):
        res_type = entry.get("type")
        res_name = entry.get("name")
        res_id_str = entry.get("id")
        if not res_type or not res_name or not res_id_str:
            continue

        try:
            res_id = int(res_id_str, 16)
        except ValueError:
            continue

        with contextlib.suppress(Exception):
            for config, value in arsc.get_resolved_res_configs(res_id):  # type: ignore[attr-defined]
                if not isinstance(value, str) or not value.startswith("res/"):
                    continue
                qualifier = ""
                with contextlib.suppress(Exception):
                    qualifier = config.get_qualifier() or ""
                identity = f"{res_type}/{res_name}/{qualifier}"
                identity_map[value] = identity
