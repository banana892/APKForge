"""Parse Morphe Desktop's ``list-patches`` text output (H.8.2).

Morphe has no JSON output for this command (checked: ``list-patches --help`` offers
only ``--out FILE``, still plain text), so the adapter parses the real format
instead. Verified against the live ``MorpheApp/morphe-patches`` v2.0.0 bundle, with
both ``--with-packages``/``--with-versions`` on and off, and the one real quirk the
tool has: the first ``Index: 0`` line of a run comes out as ``INFO: Index: 0``
because Morphe's last startup log line never gets its own trailing newline.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

__all__ = ["PatchBundleListing", "PatchCompatibility", "PatchInfo", "parse_patch_listing"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PatchCompatibility(_Frozen):
    package: str
    versions: tuple[str, ...] = ()


class PatchInfo(_Frozen):
    index: int
    name: str
    description: str = ""
    enabled: bool = False
    #: Empty when the patch is compatible with any app (or compatibility wasn't
    #: requested); Morphe calls this "universal".
    compatible: tuple[PatchCompatibility, ...] = ()


class PatchBundleListing(_Frozen):
    #: The ``--patches`` value passed in (a local .mpp path or a repo URL).
    source: str
    #: Parsed from "Resolved patches (VERSION) at PATH", when Morphe logs it
    #: (only for a repo URL: a local .mpp file is used as given).
    resolved_version: str | None = None
    resolved_path: str | None = None
    patches: tuple[PatchInfo, ...] = ()


_INDEX_RE = re.compile(r"^(?:INFO: )?Index:\s*(\d+)\s*$", re.MULTILINE)
_RESOLVED_RE = re.compile(r"^INFO: Resolved patches \((.+?)\) at (.+)$", re.MULTILINE)
_PACKAGE_RE = re.compile(r"^\s*Package name:\s*(.*)$")
_VERSIONS_HEADER_RE = re.compile(r"^\s*Compatible versions:\s*$")


def _parse_block(index: int, block: str) -> PatchInfo:
    name = ""
    description = ""
    enabled = False
    compatible: list[PatchCompatibility] = []
    current_package: str | None = None
    current_versions: list[str] = []

    def flush() -> None:
        if current_package is not None:
            compatible.append(
                PatchCompatibility(package=current_package, versions=tuple(current_versions))
            )

    for line in block.splitlines():
        if line.startswith("Name: "):
            name = line.removeprefix("Name: ")
        elif line.startswith("Description: "):
            description = line.removeprefix("Description: ")
        elif line.startswith("Enabled: "):
            enabled = line.removeprefix("Enabled: ").strip().lower() == "true"
        elif m := _PACKAGE_RE.match(line):
            flush()
            current_package, current_versions = m.group(1).strip(), []
        elif _VERSIONS_HEADER_RE.match(line) or not line.strip():
            continue
        elif current_package is not None:
            current_versions.append(line.strip())
    flush()
    return PatchInfo(
        index=index, name=name, description=description, enabled=enabled,
        compatible=tuple(compatible),
    )  # fmt: skip


def parse_patch_listing(source: str, text: str) -> PatchBundleListing:
    """Parse Morphe's ``list-patches`` stdout into a :class:`PatchBundleListing`."""
    resolved_version = resolved_path = None
    if m := _RESOLVED_RE.search(text):
        resolved_version, resolved_path = m.group(1), m.group(2)
    markers = list(_INDEX_RE.finditer(text))
    patches = tuple(
        _parse_block(
            int(m.group(1)),
            text[m.end() : markers[i + 1].start() if i + 1 < len(markers) else len(text)],
        )
        for i, m in enumerate(markers)
    )
    return PatchBundleListing(
        source=source, resolved_version=resolved_version, resolved_path=resolved_path,
        patches=patches,
    )  # fmt: skip
