"""Parse Morphe Desktop's ``list-patches`` text output (H.8.2; H.8.6 adds options).

Morphe has no JSON output for this command (checked: ``list-patches --help`` offers
only ``--out FILE``, still plain text), so the adapter parses the real format
instead. Verified against the live ``MorpheApp/morphe-patches`` v2.0.0 bundle, with
both ``--with-packages``/``--with-versions`` on and off, and the one real quirk the
tool has: the first ``Index: 0`` line of a run comes out as ``INFO: Index: 0``
because Morphe's last startup log line never gets its own trailing newline.

``--with-options`` (H.8.6) is its own real mess: an option's ``Description`` is
free-form text straight from the patch's own source and can span multiple lines with
arbitrary/inconsistent indentation (including lines with *no* leading whitespace at
all, mid-description) - so unlike everything else here, options are **not** parsed
line-by-line. Every other option field (``Title``/``Required``/``Key``/``Default``/
``Possible values``/``Type``) is reliably a single, consistently-ordered line, so each
option's free-form ``Description`` is instead extracted by slicing the raw text
between the fixed ``Description:``/``Required:`` anchors - the same reason every
other option field is located the same way rather than by indentation.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

__all__ = [
    "PatchBundleListing",
    "PatchCompatibility",
    "PatchInfo",
    "PatchOption",
    "PatchOptionValue",
    "parse_patch_listing",
]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PatchCompatibility(_Frozen):
    package: str
    versions: tuple[str, ...] = ()


class PatchOptionValue(_Frozen):
    value: str
    label: str = ""


class PatchOption(_Frozen):
    #: The ``-O key=value`` key Morphe's ``patch`` command expects.
    key: str
    title: str = ""
    description: str = ""
    required: bool = False
    default: str = ""
    type: str = ""
    #: Empty unless the option is restricted to specific values.
    possible_values: tuple[PatchOptionValue, ...] = ()


class PatchInfo(_Frozen):
    index: int
    name: str
    description: str = ""
    enabled: bool = False
    #: Empty when the patch is compatible with any app (or compatibility wasn't
    #: requested); Morphe calls this "universal".
    compatible: tuple[PatchCompatibility, ...] = ()
    #: Empty unless the patch is configurable and ``--with-options`` was requested.
    options: tuple[PatchOption, ...] = ()


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

_OPTIONS_HEADER_RE = re.compile(r"^[ \t]*Options:[ \t]*$", re.MULTILINE)
_COMPAT_HEADER_RE = re.compile(r"^[ \t]*Compatible packages:[ \t]*$", re.MULTILINE)
_OPTION_TITLE_RE = re.compile(r"^[ \t]*Title:[ \t]*(.*)$", re.MULTILINE)
_OPTION_DESCRIPTION_START_RE = re.compile(r"^[ \t]*Description:", re.MULTILINE)
_OPTION_REQUIRED_RE = re.compile(r"^[ \t]*Required:[ \t]*(true|false)[ \t]*$", re.MULTILINE)
_OPTION_KEY_RE = re.compile(r"^[ \t]*Key:[ \t]*(.*)$", re.MULTILINE)
_OPTION_DEFAULT_RE = re.compile(r"^[ \t]*Default:[ \t]*(.*)$", re.MULTILINE)
_OPTION_TYPE_RE = re.compile(r"^[ \t]*Type:[ \t]*(.*)$", re.MULTILINE)
_POSSIBLE_VALUES_HEADER_RE = re.compile(r"^[ \t]*Possible values:[ \t]*$", re.MULTILINE)


def _parse_option_value_line(line: str) -> PatchOptionValue:
    line = line.strip()
    if line.endswith(")") and " (" in line:
        value, _, label = line[:-1].rpartition(" (")
        return PatchOptionValue(value=value.strip(), label=label.strip())
    return PatchOptionValue(value=line)


def _option_field(text: str, pattern: re.Pattern[str]) -> str:
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


def _parse_option(text: str) -> PatchOption:
    desc_m = _OPTION_DESCRIPTION_START_RE.search(text)
    req_m = _OPTION_REQUIRED_RE.search(text)
    description = text[desc_m.end() : req_m.start()].strip() if desc_m and req_m else ""

    possible_values: tuple[PatchOptionValue, ...] = ()
    pv_m = _POSSIBLE_VALUES_HEADER_RE.search(text)
    type_m = _OPTION_TYPE_RE.search(text)
    if pv_m and type_m and pv_m.end() <= type_m.start():
        possible_values = tuple(
            _parse_option_value_line(line)
            for line in text[pv_m.end() : type_m.start()].splitlines()
            if line.strip()
        )
    return PatchOption(
        key=_option_field(text, _OPTION_KEY_RE),
        title=_option_field(text, _OPTION_TITLE_RE),
        description=description,
        required=_option_field(text, _OPTION_REQUIRED_RE).lower() == "true",
        default=_option_field(text, _OPTION_DEFAULT_RE),
        type=_option_field(text, _OPTION_TYPE_RE),
        possible_values=possible_values,
    )


def _parse_options(block: str) -> tuple[PatchOption, ...]:
    """Parse the ``Options:`` sub-section of one patch's block, if present."""
    header = _OPTIONS_HEADER_RE.search(block)
    if not header:
        return ()
    end = _COMPAT_HEADER_RE.search(block, header.end())
    section = block[header.end() : end.start() if end else len(block)]
    titles = list(_OPTION_TITLE_RE.finditer(section))
    return tuple(
        _parse_option(
            section[m.start() : titles[i + 1].start() if i + 1 < len(titles) else len(section)]
        )
        for i, m in enumerate(titles)
    )


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
        compatible=tuple(compatible), options=_parse_options(block),
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
