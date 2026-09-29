"""String extraction utilities — printable string scanning.

Extracts printable ASCII and UTF-8 strings from binary data and files.
Used by DEX, native, and asset inspectors.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from apkforge.inspection.models import EvidenceSource, StringReference

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "StringInspector",
    "extract_ascii_strings",
    "extract_string_references",
]

# Regex for printable ASCII sequences of at least *min_len* characters
_ASCII_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_ascii_strings(data: bytes, min_len: int = 4, limit: int = 10_000) -> list[str]:
    """Extract printable ASCII strings from raw byte data.

    Args:
        data: Raw bytes to scan.
        min_len: Minimum string length to extract (default: 4).
        limit: Maximum number of strings to return.

    Returns:
        List of decoded strings.
    """
    if min_len != 4:
        pattern = re.compile(rf"[\x20-\x7e]{{{min_len},}}".encode("ascii"))
    else:
        pattern = _ASCII_PRINTABLE

    matches: list[str] = []
    for match in pattern.finditer(data):
        try:
            val = match.group().decode("ascii")
            matches.append(val)
            if len(matches) >= limit:
                break
        except UnicodeDecodeError:
            continue
    return matches


def extract_string_references(
    data: bytes,
    source_file: str,
    min_len: int = 4,
    limit: int = 10_000,
) -> list[StringReference]:
    """Extract printable strings as StringReference models with byte offsets.

    Args:
        data: Raw bytes to scan.
        source_file: Name of the file being scanned (e.g. 'classes.dex').
        min_len: Minimum string length.
        limit: Maximum number of strings to return.

    Returns:
        List of StringReference instances.
    """
    if min_len != 4:
        pattern = re.compile(rf"[\x20-\x7e]{{{min_len},}}".encode("ascii"))
    else:
        pattern = _ASCII_PRINTABLE

    results: list[StringReference] = []
    for match in pattern.finditer(data):
        try:
            val = match.group().decode("ascii")
            results.append(
                StringReference(
                    value=val,
                    dex_file=source_file,
                    source=EvidenceSource(file=source_file, offset=match.start()),
                )
            )
            if len(results) >= limit:
                break
        except UnicodeDecodeError:
            continue
    return results


class StringInspector:
    """Inspector for extracting printable strings from binary data."""

    def __init__(self, min_len: int = 4, limit: int = 10_000) -> None:
        self.min_len = min_len
        self.limit = limit

    def scan_bytes(self, data: bytes, source_file: str = "binary") -> list[StringReference]:
        """Scan raw bytes and return StringReference objects."""
        return extract_string_references(data, source_file, min_len=self.min_len, limit=self.limit)

    def scan_file(self, file_path: Path) -> list[StringReference]:
        """Scan a file on disk and return StringReference objects."""
        try:
            data = file_path.read_bytes()
            return self.scan_bytes(data, source_file=file_path.name)
        except OSError:
            return []
