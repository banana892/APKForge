"""Helpers for the Phase E negative scenarios (tampering real APKs after the build)."""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["flip_resource_string", "rezip", "tamper_first"]


def flip_resource_string(data: bytes) -> bytes:
    """Change one letter of a lowercase run (>= 6 letters) in a binary XML string pool.

    Handles UTF-8 pools (aapt2) and UTF-16LE pools. The chunk structure stays valid;
    only one string-pool character differs. Common namespace words are skipped.
    """
    skip = ("android", "http", "schemas", "apk/res")
    for width in (1, 2):  # UTF-8, then UTF-16LE
        step = width
        span = 6 * width
        for i in range(0, len(data) - span, step):
            run = data[i : i + span]
            letters = run[::width]
            if not all(97 <= b <= 122 for b in letters):
                continue
            if width == 2 and any(run[j] != 0 for j in range(1, span, 2)):
                continue
            context = data[max(0, i - 8 * width) : i + 16 * width][::width]
            if any(w.encode() in context for w in skip):
                continue
            ch = data[i]
            return data[:i] + bytes([97 + (ch - 97 + 1) % 26]) + data[i + 1 :]
    raise ValueError("no suitable string found")


def rezip(src: Path, dst: Path, replace: dict[str, bytes]) -> None:
    """Copy *src* to *dst* entry by entry, replacing some entries' content.

    Python's zipfile does not carry over the APK Signing Block, and replaced entries no
    longer match the v1 digests: the result is NOT validly signed unless re-signed.
    """
    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w") as zo:
        for info in zi.infolist():
            zo.writestr(info, replace.get(info.filename, zi.read(info)))


def tamper_first(apk: Path, candidates: list[str]) -> tuple[str, bytes]:
    """The first candidate entry whose string pool can be altered, with altered bytes."""
    with zipfile.ZipFile(apk) as z:
        for name in candidates:
            try:
                return name, flip_resource_string(z.read(name))
            except (ValueError, KeyError):
                continue
    raise ValueError("no candidate entry could be altered")
