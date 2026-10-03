"""Archive inventory and raw diff (Phase E1).

The lowest comparison layer: what is in each APK, entry by entry, and which entries
differ. Nothing is normalised, paired or interpreted here — a raw diff must be able to
show everything that actually changed, so later layers can explain it (or fail to).

- :class:`ArchiveInventory` reads a ZIP once and records, for every entry, its path,
  sizes, CRC, SHA-256 of the uncompressed content, ZIP metadata and an entry kind.
- :func:`raw_diff` compares two inventories by exact path and content hash:
  ``added`` / ``removed`` / ``modified`` / ``unchanged``. Entries whose content is
  identical but whose ZIP metadata (timestamp, compression method, extra field) differ
  stay ``unchanged`` and are flagged ``metadata_changed`` — observed rebuild behaviour
  (two rebuilds of one APK with one toolchain differ only in entry timestamps), never a
  content change.

Kinds are assigned from the path alone and never assume a fixed APK layout: any number
of ``classesN.dex``, any ABI under ``lib/``, nested asset paths, embedded archives and
unusual-but-valid paths are recorded as found.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from collections import Counter
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "RAW_DIFF_SCHEMA_VERSION",
    "ArchiveEntry",
    "ArchiveInventory",
    "EntryKind",
    "RawChange",
    "RawDiff",
    "RawEntryDiff",
    "classify_archive_path",
    "raw_diff",
]

RAW_DIFF_SCHEMA_VERSION = 1

_DEX = re.compile(r"^classes\d*\.dex$")
_SIGNATURE = re.compile(r"^META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$", re.I)
_ABI = re.compile(r"^lib/([^/]+)/[^/]+$")
_EXECUTABLE_EXT = (".dex", ".jar", ".apk", ".so", ".odex", ".oat", ".vdex", ".elf", ".bin")


class EntryKind(StrEnum):
    MANIFEST = "manifest"
    DEX = "dex"
    RESOURCE_TABLE = "resource_table"
    RESOURCE = "resource"
    ASSET = "asset"
    NATIVE_LIBRARY = "native_library"
    LIB_OTHER = "lib_other"  # under lib/ but not lib/<abi>/<name>.so
    SIGNATURE = "signature"  # v1 signature files: MANIFEST.MF, *.SF, *.RSA/DSA/EC
    SIGNING_METADATA = "signing_metadata"  # stamp-cert-sha256 (source stamp)
    META_INF = "meta_inf"  # other META-INF/ entries (version files, services...)
    EMBEDDED_ARCHIVE = "embedded_archive"  # *.apk / *.jar / *.zip anywhere
    OTHER = "other"


def classify_archive_path(path: str) -> EntryKind:
    """Entry kind from the path alone."""
    parts = PurePosixPath(path).parts
    top = parts[0] if parts else ""
    lower = path.lower()
    if path == "AndroidManifest.xml":
        return EntryKind.MANIFEST
    if _DEX.match(path):
        return EntryKind.DEX
    if path == "resources.arsc":
        return EntryKind.RESOURCE_TABLE
    if path == "stamp-cert-sha256":
        return EntryKind.SIGNING_METADATA
    if _SIGNATURE.match(path):
        return EntryKind.SIGNATURE
    if lower.endswith((".apk", ".jar", ".zip")) and top != "res":
        return EntryKind.EMBEDDED_ARCHIVE
    if top == "res":
        return EntryKind.RESOURCE
    if top == "assets":
        return EntryKind.ASSET
    if top == "lib":
        return (
            EntryKind.NATIVE_LIBRARY
            if _ABI.match(path) and lower.endswith(".so")
            else EntryKind.LIB_OTHER
        )
    if top == "META-INF":
        return EntryKind.META_INF
    return EntryKind.OTHER


def _unusual(path: str) -> list[str]:
    notes = []
    if path.startswith("/"):
        notes.append("absolute path")
    if "\\" in path:
        notes.append("backslash in path")
    if any(seg in ("..", ".") for seg in path.split("/")):
        notes.append("dot segment")
    if "//" in path:
        notes.append("empty path segment")
    if any(ord(ch) < 0x20 for ch in path):
        notes.append("control character")
    return notes


class ArchiveEntry(BaseModel):
    path: str
    kind: EntryKind
    size: int
    compressed_size: int
    crc32: str
    sha256: str
    compress_type: int
    date_time: str
    extra_length: int
    abi: str | None = None
    notes: list[str] = Field(default_factory=list)


class ArchiveInventory(BaseModel):
    """Every entry of one APK, keyed by path."""

    source_sha256: str
    entry_count: int = 0
    entries: dict[str, ArchiveEntry] = Field(default_factory=dict)
    duplicate_names: list[str] = Field(default_factory=list)
    directories: int = 0
    unreadable: list[str] = Field(default_factory=list)

    @classmethod
    def from_apk(cls, apk: Path) -> ArchiveInventory:
        """Read *apk*. Raises ``zipfile.BadZipFile`` / ``OSError`` if it is not a ZIP."""
        h = hashlib.sha256()
        with Path(apk).open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        inv = cls(source_sha256=h.hexdigest())
        with zipfile.ZipFile(apk) as z:
            infos = z.infolist()
            counts = Counter(i.filename for i in infos)
            inv.duplicate_names = sorted(n for n, c in counts.items() if c > 1)
            for info in infos:
                if info.is_dir():
                    inv.directories += 1
                    continue
                try:
                    data = z.read(info)
                except Exception as exc:  # corrupt entry: recorded, never skipped silently
                    inv.unreadable.append(f"{info.filename}: {type(exc).__name__}: {exc}")
                    continue
                kind = classify_archive_path(info.filename)
                m = _ABI.match(info.filename)
                inv.entries[info.filename] = ArchiveEntry(
                    path=info.filename,
                    kind=kind,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    crc32=f"{info.CRC:08x}",
                    sha256=hashlib.sha256(data).hexdigest(),
                    compress_type=info.compress_type,
                    date_time="{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}".format(*info.date_time),
                    extra_length=len(info.extra),
                    abi=m.group(1) if m and kind == EntryKind.NATIVE_LIBRARY else None,
                    notes=_unusual(info.filename),
                )
        inv.entry_count = len(inv.entries)
        return inv

    def by_kind(self) -> dict[str, int]:
        return dict(sorted(Counter(str(e.kind) for e in self.entries.values()).items()))

    def summary(self) -> dict[str, Any]:
        abis = sorted({e.abi for e in self.entries.values() if e.abi})
        return {
            "sha256": self.source_sha256,
            "entries": self.entry_count,
            "by_kind": self.by_kind(),
            "dex_files": sorted(p for p, e in self.entries.items() if e.kind == EntryKind.DEX),
            "abis": abis,
            "duplicate_names": self.duplicate_names,
            "unusual_paths": sorted(p for p, e in self.entries.items() if e.notes),
            "unreadable": self.unreadable,
        }


class RawChange(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class RawEntryDiff(BaseModel):
    path: str
    change: RawChange
    kind: EntryKind
    size_before: int | None = None
    size_after: int | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None
    metadata_changed: bool = False


class RawDiff(BaseModel):
    """Exact-path, content-hash comparison of two archives. No normalisation."""

    schema_version: int = RAW_DIFF_SCHEMA_VERSION
    sha256_before: str
    sha256_after: str
    counts: dict[str, int] = Field(default_factory=dict)
    counts_by_kind: dict[str, dict[str, int]] = Field(default_factory=dict)
    metadata_only_changes: int = 0
    entries: list[RawEntryDiff] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)

    def changed(self) -> list[RawEntryDiff]:
        return [e for e in self.entries if e.change != RawChange.UNCHANGED]

    def entry(self, path: str) -> RawEntryDiff | None:
        return next((e for e in self.entries if e.path == path), None)


def raw_diff(a: ArchiveInventory, b: ArchiveInventory) -> RawDiff:
    """Compare two inventories by exact path and SHA-256 of entry content."""
    out: list[RawEntryDiff] = []
    for path in sorted(set(a.entries) | set(b.entries)):
        ea, eb = a.entries.get(path), b.entries.get(path)
        if ea is None and eb is not None:
            change = RawChange.ADDED
        elif eb is None and ea is not None:
            change = RawChange.REMOVED
        elif ea is not None and eb is not None and ea.sha256 != eb.sha256:
            change = RawChange.MODIFIED
        else:
            change = RawChange.UNCHANGED
        ref = eb or ea
        assert ref is not None
        meta = bool(
            ea
            and eb
            and change == RawChange.UNCHANGED
            and (ea.date_time, ea.compress_type, ea.extra_length)
            != (eb.date_time, eb.compress_type, eb.extra_length)
        )
        out.append(
            RawEntryDiff(
                path=path,
                change=change,
                kind=ref.kind,
                size_before=ea.size if ea else None,
                size_after=eb.size if eb else None,
                sha256_before=ea.sha256 if ea else None,
                sha256_after=eb.sha256 if eb else None,
                metadata_changed=meta,
            )
        )
    counts = Counter(str(e.change) for e in out)
    by_kind: dict[str, Counter[str]] = {}
    for e in out:
        by_kind.setdefault(str(e.kind), Counter())[str(e.change)] += 1
    problems = [
        f"{side}: duplicate entry name {n}"
        for side, inv in (("A", a), ("B", b))
        for n in inv.duplicate_names
    ]
    problems += [
        f"{side}: unreadable entry {n}"
        for side, inv in (("A", a), ("B", b))
        for n in inv.unreadable
    ]
    return RawDiff(
        sha256_before=a.source_sha256,
        sha256_after=b.source_sha256,
        counts={c.value: counts.get(c.value, 0) for c in RawChange},
        counts_by_kind={k: dict(sorted(v.items())) for k, v in sorted(by_kind.items())},
        metadata_only_changes=sum(1 for e in out if e.metadata_changed),
        entries=out,
        problems=problems,
    )
