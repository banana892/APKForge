"""Safe archive handling for untrusted ZIP/APK files.

Every APK is untrusted input.  This module provides safe extraction with:
- Path traversal prevention (zip-slip)
- Absolute-path rejection
- File count limits
- Per-file and total size limits
- Malformed archive detection

All limits come from :class:`~apkforge.core.config.ExtractionLimits`.
"""

from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from apkforge.core.exceptions import ExtractionError
from apkforge.core.logging import get_logger

if TYPE_CHECKING:
    from apkforge.core.config import ExtractionLimits

__all__ = ["SafeZipExtractor", "is_zip_file", "validate_zip"]

_log = get_logger(__name__)


def is_zip_file(path: Path) -> bool:
    """Return True if *path* appears to be a ZIP-compatible archive.

    Checks the file magic bytes rather than the extension.
    """
    try:
        with path.open("rb") as fh:
            magic = fh.read(4)
        # PK magic: 0x50 0x4B 0x03 0x04 (local file header)
        # Also accept 0x50 0x4B 0x05 0x06 (empty archive — end of central dir)
        return magic[:2] == b"PK" and len(magic) >= 4
    except OSError:
        return False


def validate_zip(path: Path) -> list[str]:
    """Validate that *path* is a well-formed ZIP archive.

    Returns a list of warning strings.  An empty list means the archive
    is structurally valid.  Raises :class:`ExtractionError` for fatal issues.
    """
    warnings: list[str] = []

    if not path.is_file():
        raise ExtractionError(f"Not a file: {path}", context="archive-validate")

    if not is_zip_file(path):
        raise ExtractionError(
            f"Not a ZIP-compatible archive: {path}",
            context="archive-validate",
        )

    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                warnings.append(f"Corrupt entry detected: {bad}")
    except zipfile.BadZipFile as exc:
        raise ExtractionError(
            f"Bad ZIP file: {path} — {exc}",
            context="archive-validate",
        ) from exc
    except OSError as exc:
        raise ExtractionError(
            f"Cannot open archive: {path} — {exc}",
            context="archive-validate",
        ) from exc

    return warnings


class SafeZipExtractor:
    """Extracts ZIP entries with security limits enforced.

    This class never extracts the full archive blindly.  Instead, callers
    request specific entries or iterate with validation.

    Args:
        path: Path to the ZIP archive.
        limits: Extraction limits from configuration.
    """

    def __init__(self, path: Path, limits: ExtractionLimits) -> None:
        self._path = path
        self._limits = limits

    def list_entries(self) -> list[zipfile.ZipInfo]:
        """Return the list of entries in the archive, rejecting unsafe ones.

        Raises:
            ExtractionError: If the archive exceeds file count limits or
                contains unsafe paths.
        """
        try:
            with zipfile.ZipFile(self._path, "r") as zf:
                entries = zf.infolist()
        except (zipfile.BadZipFile, OSError) as exc:
            raise ExtractionError(
                f"Cannot read archive: {self._path} — {exc}",
                context="archive-list",
            ) from exc

        if len(entries) > self._limits.max_file_count:
            raise ExtractionError(
                f"Archive contains {len(entries)} entries, "
                f"exceeding limit of {self._limits.max_file_count}",
                context="archive-limits",
            )

        # Validate each entry path
        for entry in entries:
            self._validate_entry_path(entry.filename)
            if entry.file_size > self._limits.max_single_file_bytes:
                raise ExtractionError(
                    f"Entry {entry.filename!r} uncompressed size "
                    f"({entry.file_size:,} bytes) exceeds limit "
                    f"({self._limits.max_single_file_bytes:,} bytes)",
                    context="archive-limits",
                )

        total = sum(e.file_size for e in entries)
        if total > self._limits.max_total_size_bytes:
            raise ExtractionError(
                f"Total uncompressed size ({total:,} bytes) exceeds limit "
                f"({self._limits.max_total_size_bytes:,} bytes)",
                context="archive-limits",
            )

        return entries

    def read_entry(self, entry_name: str) -> bytes:
        """Read a single entry from the archive.

        Args:
            entry_name: ZIP entry path (e.g. ``AndroidManifest.xml``).

        Returns:
            bytes: Raw entry contents.

        Raises:
            ExtractionError: If the entry does not exist, is too large, or
                the path is unsafe.
        """
        self._validate_entry_path(entry_name)

        try:
            with zipfile.ZipFile(self._path, "r") as zf:
                info = zf.getinfo(entry_name)

                if info.file_size > self._limits.max_single_file_bytes:
                    raise ExtractionError(
                        f"Entry {entry_name!r} uncompressed size "
                        f"({info.file_size:,} bytes) exceeds limit",
                        context="archive-limits",
                    )

                return zf.read(entry_name)
        except KeyError:
            raise ExtractionError(
                f"Entry {entry_name!r} not found in archive",
                context="archive-read",
            ) from None
        except (zipfile.BadZipFile, OSError) as exc:
            raise ExtractionError(
                f"Cannot read entry {entry_name!r}: {exc}",
                context="archive-read",
            ) from exc

    def extract_to(self, dest: Path, *, entry_names: list[str] | None = None) -> list[Path]:
        """Extract entries to *dest*, enforcing all security limits.

        Args:
            dest: Destination directory (must exist).
            entry_names: Specific entries to extract.  ``None`` = all entries.

        Returns:
            list[Path]: Paths to the extracted files.

        Raises:
            ExtractionError: On limit violation or unsafe paths.
        """
        dest = dest.resolve()
        extracted: list[Path] = []
        total_bytes = 0

        try:
            with zipfile.ZipFile(self._path, "r") as zf:
                entries = [zf.getinfo(n) for n in entry_names] if entry_names else zf.infolist()

                if len(entries) > self._limits.max_file_count:
                    raise ExtractionError(
                        f"Too many entries to extract: {len(entries)} "
                        f"> {self._limits.max_file_count}",
                        context="archive-extract",
                    )

                for info in entries:
                    self._validate_entry_path(info.filename)

                    if info.is_dir():
                        continue

                    if info.file_size > self._limits.max_single_file_bytes:
                        raise ExtractionError(
                            f"Entry {info.filename!r} too large: {info.file_size:,} bytes",
                            context="archive-limits",
                        )

                    total_bytes += info.file_size
                    if total_bytes > self._limits.max_total_size_bytes:
                        raise ExtractionError(
                            f"Total extraction size ({total_bytes:,} bytes) "
                            f"exceeds limit ({self._limits.max_total_size_bytes:,})",
                            context="archive-limits",
                        )

                    # Construct safe output path
                    out_path = (dest / info.filename).resolve()
                    if not str(out_path).startswith(str(dest)):
                        raise ExtractionError(
                            f"Path traversal in extraction: {info.filename!r}",
                            context="archive-security",
                        )

                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, out_path.open("wb") as dst:
                        while chunk := src.read(128 * 1024):
                            dst.write(chunk)

                    extracted.append(out_path)

        except KeyError as exc:
            raise ExtractionError(
                f"Entry not found: {exc}",
                context="archive-extract",
            ) from exc
        except (zipfile.BadZipFile, OSError) as exc:
            raise ExtractionError(
                f"Extraction failed: {exc}",
                context="archive-extract",
            ) from exc

        _log.debug(
            "Extracted %d entries (%d bytes) from %s",
            len(extracted),
            total_bytes,
            self._path.name,
        )
        return extracted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_entry_path(name: str) -> None:
        """Reject paths that could escape the extraction directory."""
        p = PurePosixPath(name)

        # Reject absolute paths
        if p.is_absolute():
            raise ExtractionError(
                f"Absolute path in archive: {name!r}",
                context="archive-security",
            )

        # Reject path traversal
        if ".." in p.parts:
            raise ExtractionError(
                f"Path traversal in archive: {name!r}",
                context="archive-security",
            )

        # Reject Windows drive letters
        if len(name) >= 2 and name[1] == ":":
            raise ExtractionError(
                f"Windows drive path in archive: {name!r}",
                context="archive-security",
            )
