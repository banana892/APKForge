"""Streaming cryptographic hash computation.

All hashing uses chunked I/O so that large APK files are never loaded
entirely into memory.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from apkforge.intake import FileHashes

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["compute_bytes_hashes", "compute_file_hashes"]

_CHUNK_SIZE = 128 * 1024  # 128 KiB


def compute_file_hashes(path: Path) -> FileHashes:
    """Compute MD5, SHA-1, and SHA-256 of *path* using streaming I/O.

    Args:
        path: Path to the file on disk.

    Returns:
        FileHashes: Lowercase hex digests.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: On I/O errors.
    """
    md5 = hashlib.md5()  # noqa: S324 — MD5 used for identification, not security
    sha1 = hashlib.sha1()  # noqa: S324
    sha256 = hashlib.sha256()

    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )


def compute_bytes_hashes(data: bytes) -> FileHashes:
    """Compute MD5, SHA-1, and SHA-256 of an in-memory byte buffer.

    Prefer :func:`compute_file_hashes` for files on disk.

    Args:
        data: Raw bytes.

    Returns:
        FileHashes: Lowercase hex digests.
    """
    return FileHashes(
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324
        sha256=hashlib.sha256(data).hexdigest(),
    )


def compute_sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()
