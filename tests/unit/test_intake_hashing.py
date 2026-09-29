"""Tests for streaming cryptographic hash computation."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apkforge.intake.hashing import (
    compute_bytes_hashes,
    compute_file_hashes,
    compute_sha256,
)


def test_compute_file_hashes(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    content = b"APKForge streaming hash test data" * 1024
    test_file.write_bytes(content)

    expected_md5 = hashlib.md5(content).hexdigest()
    expected_sha1 = hashlib.sha1(content).hexdigest()
    expected_sha256 = hashlib.sha256(content).hexdigest()

    hashes = compute_file_hashes(test_file)
    assert hashes.md5 == expected_md5
    assert hashes.sha1 == expected_sha1
    assert hashes.sha256 == expected_sha256


def test_compute_bytes_hashes() -> None:
    data = b"Hello APKForge"
    hashes = compute_bytes_hashes(data)
    assert hashes.md5 == hashlib.md5(data).hexdigest()
    assert hashes.sha1 == hashlib.sha1(data).hexdigest()
    assert hashes.sha256 == hashlib.sha256(data).hexdigest()


def test_compute_sha256() -> None:
    data = b"DEX payload test"
    assert compute_sha256(data) == hashlib.sha256(data).hexdigest()


def test_compute_file_hashes_nonexistent(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        compute_file_hashes(tmp_path / "missing.apk")
