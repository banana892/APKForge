"""Tests for safe archive handling and decompression limit enforcement."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from apkforge.core.config import ExtractionLimits
from apkforge.core.exceptions import ExtractionError
from apkforge.intake.archive import SafeZipExtractor, is_zip_file, validate_zip


def test_is_zip_file(tmp_path: Path) -> None:
    non_zip = tmp_path / "test.txt"
    non_zip.write_text("not a zip")
    assert not is_zip_file(non_zip)

    valid_zip = tmp_path / "valid.zip"
    with zipfile.ZipFile(valid_zip, "w") as zf:
        zf.writestr("test.txt", "hello")
    assert is_zip_file(valid_zip)


def test_validate_zip_valid(tmp_path: Path) -> None:
    valid_zip = tmp_path / "valid.zip"
    with zipfile.ZipFile(valid_zip, "w") as zf:
        zf.writestr("test.txt", "hello")
    warnings = validate_zip(valid_zip)
    assert warnings == []


def test_validate_zip_non_file(tmp_path: Path) -> None:
    with pytest.raises(ExtractionError, match="Not a file"):
        validate_zip(tmp_path)


def test_validate_zip_corrupt(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.apk"
    corrupt.write_bytes(b"PK\x03\x04corrupted_zip_payload")
    with pytest.raises(ExtractionError):
        validate_zip(corrupt)


def test_safe_zip_extractor_read_entry(tmp_path: Path) -> None:
    arc = tmp_path / "test.apk"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("hello.txt", b"world")
    limits = ExtractionLimits()
    extractor = SafeZipExtractor(arc, limits)
    assert extractor.read_entry("hello.txt") == b"world"


def test_safe_zip_extractor_missing_entry(tmp_path: Path) -> None:
    arc = tmp_path / "test.apk"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("hello.txt", b"world")
    limits = ExtractionLimits()
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="not found"):
        extractor.read_entry("nonexistent.txt")


def test_safe_zip_path_traversal_rejection(tmp_path: Path) -> None:
    arc = tmp_path / "traversal.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("../escaped.txt", b"evil")
    limits = ExtractionLimits()
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="Path traversal"):
        extractor.list_entries()


def test_safe_zip_absolute_path_rejection(tmp_path: Path) -> None:
    arc = tmp_path / "absolute.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("/etc/passwd", b"root:x:0:0")
    limits = ExtractionLimits()
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="Absolute path"):
        extractor.list_entries()


def test_safe_zip_file_count_limit(tmp_path: Path) -> None:
    arc = tmp_path / "many_files.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        for i in range(10):
            zf.writestr(f"file_{i}.txt", b"content")
    limits = ExtractionLimits(max_file_count=5)
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="exceeding limit of 5"):
        extractor.list_entries()


def test_safe_zip_single_file_size_limit(tmp_path: Path) -> None:
    arc = tmp_path / "large_file.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("huge.bin", b"0" * 2000)
    limits = ExtractionLimits(max_single_file_bytes=1000, max_total_size_bytes=5000)
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="exceeds limit"):
        extractor.list_entries()


def test_safe_zip_default_limits_accommodate_large_native_lib(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    arc = tmp_path / "mock_large.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("lib/arm64-v8a/libxul.so", b"dummy")

    # Mock infolist to simulate a 160MB uncompressed entry
    real_zipfile = zipfile.ZipFile
    class MockZipFile(real_zipfile):
        def infolist(self):
            entries = super().infolist()
            for e in entries:
                if e.filename == "lib/arm64-v8a/libxul.so":
                    e.file_size = 160 * 1024 * 1024
            return entries

    monkeypatch.setattr(zipfile, "ZipFile", MockZipFile)

    # Default limits (256 MiB single / 1024 MiB total) should pass without error
    extractor = SafeZipExtractor(arc, ExtractionLimits())
    entries = extractor.list_entries()
    assert len(entries) == 1
    assert entries[0].file_size == 160 * 1024 * 1024

    # Restrictive limits (128 MiB) should reject it
    old_limits = ExtractionLimits(max_single_file_bytes=128 * 1024 * 1024, max_total_size_bytes=512 * 1024 * 1024)
    extractor_restrictive = SafeZipExtractor(arc, old_limits)
    with pytest.raises(ExtractionError, match="exceeds limit"):
        extractor_restrictive.list_entries()



def test_safe_zip_total_size_limit(tmp_path: Path) -> None:
    arc = tmp_path / "large_total.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        for i in range(5):
            zf.writestr(f"file_{i}.bin", b"0" * 400)
    limits = ExtractionLimits(max_single_file_bytes=500, max_total_size_bytes=1000)
    extractor = SafeZipExtractor(arc, limits)
    with pytest.raises(ExtractionError, match="Total uncompressed size"):
        extractor.list_entries()


def test_safe_zip_extract_to(tmp_path: Path) -> None:
    arc = tmp_path / "archive.zip"
    dest = tmp_path / "extracted"
    dest.mkdir()
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("sub/hello.txt", b"hello world")
        zf.writestr("root.txt", b"root content")
    limits = ExtractionLimits()
    extractor = SafeZipExtractor(arc, limits)
    extracted = extractor.extract_to(dest)
    assert len(extracted) == 2
    assert (dest / "sub" / "hello.txt").read_bytes() == b"hello world"
    assert (dest / "root.txt").read_bytes() == b"root content"
