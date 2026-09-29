"""Tests for APK certificate extraction."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkforge.intake.certificates import (
    extract_certificates,
    extract_certificates_from_zip,
)
from tests.fixtures import create_synthetic_apk, generate_test_pkcs7_cert


def test_extract_certificates_with_cert(tmp_path: Path) -> None:
    apk_path = tmp_path / "signed.apk"
    create_synthetic_apk(apk_path, include_cert=True)

    certs, _ = extract_certificates(apk_path)
    assert len(certs) >= 1
    cert = certs[0]
    assert cert.subject is not None
    assert "APKForge" in cert.subject
    assert cert.sha256_fingerprint is not None
    assert len(cert.sha256_fingerprint) == 64
    assert cert.sha1_fingerprint is not None
    assert len(cert.sha1_fingerprint) == 40


def test_extract_certificates_from_zip_direct(tmp_path: Path) -> None:
    apk_path = tmp_path / "raw_signed.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest />")
        zf.writestr("META-INF/CERT.RSA", generate_test_pkcs7_cert(common_name="Direct Test"))

    certs, _ = extract_certificates_from_zip(apk_path)
    assert len(certs) >= 1
    assert "Direct Test" in (certs[0].subject or "")
    assert certs[0].signature_version == "v1"


def test_extract_certificates_unsigned(tmp_path: Path) -> None:
    apk_path = tmp_path / "unsigned.apk"
    create_synthetic_apk(apk_path, include_cert=False)

    certs, warnings = extract_certificates(apk_path)
    assert certs == []
    assert any("No signing certificates" in w for w in warnings)
