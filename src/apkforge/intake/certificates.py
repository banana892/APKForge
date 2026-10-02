"""APK signing certificate extraction.

Extracts X.509 certificates from APK signing information.

APK signing schemes supported:
- **v1 (JAR signing)**: Certificates in META-INF/*.RSA, *.DSA, *.EC files
  (PKCS#7 / CMS structures).
- **v2/v3**: Not yet implemented (the signature block is embedded in the APK
  between ZIP entries and the central directory).  This is a Phase 1 limitation.

Uses the ``cryptography`` library for PKCS#7/CMS parsing.

A valid signature establishes signing identity — it does NOT establish that
the application is safe.
"""

from __future__ import annotations

import hashlib
import zipfile
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.intake import SigningCertificate

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["extract_certificates", "extract_certificates_from_zip"]

_log = get_logger(__name__)

# META-INF file extensions that contain PKCS#7 certificate data
_CERT_EXTENSIONS = (".rsa", ".dsa", ".ec")


def extract_certificates(apk_path: Path) -> tuple[list[SigningCertificate], list[str]]:
    """Extract signing certificates from an APK file.

    Tries Androguard first (handles v1/v2/v3), falls back to raw PKCS#7
    parsing of META-INF/*.RSA/*.DSA/*.EC files.

    A primary-backend failure that the fallback fully recovers from is not a
    warning: when the fallback yields only complete certificates and reports
    no problems of its own, the Androguard message is attached to each
    certificate as an informational ``extraction_note`` and no warning is
    returned, so intake status is unaffected.  Any other combination keeps the
    previous behaviour (all messages returned as warnings).

    Args:
        apk_path: Path to the APK file.

    Returns:
        A tuple of (certificates, warnings).
    """
    warnings: list[str] = []

    # Strategy 1: Try Androguard (handles all signing versions)
    certs, ag_warnings = _extract_via_androguard(apk_path)
    if certs:
        return certs, ag_warnings

    # Strategy 2: Fall back to raw PKCS#7 parsing of META-INF entries
    certs, pkcs_warnings = extract_certificates_from_zip(apk_path)

    if ag_warnings and certs and not pkcs_warnings and all(map(_is_complete, certs)):
        notes = [
            f"Primary certificate backend failed and was recovered by the PKCS#7 fallback: {w}"
            for w in ag_warnings
        ]
        _log.info("Certificate extraction recovered via PKCS#7 fallback: %s", ag_warnings)
        return [
            c.model_copy(update={"extraction_notes": [*c.extraction_notes, *notes]}) for c in certs
        ], []

    warnings.extend(ag_warnings)
    warnings.extend(pkcs_warnings)

    if not certs:
        warnings.append("No signing certificates could be extracted.")

    return certs, warnings


def _is_complete(cert: SigningCertificate) -> bool:
    """Whether a certificate record carries full identity information."""
    return all(
        (
            cert.subject,
            cert.issuer,
            cert.serial_number,
            cert.not_before,
            cert.not_after,
            cert.sha256_fingerprint,
            cert.sha1_fingerprint,
        )
    )


def _extract_via_androguard(
    apk_path: Path,
) -> tuple[list[SigningCertificate], list[str]]:
    """Try to extract certificates using Androguard."""
    warnings: list[str] = []

    try:
        from androguard.core.apk import APK
    except ImportError:
        return [], ["Androguard not available for certificate extraction."]

    try:
        apk = APK(str(apk_path))
        raw_certs = apk.get_certificates()
    except Exception as exc:
        _log.debug("Androguard certificate extraction failed: %s", exc)
        return [], [f"Androguard certificate extraction failed: {exc}"]

    certs: list[SigningCertificate] = []
    for cert in raw_certs:
        try:
            der_bytes = cert.dump()
            sha256_fp = hashlib.sha256(der_bytes).hexdigest()
            sha1_fp = hashlib.sha1(der_bytes).hexdigest()  # noqa: S324
        except Exception:
            sha256_fp = None
            sha1_fp = None

        try:
            subject_str = cert.subject.rfc4514_string() if cert.subject else None
            issuer_str = cert.issuer.rfc4514_string() if cert.issuer else None
            serial = format(cert.serial_number, "x") if cert.serial_number else None
            # `cryptography>=42.0.0` is a hard dependency (see pyproject.toml),
            # so the timezone-aware accessors are always present.
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except Exception as exc:
            _log.debug("Error reading certificate fields: %s", exc)
            subject_str = issuer_str = serial = None
            not_before = not_after = None

        certs.append(
            SigningCertificate(
                subject=subject_str,
                issuer=issuer_str,
                serial_number=serial,
                not_before=not_before,
                not_after=not_after,
                sha256_fingerprint=sha256_fp,
                sha1_fingerprint=sha1_fp,
                extraction_backend="androguard",
            )
        )

    return certs, warnings


def extract_certificates_from_zip(
    apk_path: Path,
) -> tuple[list[SigningCertificate], list[str]]:
    """Extract certificates from META-INF/*.RSA/*.DSA/*.EC using cryptography.

    This is the fallback path when Androguard is not available.
    """
    warnings: list[str] = []
    certs: list[SigningCertificate] = []

    try:
        from cryptography.hazmat.primitives.serialization import (
            pkcs7 as pkcs7_mod,
        )
    except ImportError:
        return [], ["cryptography library not available for certificate extraction."]

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            cert_entries = [
                n
                for n in zf.namelist()
                if n.startswith("META-INF/") and n.lower().endswith(_CERT_EXTENSIONS)
            ]

            for entry_name in cert_entries:
                try:
                    raw = zf.read(entry_name)
                    x509_certs = pkcs7_mod.load_der_pkcs7_certificates(raw)

                    for cert in x509_certs:
                        der_bytes = cert.public_bytes(
                            encoding=__import__(
                                "cryptography.hazmat.primitives.serialization",
                                fromlist=["Encoding"],
                            ).Encoding.DER
                        )

                        certs.append(
                            SigningCertificate(
                                subject=cert.subject.rfc4514_string(),
                                issuer=cert.issuer.rfc4514_string(),
                                serial_number=format(cert.serial_number, "x"),
                                not_before=cert.not_valid_before_utc
                                if hasattr(cert, "not_valid_before_utc")
                                else None,
                                not_after=cert.not_valid_after_utc
                                if hasattr(cert, "not_valid_after_utc")
                                else None,
                                sha256_fingerprint=hashlib.sha256(der_bytes).hexdigest(),
                                sha1_fingerprint=hashlib.sha1(der_bytes).hexdigest(),  # noqa: S324
                                signature_version="v1",
                                extraction_backend="pkcs7_fallback",
                            )
                        )
                except Exception as exc:
                    _log.debug("Failed to parse certificate from %s: %s", entry_name, exc)
                    warnings.append(f"Could not parse certificate from {entry_name}: {exc}")

    except (zipfile.BadZipFile, OSError) as exc:
        warnings.append(f"Could not read archive for certificates: {exc}")

    return certs, warnings
