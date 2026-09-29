"""Cryptography weaknesses, insecure cipher modes, and hardcoded secret detection."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.security.rules import SecurityEvidenceIndex

_log = logging.getLogger(__name__)

# Patterns for hardcoded credentials with matching regexes
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "CWE-798: Use of Hard-coded Credentials",
    ),
    (
        "Google API Key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "CWE-798: Use of Hard-coded Credentials",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        "CWE-798: Use of Hard-coded Credentials",
    ),
    (
        "Stripe Live API Key",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b"),
        "CWE-798: Use of Hard-coded Credentials",
    ),
    (
        "Generic Private Key Header",
        re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
        "CWE-312: Cleartext Storage of Sensitive Information",
    ),
]


def mask_secret(value: str) -> str:
    """Mask sensitive secret value to prevent credential leakage in reports."""
    val = value.strip()
    if len(val) <= 4:
        return "****"
    if len(val) <= 8:
        return f"{val[:2]}****{val[-2:]}"
    prefix = val[:4]
    suffix = val[-4:]
    masked_len = max(len(val) - 8, 4)
    return f"{prefix}{'*' * masked_len}{suffix}"


class CryptoVulnerabilityAnalyzer:
    """Detects weak cryptographic algorithms, insecure modes, and hardcoded credentials."""

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Inspect strings and APIs for cryptographic weaknesses and leaked secrets."""
        findings: list[SecurityFinding] = []

        # 1. Insecure Electronic Codebook (ECB) Cipher Mode
        ecb_strings = [
            s
            for s in index.strings
            if any(term in s for term in ("AES/ECB/", "DES/ECB/", "Blowfish/ECB/"))
        ]
        if ecb_strings:
            ev = [
                Evidence(
                    description=f"ECB cipher mode string pattern: {s}",
                    location="dex:strings",
                    snippet=s,
                )
                for s in ecb_strings[:3]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-CRYPTO-ECB",
                    category="crypto",
                    title="Insecure Electronic Codebook (ECB) Cipher Mode Detected",
                    description=(
                        "Application references symmetric cipher transformation strings"
                        "utilizing ECB mode"
                        "(e.g. 'AES/ECB/PKCS5Padding')."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    assessment=(
                        "ECB mode encrypts identical plaintext blocks into identical ciphertext"
                        "blocks."
                        "It does not provide semantic security and exposes underlying data"
                        "patterns to attackers."
                    ),
                    limitations=[
                        "Static presence in string table does not confirm this mode is actively"
                        "used for sensitive payloads."
                    ],
                    references=["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
                    tags=["crypto", "ecb", "vulnerability"],
                )
            )

        # 2. Legacy / Broken Symmetric Ciphers (DES / 3DES / RC4)
        broken_ciphers = [
            s for s in index.strings if s in ("DES", "DESede", "RC4", "ARCFOUR", "Blowfish")
        ]
        if broken_ciphers:
            ev = [
                Evidence(
                    description=f"Legacy cipher algorithm referenced: {s}",
                    location="dex:strings",
                    snippet=s,
                )
                for s in broken_ciphers[:3]
            ]
            ciphers_str = ", ".join(broken_ciphers)
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-CRYPTO-WEAK-CIPHER",
                    category="crypto",
                    title="Legacy or Deprecated Cryptographic Cipher Referenced",
                    description=f"Application references legacy cipher algorithms: {ciphers_str}.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=ev,
                    assessment=(
                        "Legacy ciphers like DES and RC4 have known structural weaknesses and"
                        "small key sizes"
                        "vulnerable to modern brute-force and cryptanalytic attacks."
                    ),
                    limitations=[
                        "Legacy ciphers may be present in third-party compatibility libraries"
                        "for backwards compatibility."
                    ],
                    references=["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
                    tags=["crypto", "cipher", "vulnerability"],
                )
            )

        # 3. Weak Hash Algorithms (MD5 / SHA-1)
        weak_hashes = [s for s in index.strings if s in ("MD5", "SHA-1", "SHA1")]
        if weak_hashes:
            ev = [
                Evidence(
                    description=f"Weak hash algorithm referenced: {s}",
                    location="dex:strings",
                    snippet=s,
                )
                for s in weak_hashes[:3]
            ]
            hashes_str = ", ".join(weak_hashes)
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-CRYPTO-WEAK-HASH",
                    category="crypto",
                    title="Legacy Cryptographic Hash Algorithm Referenced (MD5/SHA-1)",
                    description=f"Application references deprecated hash algorithms: {hashes_str}.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence=ev,
                    assessment=(
                        "MD5 and SHA-1 have proven collision attacks. If used for digital "
                        "signatures or password verification, they can be bypassed by "
                        "practical collision generation."
                    ),
                    limitations=[
                        "MD5 and SHA-1 are frequently used for non-cryptographic cache keys "
                        "or file integrity checksums."
                    ],
                    references=["CWE-328: Use of Weak Hash"],
                    tags=["crypto", "hash", "vulnerability"],
                )
            )

        # 4. Hardcoded Secret Keys & API Tokens (Masked for safety)
        discovered_secrets: list[tuple[str, str, str]] = []
        for s in index.strings:
            for name, pattern, ref in SECRET_PATTERNS:
                m = pattern.search(s)
                if m:
                    raw_val = m.group(1)
                    masked = mask_secret(raw_val)
                    discovered_secrets.append((name, masked, ref))

        if discovered_secrets:
            # Group by secret type
            by_type: dict[str, list[tuple[str, str]]] = {}
            for name, masked, ref in discovered_secrets:
                by_type.setdefault(name, []).append((masked, ref))

            for name, items in by_type.items():
                ev = [
                    Evidence(
                        description=f"Potential hardcoded {name} observed (masked): {masked}",
                        location="dex:strings",
                        snippet=f"{name}: {masked}",
                    )
                    for masked, _ in items[:3]
                ]
                ref = items[0][1]
                findings.append(
                    SecurityFinding(
                        id=f"SEC-VULN-SECRET-{name.upper().replace(' ', '_')}",
                        category="credential_access",
                        title=f"Potential Hardcoded Secret Detected: {name}",
                        description=(
                            f"Discovered pattern matching {name} embedded in application strings. "
                            f"Values are masked in reporting to prevent credential exposure."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=ev,
                        assessment=(
                            f"Hardcoded {name} credentials bundled in the APK binary can be "
                            f"extracted by any user or attacker through static decompression "
                            f"and reverse engineering."
                        ),
                        limitations=[
                            "Static regular expressions may match public client IDs, sample keys, "
                            "or documentation strings."
                        ],
                        references=[ref],
                        tags=["secret", "credential", "hardcoded"],
                    )
                )

        return sorted(findings, key=lambda f: f.id)
