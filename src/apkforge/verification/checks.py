"""Individual verification checks (Phase E6).

- :func:`structural_check`: archive and container validity, performed locally in
  Python (no toolchain): readable ZIP, CRCs, no duplicate entry names, a decodable
  binary manifest, DEX and resource-table headers.
- :func:`signature_check`: interprets a BuildService ``verify`` result (``apksigner
  verify``, ``zipalign -c``, expected signer). Without a toolchain the check is
  ``undetermined`` — a signature is never assumed valid.
"""

from __future__ import annotations

import contextlib
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.diff.archive import ArchiveInventory, EntryKind
from apkforge.verification.models import CheckStatus, VerificationCheck

if TYPE_CHECKING:
    from apkforge.builders.models import BuildVerificationResult

__all__ = ["signature_check", "signature_check_with_service", "structural_check"]

_DEX_MAGIC = b"dex\n"
_ARSC_TYPE = b"\x02\x00"  # RES_TABLE_TYPE


def structural_check(apk: Path) -> VerificationCheck:
    """Container validity of *apk*. FAILED on any structural defect."""
    apk = Path(apk)
    problems: list[str] = []
    evidence: list[str] = []
    details: dict[str, Any] = {}
    if not apk.is_file():
        return VerificationCheck(
            name="structural", status=CheckStatus.FAILED, summary=f"not a file: {apk.name}"
        )
    if not zipfile.is_zipfile(apk):
        return VerificationCheck(
            name="structural", status=CheckStatus.FAILED, summary="not a ZIP archive"
        )
    try:
        inv = ArchiveInventory.from_apk(apk)
        with zipfile.ZipFile(apk) as z:
            bad = z.testzip()
            if bad:
                problems.append(f"CRC mismatch in entry {bad}")
            heads = {
                name: z.read(name)[:8]
                for name, e in inv.entries.items()
                if e.kind in (EntryKind.DEX, EntryKind.RESOURCE_TABLE)
            }
            manifest_raw = (
                z.read("AndroidManifest.xml") if "AndroidManifest.xml" in inv.entries else None
            )
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError) as exc:
        return VerificationCheck(
            name="structural",
            status=CheckStatus.FAILED,
            summary=f"archive unreadable: {type(exc).__name__}: {exc}",
        )
    details["inventory"] = inv.summary()
    problems += [f"duplicate entry name: {n}" for n in inv.duplicate_names]
    problems += [f"unreadable entry: {n}" for n in inv.unreadable]
    for name, head in heads.items():
        kind = inv.entries[name].kind
        if kind == EntryKind.DEX and not head.startswith(_DEX_MAGIC):
            problems.append(f"{name}: not a DEX file (bad magic)")
        if kind == EntryKind.RESOURCE_TABLE and not head.startswith(_ARSC_TYPE):
            problems.append(f"{name}: not a resource table (bad chunk type)")
    if manifest_raw is None:
        problems.append("AndroidManifest.xml missing")
    else:
        try:
            from androguard.core.axml import AXMLPrinter

            with contextlib.suppress(ImportError):
                from loguru import logger

                logger.disable("androguard")
            printer = AXMLPrinter(manifest_raw)
            if not printer.get_xml() or not printer.is_valid():
                problems.append("AndroidManifest.xml is not decodable binary XML")
            else:
                evidence.append("AndroidManifest.xml decodes as binary XML")
        except Exception as exc:
            problems.append(f"AndroidManifest.xml decode error: {type(exc).__name__}: {exc}")
    dex = details["inventory"]["dex_files"]
    evidence.append(f"{inv.entry_count} entries; DEX files: {', '.join(dex) or 'none'}")
    if not dex:
        evidence.append("no classesN.dex (valid only for android:hasCode=false packages)")
    unusual = details["inventory"]["unusual_paths"]
    if unusual:
        evidence.append(f"unusual entry paths (recorded, not rejected): {unusual[:10]}")
    return VerificationCheck(
        name="structural",
        status=CheckStatus.FAILED if problems else CheckStatus.PASSED,
        summary="; ".join(problems) if problems else "archive and container structure valid",
        evidence=evidence + problems,
        details=details,
    )


def signature_check(
    ver: BuildVerificationResult | dict[str, Any] | None, *, reason: str = ""
) -> VerificationCheck:
    """Interpret a BuildService verify result."""
    if ver is None:
        return VerificationCheck(
            name="signature",
            status=CheckStatus.UNDETERMINED,
            summary=reason or "signature was not verified (no apksigner result)",
        )
    d = ver if isinstance(ver, dict) else ver.to_dict()
    cert = d.get("certificate") or {}
    evidence = [
        f"apksigner verify: {'verifies' if d.get('signature_verified') else 'does NOT verify'}",
        f"zipalign -c: {'aligned' if d.get('zipalign_verified') else 'NOT aligned'}",
        f"ZIP integrity: {'ok' if d.get('zip_integrity_verified') else 'FAILED'}",
    ]
    schemes = [s for s in ("v1", "v2", "v3") if cert.get(f"{s}_scheme")]
    if cert:
        evidence.append(
            f"signer(s): {cert.get('signer_count')}, sha256 {cert.get('sha256_digest')}, "
            f"schemes {schemes or 'none'}"
        )
    expected = d.get("expected_certificate_sha256")
    matched = d.get("expected_signer_matched")
    if expected:
        evidence.append(f"expected signer {expected}: {'matched' if matched else 'NOT matched'}")
    ok = bool(
        d.get("signature_verified")
        and d.get("zipalign_verified")
        and d.get("zip_integrity_verified")
        and matched is not False
    )
    summary = "signature verifies" + (" with the expected signer" if matched else "")
    if not ok:
        summary = "; ".join(d.get("errors") or []) or "signature verification failed"
    return VerificationCheck(
        name="signature",
        status=CheckStatus.PASSED if ok else CheckStatus.FAILED,
        summary=summary,
        evidence=evidence,
        details={k: v for k, v in d.items() if k != "apksigner_output"},
    )


def signature_check_with_service(
    service: Any,  # noqa: ANN401 - BuildService or a test double
    apk: Path,
    expected_signer: str | None = None,
) -> VerificationCheck:
    """Run ``BuildService.verify`` on *apk*; ``undetermined`` without a toolchain."""
    if service is None:
        return signature_check(None, reason="no build toolchain available to run apksigner")
    try:
        check = service.check_toolchain()
        if not getattr(check, "valid", False):
            return signature_check(
                None, reason="toolchain invalid: " + "; ".join(getattr(check, "errors", []))
            )
        sr = service.verify(apk, expected_certificate_sha256=expected_signer)
    except Exception as exc:
        reason = _redact(f"verify could not run: {type(exc).__name__}: {exc}", apk)
        return signature_check(None, reason=reason)
    result = signature_check(sr.verification, reason=_redact(sr.failure_cause or "", apk))
    result.summary = _redact(result.summary, apk)
    result.details.pop("errors", None)
    if sr.verification is not None:
        result.details["errors"] = [_redact(e, apk) for e in sr.verification.errors]
    return result


def _redact(text: str, apk: Path) -> str:
    """Reports identify APKs by file name; never embed the local absolute path."""
    for form in {str(apk), str(Path(apk).resolve())}:
        text = text.replace(form, Path(apk).name)
    return text
