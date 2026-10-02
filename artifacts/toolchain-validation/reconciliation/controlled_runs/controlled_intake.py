"""Controlled Applications Info intake probe.

Runs APKIntakeService + raw androguard cert extraction against the same APK,
reporting status, warnings, cert details and the exact exception if cert
extraction fails.  The apkforge source tree used is taken from sys.argv[1].
"""
import json, os, sys, traceback, hashlib, platform, subprocess, datetime

SRC = sys.argv[1]
TAG = sys.argv[2]
APK = sys.argv[3]
sys.path.insert(0, SRC)

import apkforge
assert apkforge.__file__.startswith(SRC), f"wrong apkforge: {apkforge.__file__}"

try:
    from loguru import logger; logger.remove()
except Exception:
    pass
import logging; logging.disable(logging.CRITICAL)

out = {
    "tag": TAG,
    "timestamp_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "src_tree": SRC,
    "apkforge_module": apkforge.__file__,
    "apk": APK,
    "apk_sha256": hashlib.sha256(open(APK, "rb").read()).hexdigest(),
    "python": sys.version,
    "python_executable": sys.executable,
}

# --- environment / dependency capture ---
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as _b
out["cryptography_version"] = cryptography.__version__
out["openssl_version_text"] = _b.openssl_version_text()
try:
    import androguard; out["androguard_version"] = getattr(androguard, "__version__", "?")
except Exception as e:
    out["androguard_version"] = f"<err {e}>"
try:
    import asn1crypto; out["asn1crypto_version"] = asn1crypto.__version__
except Exception as e:
    out["asn1crypto_version"] = f"<err {e}>"
try:
    import OpenSSL; out["pyopenssl_version"] = OpenSSL.__version__
except ImportError:
    out["pyopenssl_version"] = None
out["env_openssl_vars"] = {
    k: v for k, v in os.environ.items()
    if "OPENSSL" in k.upper() or "CRYPTO" in k.upper() or k.upper().startswith("SSL")
}
out["fips_enabled_proc"] = (
    open("/proc/sys/crypto/fips_enabled").read().strip()
    if os.path.exists("/proc/sys/crypto/fips_enabled") else None
)

# --- does this backend support SHA-1 RSA at all? ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
try:
    _sig = _k.sign(b"probe", padding.PKCS1v15(), hashes.SHA1())
    out["sha1_rsa_sign"] = "OK"
except Exception as e:
    _sig = None
    out["sha1_rsa_sign"] = f"{type(e).__name__}: {e}"
try:
    _k.public_key().verify(_sig or b"\x00" * 256, b"probe", padding.PKCS1v15(), hashes.SHA1())
    out["sha1_rsa_verify"] = "OK"
except Exception as e:
    out["sha1_rsa_verify"] = f"{type(e).__name__}: {e}"

# --- raw androguard certificate extraction, with full exception detail ---
from androguard.core.apk import APK as AgAPK
ag = {}
try:
    _apk = AgAPK(APK)
    ag["min_sdk_version"] = _apk.get_min_sdk_version()
    ag["signature_names"] = list(_apk.get_signature_names())
    ag["is_signed_v1"] = _apk.is_signed_v1()
    ag["is_signed_v2"] = _apk.is_signed_v2()
    ag["is_signed_v3"] = _apk.is_signed_v3()
    # signature algorithm actually used by the v1 signer
    import asn1crypto.cms as cms
    si = cms.ContentInfo.load(_apk.get_file(ag["signature_names"][0]))["content"]["signer_infos"][0]
    ag["digest_algorithm"] = si["digest_algorithm"]["algorithm"].native
    ag["signature_algorithm"] = si["signature_algorithm"]["algorithm"].native
    ag["has_signed_attrs"] = si["signed_attrs"].native is not None
    certs = _apk.get_certificates()
    ag["get_certificates"] = "OK"
    ag["cert_count"] = len(certs)
    ag["cert_sha256"] = [hashlib.sha256(c.dump()).hexdigest() for c in certs]
except Exception as e:
    ag["get_certificates"] = f"RAISED {type(e).__name__}: {e}"
    ag["traceback"] = traceback.format_exc()
out["androguard_raw"] = ag

# --- apkforge certificate extraction layer ---
from pathlib import Path
from apkforge.intake.certificates import extract_certificates
try:
    certs, warns = extract_certificates(Path(APK))
    out["extract_certificates"] = {
        "cert_count": len(certs),
        "warnings": warns,
        "sha1_fingerprints": [c.sha1_fingerprint for c in certs],
        "sha256_fingerprints": [c.sha256_fingerprint for c in certs],
    }
except Exception as e:
    out["extract_certificates"] = {"RAISED": f"{type(e).__name__}: {e}",
                                   "traceback": traceback.format_exc()}

# --- full intake service (what the corpus runner's `intake` capability uses) ---
from apkforge.intake import APKIntakeService
try:
    pkg = APKIntakeService().process(Path(APK))
    out["intake"] = {
        "status": str(pkg.status),
        "warnings": list(pkg.warnings or []),
        "errors": list(pkg.errors or []),
        "package_name": pkg.identity.package_name if pkg.identity else None,
        "file_count": len(pkg.files or []),
        "dex_count": len(pkg.dex_files or []),
        "certificate_count": len(pkg.certificates or []),
    }
    # corpus-runner verdict logic, reproduced
    from apkforge.core.models import AnalysisStatus
    if pkg.status == AnalysisStatus.FAILED:
        v = "FAIL"
    elif pkg.status == AnalysisStatus.PARTIAL:
        v = "PARTIAL"
    elif pkg.identity and pkg.identity.package_name and pkg.hashes and pkg.files:
        v = "PASS"
    else:
        v = "PARTIAL"
    out["intake_capability_verdict"] = v
except Exception as e:
    out["intake"] = {"RAISED": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()}
    out["intake_capability_verdict"] = "FAIL"

print(json.dumps(out, indent=2))
