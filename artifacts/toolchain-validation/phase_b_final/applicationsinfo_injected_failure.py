"""Applications Info through the full corpus-runner pipeline, with the observed
Androguard SHA-1 backend failure injected. Run in the recreated validation env."""
import json, sys
from dataclasses import asdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
import corpus_runner as cr  # noqa: E402
from apkforge.intake import certificates as certs_mod  # noqa: E402

MSG = "Androguard certificate extraction failed: sha1 is not supported by this backend for RSA signing."
APK = ROOT / "tests/corpus/com.oF2pks.applicationsinfo_19.apk"
calls = {"androguard_failures_injected": 0}

def fail(_p):
    calls["androguard_failures_injected"] += 1
    return [], [MSG]

certs_mod._extract_via_androguard = fail
result = cr.run_single_apk(APK)
from apkforge.intake import APKIntakeService  # noqa: E402
pkg = APKIntakeService().process(APK)
out = {
    "apk": str(APK.relative_to(ROOT)),
    "injected_message": MSG,
    **calls,
    "capability_verdicts": {c["capability"]: c["verdict"] for c in result["capabilities"]},
    "intake_data_summary": next(c["data_summary"] for c in result["capabilities"] if c["capability"] == "intake"),
    "intake_status_direct": str(pkg.status),
    "intake_warnings_direct": pkg.warnings,
    "certificates_direct": [c.model_dump(mode="json") for c in pkg.certificates],
    "environment": cr.environment_identity(),
}
print(json.dumps(out, indent=2))
