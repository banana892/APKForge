"""Is security-finding evidence selection dependent on PYTHONHASHSEED?

Runs the PCAPdroid security pipeline and prints a digest of each finding's
evidence list (order-sensitive) plus a digest of the id/severity/confidence set.
"""
import hashlib, json, sys
from pathlib import Path
try:
    from loguru import logger; logger.remove()
except Exception: pass
import logging; logging.disable(logging.CRITICAL)
from apkforge.inspection.engine import InspectionEngine
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.engine import SecurityEngine
p = Path("tests/corpus/com.emanuelef.remote_capture_95.apk")
insp = InspectionEngine().inspect(p)
priv = PrivacyEngine().analyze(insp, keep_workspace=False)
sec = SecurityEngine().analyze(target=insp, privacy=priv, apk_path=p, keep_workspace=False)
fs = [f.model_dump(mode="json") for f in sec.findings]
ident = hashlib.sha256(json.dumps(sorted((f["id"], f["severity"], f["confidence"], len(f["evidence"])) for f in fs)).encode()).hexdigest()[:16]
ev = hashlib.sha256(json.dumps([f["evidence"] for f in fs]).encode()).hexdigest()[:16]
print(json.dumps({"identity_digest": ident, "evidence_digest": ev}))
