"""Regenerate the three-app security findings at the CURRENT working tree.

Writes raw findings JSON per app so the TP matrix can be verified against
code as it stands now (rules.py / crypto.py were edited after the previous
post-PRC artifacts were written).
"""
import json, sys, datetime, hashlib
from pathlib import Path
try:
    from loguru import logger; logger.remove()
except Exception:
    pass
import logging; logging.disable(logging.CRITICAL)

from apkforge.inspection.engine import InspectionEngine
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.engine import SecurityEngine

APKS = {
    "openlink": "tests/corpus/de.audioattack.openlink_28.apk",
    "pcapdroid": "tests/corpus/com.emanuelef.remote_capture_95.apk",
    "appmanager": "tests/corpus/io.github.muntashirakon.AppManager_451.apk",
}
OUT = Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)

def dump(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj

for app, rel in APKS.items():
    p = Path(rel)
    insp = InspectionEngine().inspect(p)
    priv = PrivacyEngine().analyze(insp, keep_workspace=False)
    sec = SecurityEngine().analyze(target=insp, privacy=priv, apk_path=p, keep_workspace=False)
    d = dump(sec)
    d["_regen_meta"] = {
        "generated_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "apk": rel,
        "apk_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        "source_state": "working_tree",
    }
    (OUT / f"raw_{app}_security.json").write_text(json.dumps(d, indent=2))
    ids = [f["id"] for f in d["findings"]]
    print(f"{app}: {len(ids)} findings")
    for i in sorted(ids):
        print(f"   {i}")
