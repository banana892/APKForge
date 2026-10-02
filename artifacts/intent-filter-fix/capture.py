"""Capture manifest inspection (9 corpus APKs) and raw security findings (3 reviewed apps).

Usage (run with the source tree to measure on PYTHONPATH):

    PYTHONHASHSEED=0 PYTHONPATH=<tree>/src .venv-validation/bin/python \
        artifacts/intent-filter-fix/capture.py <tree> <out_dir>

Writes per APK ``manifest_<id>.json`` (full ManifestInspection, inspector status and
warnings), ``filter_counts.json`` (per-component intent-filter counts for all APKs) and,
for OpenLink / PCAPdroid / AppManager, ``raw_<app>_security.json`` in the same format as
``artifacts/security-validation/prc_validation``.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path

try:
    from loguru import logger

    logger.remove()
except Exception:
    pass
logging.disable(logging.CRITICAL)

import apkforge  # noqa: E402
from apkforge.inspection.engine import InspectionEngine  # noqa: E402
from apkforge.privacy.engine import PrivacyEngine  # noqa: E402
from apkforge.security.engine import SecurityEngine  # noqa: E402

REVIEWED = {
    "de.audioattack.openlink@28": "openlink",
    "com.emanuelef.remote_capture@95": "pcapdroid",
    "io.github.muntashirakon.AppManager@451": "appmanager",
}

tree = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
corpus = tree / "tests" / "corpus"
manifest = json.loads((corpus / "manifest.json").read_text())
revision = subprocess.run(
    ["git", "-C", str(tree), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
).stdout.strip()
dirty = subprocess.run(
    ["git", "-C", str(tree), "status", "--porcelain", "--", "src"],
    capture_output=True,
    text=True,
    check=True,
).stdout.strip()
meta = {
    "generated_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "apkforge_module": str(Path(apkforge.__file__).resolve()),
    "git_head": revision,
    "src_dirty": dirty.splitlines(),
}
assert str(tree / "src") in meta["apkforge_module"], meta

counts: dict[str, object] = {"_meta": meta, "apks": {}}
for entry in manifest["entries"]:
    apk = corpus / entry["filename"]
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert sha == entry["sha256"], entry["id"]
    insp = InspectionEngine().inspect(apk, keep_workspace=False)
    m = insp.manifest
    assert m is not None, entry["id"]
    record = {
        "_meta": {**meta, "id": entry["id"], "apk_sha256": sha},
        "inspector_status": insp.inspector_statuses.get("manifest"),
        "overall_status": str(insp.status),
        "warnings": insp.warnings,
        "manifest": m.model_dump(mode="json"),
    }
    (out / f"manifest_{entry['id'].replace('@', '_')}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True)
    )
    per_component = {}
    for kind in ("activities", "services", "receivers"):
        for c in getattr(m, kind):
            per_component[f"{kind}:{c.name}"] = len(c.intent_filters)
    counts["apks"][entry["id"]] = {  # type: ignore[index]
        "inspector_status": record["inspector_status"],
        "intent_filter_warnings": [w for w in insp.warnings if "intent-filter" in w],
        "totals": {
            kind: {
                "components": len(getattr(m, kind)),
                "with_filters": sum(1 for c in getattr(m, kind) if c.intent_filters),
                "filters": sum(len(c.intent_filters) for c in getattr(m, kind)),
            }
            for kind in ("activities", "services", "receivers")
        },
        "per_component": per_component,
    }
    print(entry["id"], counts["apks"][entry["id"]]["totals"])  # type: ignore[index]

    app = REVIEWED.get(entry["id"])
    if app:
        priv = PrivacyEngine().analyze(insp, keep_workspace=False)
        sec = SecurityEngine().analyze(target=insp, privacy=priv, apk_path=apk, keep_workspace=False)
        d = sec.model_dump(mode="json")
        d["_regen_meta"] = {**meta, "apk": str(apk.relative_to(tree)), "apk_sha256": sha}
        (out / f"raw_{app}_security.json").write_text(json.dumps(d, indent=2))
        print(f"  {app}: {len(d['findings'])} findings")

(out / "filter_counts.json").write_text(json.dumps(counts, indent=2, sort_keys=True))
