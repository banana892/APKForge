"""Trace the non-reviewed corpus changes seen in corpus_comparison.json.

For AntennaPod, Conversations, Fennec and NewPipe: security finding ids/severity/
confidence/evidence and the network inspector's domains, for the tree on PYTHONPATH.
Usage: PYTHONHASHSEED=0 PYTHONPATH=<tree>/src python capture_other.py <tree> <out.json>
"""

import json
import logging
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)
from loguru import logger  # noqa: E402

logger.remove()
import apkforge  # noqa: E402
from apkforge.inspection.engine import InspectionEngine  # noqa: E402
from apkforge.privacy.engine import PrivacyEngine  # noqa: E402
from apkforge.security.engine import SecurityEngine  # noqa: E402

tree = Path(sys.argv[1]).resolve()
assert str(tree / "src") in str(Path(apkforge.__file__).resolve())
APKS = ["de.danoeh.antennapod_3120295.apk", "eu.siacs.conversations_4218104.apk",
        "org.mozilla.fennec_fdroid_1560020.apk", "org.schabi.newpipe_1015_cb84069.apk"]
out = {"apkforge_module": str(Path(apkforge.__file__).resolve()), "apks": {}}
for name in APKS:
    apk = tree / "tests" / "corpus" / name
    insp = InspectionEngine().inspect(apk, keep_workspace=False)
    priv = PrivacyEngine().analyze(insp, keep_workspace=False)
    sec = SecurityEngine().analyze(target=insp, privacy=priv, apk_path=apk, keep_workspace=False)
    net = insp.network.model_dump(mode="json") if insp.network else {}
    out["apks"][name] = {
        "findings": {f.id: {"severity": str(f.severity), "confidence": str(f.confidence), "title": f.title,
                            "evidence": [e.model_dump(mode="json") for e in f.evidence]} for f in sec.findings},
        "domains": sorted({str(d.get("domain") if isinstance(d, dict) else d) for d in net.get("domains", [])}),
        "privacy_endpoints": sorted({f"{e.endpoint} [{e.category}] provenance={e.provenance}" for e in priv.endpoints.classified_endpoints}),
    }
    print(name, len(sec.findings), len(out["apks"][name]["domains"]), len(out["apks"][name]["privacy_endpoints"]))
Path(sys.argv[2]).write_text(json.dumps(out, indent=2))
