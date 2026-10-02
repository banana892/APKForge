"""Evidence for classifying SEC-MAL-BOOT-001: what each app's boot receiver calls.

Androguard cross-references (methods called from each BootReceiver), plus the receiver's
intent-filter actions from aapt2. Output: boot_receiver_xrefs.json.
"""

import json
import logging
import subprocess
from pathlib import Path

logging.disable(logging.CRITICAL)
from loguru import logger  # noqa: E402

logger.remove()
from androguard.misc import AnalyzeAPK  # noqa: E402

HERE = Path(__file__).resolve().parent
TARGETS = {
    "pcapdroid": ("tests/corpus/com.emanuelef.remote_capture_95.apk", "com.emanuelef.remote_capture.BootReceiver"),
    "appmanager": ("tests/corpus/io.github.muntashirakon.AppManager_451.apk", "io.github.muntashirakon.AppManager.self.BootReceiver"),
    "openlink": ("tests/corpus/de.audioattack.openlink_28.apk", "de.audioattack.openlink.conf.PackageChangeBroadcastReceiver"),
}
out = {}
for app, (apk, cls) in TARGETS.items():
    _, _, dx = AnalyzeAPK(apk)
    c = dx.get_class_analysis("L" + cls.replace(".", "/") + ";")
    xml = subprocess.run(["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", apk],
                         capture_output=True, text=True, check=True).stdout
    out[app] = {
        "receiver": cls,
        "aapt2_manifest_mentions_receiver": cls in xml,
        "calls": {
            str(m.name): sorted({f"{t.class_name}->{t.name}" for _, t, _ in m.get_xref_to()})
            for m in c.get_methods()
        } if c else None,
    }
(HERE / "boot_receiver_xrefs.json").write_text(json.dumps(out, indent=2))
print(json.dumps(out, indent=1))
