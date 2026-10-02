"""Independently verify where the SHA-1 / SHA1 / MD5 strings in AppManager come from."""
import json, collections
from pathlib import Path
try:
    from loguru import logger; logger.remove()
except Exception: pass
import logging; logging.disable(logging.CRITICAL)
from apkforge.inspection.engine import InspectionEngine

p = Path('tests/corpus/io.github.muntashirakon.AppManager_451.apk')
insp = InspectionEngine().inspect(p)
pkg = 'io.github.muntashirakon.AppManager'

prov = collections.defaultdict(list)
for s in insp.dex.strings:
    if s.value in ('SHA-1','SHA1','MD5','DES','DESede','RC4','ARCFOUR','Blowfish'):
        prov[s.value].append((s.class_name, s.method_name, s.dex_file))

out = {}
for val, refs in sorted(prov.items()):
    named = [r for r in refs if r[0]]
    app = sorted({r[0] for r in named if r[0].startswith(pkg)})
    bc  = sorted({r[0] for r in named if r[0].startswith(('org.bouncycastle.','org.spongycastle.'))})
    other = sorted({r[0] for r in named if not r[0].startswith(pkg)
                    and not r[0].startswith(('org.bouncycastle.','org.spongycastle.'))})
    unattributed = [r for r in refs if not r[0]]
    out[val] = {
        "total_refs": len(refs),
        "app_owned_classes": app,
        "bouncycastle_classes_count": len(bc),
        "bouncycastle_classes_sample": bc[:5],
        "other_third_party_classes": other[:10],
        "other_third_party_count": len(other),
        "refs_without_class_attribution": len(unattributed),
        "app_owned_methods": sorted({f"{r[0]}.{r[1]}" for r in named if r[0].startswith(pkg)}),
    }
print(json.dumps(out, indent=2))
