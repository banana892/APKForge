import sys, json
from pathlib import Path
try:
    from loguru import logger; logger.remove()
except Exception: pass
import logging; logging.disable(logging.CRITICAL)
from apkforge.intake.certificates import extract_certificates
N = int(sys.argv[1])
APK = Path('tests/corpus/com.oF2pks.applicationsinfo_19.apk')
fails = 0
for i in range(N):
    certs, warns = extract_certificates(APK)
    if warns or not certs:
        fails += 1
        print(f'  iter {i}: FAIL certs={len(certs)} warns={warns}')
print(json.dumps({"in_process_iterations": N, "failures": fails}))
