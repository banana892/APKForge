"""Compare C.5 no-op baseline and OpenLink result, before vs after the fix.

Volatile fields (timestamps, paths, git revision, rebuilt-APK hashes that change with
every signing) are removed; everything else, including every observation and its
classification, is compared. Writes c5_comparison.json.
"""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
VOLATILE = {"generated_at", "generated", "apk", "target_apk", "output_apk", "workspace",
            "git_commit", "git_dirty", "apkforge", "rebuilt_sha256", "output_sha256"}
PATH = re.compile(r"/home/\S+?/(work|tests)/")


def norm(x):
    if isinstance(x, dict):
        return {k: norm(v) for k, v in x.items() if k not in VOLATILE}
    if isinstance(x, list):
        return [norm(v) for v in x]
    if isinstance(x, str):
        return re.sub(r"[0-9]{8}T[0-9]{6}Z-\w+", "<RUN>", PATH.sub(r"<ROOT>/\1/", x))
    return x


def diffs(a, b, p=""):
    if type(a) is not type(b):
        return [(p, a, b)]
    if isinstance(a, dict):
        return [d for k in sorted(a.keys() | b.keys()) for d in diffs(a.get(k), b.get(k), f"{p}/{k}")]
    if isinstance(a, list):
        if len(a) != len(b):
            return [(p + "#len", len(a), len(b))]
        return [d for i, (u, v) in enumerate(zip(a, b)) for d in diffs(u, v, f"{p}[{i}]")]
    return [] if a == b else [(p, a, b)]


out = {}
for name in ("c5-semantic-noop-baseline.json", "c5-openlink-result.json"):
    a = norm(json.loads((HERE / "before/c5" / name).read_text()))
    b = norm(json.loads((HERE / "after/c5" / name).read_text()))
    d = diffs(a, b)
    out[name] = {"identical_after_normalisation": not d, "differences": [list(x) for x in d]}
    print(name, "identical" if not d else f"{len(d)} differences")
    for x in d[:40]:
        print("  ", str(x)[:300])
(HERE / "c5_comparison.json").write_text(json.dumps(out, indent=2, default=str))
