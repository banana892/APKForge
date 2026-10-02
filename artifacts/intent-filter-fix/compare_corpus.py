"""Capability corpus (tests/corpus_runner.py): before vs after the intent-filter fix.

Compares every (APK, capability) verdict and every non-timing field, with lists compared
order-insensitively (component / permission / evidence order comes from Androguard sets
and is not stable run to run). Writes corpus_comparison.json.
"""

import collections
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
VOLATILE = {"duration_seconds"}


def caps(d):
    return {(a["filename"], c["capability"]): c for a in d["per_apk_results"] for c in a["capabilities"]}


def canon(x):
    if isinstance(x, dict):
        return {k: canon(v) for k, v in x.items() if k not in VOLATILE}
    if isinstance(x, list):
        return sorted((canon(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
    return x


def leaf_diffs(a, b, p=""):
    if isinstance(a, dict) and isinstance(b, dict):
        return [d for k in sorted(a.keys() | b.keys()) for d in leaf_diffs(a.get(k), b.get(k), f"{p}/{k}")]
    return [] if a == b else [{"path": p, "before": a, "after": b}]


b = json.loads((HERE / "before/corpus_results.json").read_text())
a = json.loads((HERE / "after/corpus_results.json").read_text())
cb, ca = caps(b), caps(a)
out = {
    "verdicts_before": dict(collections.Counter(v["verdict"] for v in cb.values())),
    "verdicts_after": dict(collections.Counter(v["verdict"] for v in ca.values())),
    "verdict_differences": [
        {"apk": k[0], "capability": k[1], "before": cb.get(k, {}).get("verdict"), "after": ca.get(k, {}).get("verdict")}
        for k in sorted(cb.keys() | ca.keys())
        if cb.get(k, {}).get("verdict") != ca.get(k, {}).get("verdict")
    ],
    "field_differences": [
        {"apk": k[0], "capability": k[1], **d}
        for k in sorted(cb.keys() & ca.keys())
        for d in leaf_diffs(canon(cb[k]), canon(ca[k]))
    ],
    "diff_pair_differences": [
        {"before": x, "after": y}
        for x, y in zip(canon(b["diff_results"]), canon(a["diff_results"]), strict=True)
        if x != y
    ],
}
(HERE / "corpus_comparison.json").write_text(json.dumps(out, indent=2))
print("verdicts", out["verdicts_before"], "->", out["verdicts_after"])
print("verdict differences", out["verdict_differences"])
for d in out["field_differences"]:
    print(" ", d["apk"], d["capability"], d["path"], str(d["before"])[:120], "->", str(d["after"])[:120])
print("diff pair differences", len(out["diff_pair_differences"]))
for d in out["diff_pair_differences"]:
    print("  ", json.dumps(leaf_diffs(d["before"], d["after"]))[:600])
