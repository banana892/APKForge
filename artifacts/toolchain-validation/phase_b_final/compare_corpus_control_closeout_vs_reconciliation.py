"""Compare the phase_b_final corpus result with the reconciliation baseline."""
import collections, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/toolchain-validation/closeout/corpus_results_closeout.json"
NEW = ROOT / "artifacts/toolchain-validation/reconciliation/corpus_results_reconciliation.json"
VOLATILE = {"duration_seconds"}  # timing only

def caps(d):
    return {(a["filename"], c["capability"]): c for a in d["per_apk_results"] for c in a["capabilities"]}

b, n = json.loads(BASE.read_text()), json.loads(NEW.read_text())
cb, cn = caps(b), caps(n)
out = {"baseline": str(BASE.relative_to(ROOT)), "final": str(NEW.relative_to(ROOT))}
for tag, c, d in (("baseline", cb, b), ("final", cn, n)):
    out[f"{tag}_verdicts"] = dict(collections.Counter(v["verdict"] for v in c.values()))
    out[f"{tag}_duration_seconds"] = d["meta"]["total_duration_seconds"]
out["verdict_differences"] = [
    {"apk": k[0], "capability": k[1], "baseline": cb.get(k, {}).get("verdict"), "final": cn.get(k, {}).get("verdict")}
    for k in sorted(cb.keys() | cn.keys()) if cb.get(k, {}).get("verdict") != cn.get(k, {}).get("verdict")
]
out["non_timing_field_differences"] = [
    {"apk": k[0], "capability": k[1], "field": f, "baseline": cb[k].get(f), "final": cn[k].get(f)}
    for k in sorted(cb.keys() & cn.keys())
    for f in sorted(cb[k].keys() | cn[k].keys()) if f not in VOLATILE and cb[k].get(f) != cn[k].get(f)
]
out["partials_final"] = sorted(f"{k[0]}:{k[1]}" for k, v in cn.items() if v["verdict"] == "PARTIAL")
out["applicationsinfo_final"] = {k[1]: v["verdict"] for k, v in cn.items() if k[0].startswith("com.oF2pks")}
def canon(x):
    """Order-insensitive canonical form: lists become sorted lists of canonical items."""
    if isinstance(x, dict):
        return {k: canon(v) for k, v in x.items()}
    if isinstance(x, list):
        return sorted((canon(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(x, str) and x.startswith("OK: ") and "[" in x:
        # messages that embed a str(list(set(...))), e.g. "ABIs: ['x86', ...]"
        head, _, rest = x.partition("[")
        items, _, tail = rest.partition("]")
        return head + "[" + ", ".join(sorted(i.strip() for i in items.split(","))) + "]" + tail
    return x


out["non_timing_differences_remaining_after_order_normalisation"] = [
    d for d in out["non_timing_field_differences"] if canon(d["baseline"]) != canon(d["final"])
]
out["non_timing_differences_order_only_count"] = len(out["non_timing_field_differences"]) - len(
    out["non_timing_differences_remaining_after_order_normalisation"]
)
strip = lambda r: {k: v for k, v in r.items() if k not in VOLATILE}
out["diff_pair_differences"] = [
    {"baseline": strip(x), "final": strip(y)} for x, y in zip(b["diff_results"], n["diff_results"], strict=True)
    if strip(x) != strip(y)
]
out["diff_pairs_final"] = [(r.get("apk_a"), r.get("apk_b"), r.get("verdict")) for r in n["diff_results"]]
out["nested_limit_warnings_in_final"] = sorted({
    w for v in cn.values() for w in v.get("data_summary", {}).get("warnings", []) if "extraction limits" in w
})
out["environment_metadata_final"] = n["meta"].get("environment")
out["environment_metadata_baseline_present"] = "environment" in b["meta"]
json.dump(out, sys.stdout, indent=2)
