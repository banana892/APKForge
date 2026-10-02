"""Compare phase_b_final three-app security findings with the reconciliation baseline,
and re-verify the 35 reviewed true positives individually by app + rule ID."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
RC = ROOT / "artifacts/toolchain-validation/reconciliation/final_security"
NEW = ROOT / "artifacts/toolchain-validation/phase_b_final/final_security"
REVIEW = ROOT / "artifacts/security-validation/findings_review.json"
APPS = ("openlink", "pcapdroid", "appmanager")

def load(d, app):
    data = json.loads((d / f"raw_{app}_security.json").read_text())
    data.pop("_regen_meta", None)
    return data

out = {"apps": {}, "tp_matrix": [], "summary": {}}
total_diff = 0
evidence_only = 0
for app in APPS:
    a, b = load(RC, app), load(NEW, app)
    fa = {f["id"]: f for f in a["findings"]}; fb = {f["id"]: f for f in b["findings"]}
    changed = sorted(i for i in fa.keys() & fb.keys() if fa[i] != fb[i])
    added, removed = sorted(fb.keys() - fa.keys()), sorted(fa.keys() - fb.keys())
    top_level_diff = sorted(k for k in a.keys() | b.keys() if k != "findings" and a.get(k) != b.get(k))
    def ident(f):
        # Everything except the evidence list itself, plus the evidence count.
        # Evidence ordering/sampling varies run-to-run (hashseed_probe_results.txt),
        # so identity is compared field-by-field instead of byte-for-byte.
        return {**{k: v for k, v in f.items() if k != "evidence"}, "evidence_count": len(f["evidence"])}

    identity_changed = sorted(i for i in fa.keys() & fb.keys() if ident(fa[i]) != ident(fb[i]))
    summary_equal = a.get("summary") == b.get("summary")
    other_fields_equal = all(
        a.get(k) == b.get(k)
        for k in a.keys() | b.keys()
        if k not in ("findings", "malware_indicators", "spyware_indicators",
                     "vulnerability_indicators")
    )
    out["apps"][app] = {
        "identity_changed": identity_changed,
        "summary_equal": summary_equal,
        "non_evidence_top_level_fields_equal": other_fields_equal,
        "reconciliation_count": len(fa), "final_count": len(fb),
        "added": added, "removed": removed, "changed_full_record": changed,
        "other_top_level_fields_differing": top_level_diff,
        "byte_identical_findings": a["findings"] == b["findings"],
    }
    total_diff += len(added) + len(removed) + len(identity_changed)
    evidence_only += len(changed) - len(identity_changed)

review = json.loads(REVIEW.read_text())
for app, v in review["apps"].items():
    fb = {f["id"]: f for f in load(NEW, app)["findings"]}
    for f in v["findings"]:
        if f["verdict"] != "TRUE_POSITIVE":
            continue
        cur = fb.get(f["rule_id"])
        out["tp_matrix"].append({
            "app": app, "rule_id": f["rule_id"], "finding_id": f["rule_id"],
            "present": cur is not None,
            "severity_reviewed": f["severity"], "severity_final": cur and cur["severity"],
            "confidence_reviewed": f["confidence"], "confidence_final": cur and cur["confidence"],
        })
tp = out["tp_matrix"]
out["summary"] = {
    "finding_identity_differences_vs_reconciliation": total_diff,
    "findings_differing_only_in_evidence_order_or_sample": evidence_only,
    "tp_expected": len(tp),
    "tp_present": sum(r["present"] for r in tp),
    "tp_severity_or_confidence_changed": sum(
        r["present"] and (r["severity_reviewed"] != r["severity_final"]
                          or r["confidence_reviewed"] != r["confidence_final"]) for r in tp),
    "sec_mal_root_indicators_appmanager_present":
        any(r["app"] == "appmanager" and r["rule_id"] == "SEC-MAL-ROOT-INDICATORS" and r["present"] for r in tp),
}
json.dump(out, sys.stdout, indent=2)
