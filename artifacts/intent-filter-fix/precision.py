"""Post-fix false-positive rate for the three reviewed apps.

Same method as artifacts/security-validation/prc_validation/findings_review_post_prc.md
(FP rate = FP / total findings): every finding in after/raw_<app>_security.json gets the
hand-review verdict recorded for (app, rule id) in artifacts/security-validation/
findings_review.json; findings new in this fix get the classification in NEW_VERDICTS
(evidence: comparison.json, aapt2_verification.json, boot_receiver_xrefs.json).
The same computation over before/ must reproduce the published 11.9%.
Writes precision.json.
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REVIEW = json.loads((ROOT / "artifacts/security-validation/findings_review.json").read_text())
APPS = ("openlink", "pcapdroid", "appmanager")
NEW_VERDICTS = {
    ("pcapdroid", "SEC-MAL-BOOT-001"): "TRUE_POSITIVE",
    ("appmanager", "SEC-MAL-BOOT-001"): "TRUE_POSITIVE",
}


def tally(state: str) -> dict:
    out: dict = {"apps": {}, "unreviewed": []}
    tot = {"findings": 0, "TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "UNCLEAR": 0}
    for app in APPS:
        verdicts = {f["rule_id"]: f["verdict"] for f in REVIEW["apps"][app]["findings"]}
        ids = [f["id"] for f in json.loads((HERE / state / f"raw_{app}_security.json").read_text())["findings"]]
        row = {"findings": len(ids), "TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "UNCLEAR": 0, "new": []}
        for i in ids:
            v = verdicts.get(i) or NEW_VERDICTS.get((app, i))
            if i not in verdicts:
                row["new"].append({"id": i, "verdict": v})
            if v is None:
                out["unreviewed"].append([app, i])
                continue
            row[v] += 1
        row["fp_rate"] = round(100 * row["FALSE_POSITIVE"] / row["findings"], 1)
        out["apps"][app] = row
        for k in tot:
            tot[k] += row[k]
    tot["fp_rate"] = round(100 * tot["FALSE_POSITIVE"] / tot["findings"], 1)
    out["total"] = tot
    return out


result = {"before": tally("before"), "after": tally("after"), "new_verdicts": {f"{a}:{i}": v for (a, i), v in NEW_VERDICTS.items()}}
(HERE / "precision.json").write_text(json.dumps(result, indent=2))
for s in ("before", "after"):
    print(s, result[s]["total"], {a: (r["findings"], r["FALSE_POSITIVE"], r["fp_rate"]) for a, r in result[s]["apps"].items()}, "unreviewed", result[s]["unreviewed"])
