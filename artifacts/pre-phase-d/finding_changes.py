#!/usr/bin/env python3
"""Per-finding table of security changes caused by the intent-filter fix (§16).

Inputs (all pre-existing evidence, read-only):
    artifacts/intent-filter-fix/{before,after}/raw_{openlink,pcapdroid,appmanager}_security.json
    artifacts/intent-filter-fix/{before,after}/other_apps.json
    artifacts/intent-filter-fix/after/manifest_*.json
    artifacts/intent-filter-fix/precision.json            (hand-review verdicts of new findings)
    artifacts/security-validation/findings_review.json    (Phase B hand review)

Outputs: finding_changes.json, finding_changes.md (next to this script).

Status vocabulary (evidence is kept apart from interpretation):
    supported_by_evidence  hand-reviewed; the rule's factual claim was checked and holds.
                           This is NOT a claim of malicious behaviour.
    observed_unreviewed    produced by the rule on corrected manifest data, not hand-reviewed.
    existing_reviewed      finding existed before; only confidence/evidence changed and its
                           Phase B review verdict is carried over.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = ROOT / "artifacts" / "intent-filter-fix"

REVIEWED = {
    "openlink": "de.audioattack.openlink_28",
    "pcapdroid": "com.emanuelef.remote_capture_95",
    "appmanager": "io.github.muntashirakon.AppManager_451",
}
BOOT_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
}
LOCATION_PERMS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _findings(side: str) -> dict[str, dict[str, dict]]:
    """apk stem -> finding id -> {severity, confidence, evidence}."""
    out: dict[str, dict[str, dict]] = {}
    for short, stem in REVIEWED.items():
        raw = _load(FIX / side / f"raw_{short}_security.json")
        out[stem] = {f["id"]: f for f in raw["findings"]}
    for apk, data in _load(FIX / side / "other_apps.json")["apks"].items():
        stem = apk.removesuffix(".apk")
        out.setdefault(stem, data["findings"])
    return out


def _manifest(stem: str) -> dict:
    # NewPipe's manifest capture drops the commit suffix of the corpus file name.
    candidates = [FIX / "after" / f"manifest_{stem}.json"] + sorted(
        (FIX / "after").glob(f"manifest_{stem.rsplit('_', 1)[0]}*.json")
    )
    for c in candidates:
        if c.is_file():
            return _load(c)["manifest"]
    raise FileNotFoundError(stem)


def _boot_receivers(manifest: dict) -> list[dict]:
    rows = []
    for r in manifest.get("receivers", []):
        filters = [
            {"actions": sorted(f.get("actions", [])), "categories": sorted(f.get("categories", []))}
            for f in r.get("intent_filters", [])
            if BOOT_ACTIONS & set(f.get("actions", []))
        ]
        if filters:
            rows.append(
                {
                    "component": r["name"],
                    "exported": r.get("exported"),
                    "enabled": r.get("enabled"),
                    "intent_filters": filters,
                }
            )
    return sorted(rows, key=lambda x: x["component"])


def _review_verdicts() -> dict[tuple[str, str], str]:
    """(app short name, rule id) -> Phase B hand-review verdict."""
    review = _load(ROOT / "artifacts" / "security-validation" / "findings_review.json")
    return {
        (app, f["rule_id"]): f["verdict"]
        for app, data in review["apps"].items()
        for f in data["findings"]
    }


def main() -> None:
    before, after = _findings("before"), _findings("after")
    new_verdicts = _load(FIX / "precision.json")["new_verdicts"]
    phase_b = _review_verdicts()
    short_of = {v: k for k, v in REVIEWED.items()}
    rows = []
    for stem in sorted(after):
        b, a = before.get(stem, {}), after[stem]
        manifest = _manifest(stem)
        perms = {p["name"] for p in manifest.get("permissions", [])}
        boot = _boot_receivers(manifest)
        reviewed_app = stem in short_of
        for fid in sorted(set(a) | set(b)):
            fb, fa = b.get(fid), a.get(fid)
            if fb and fa and (fb["severity"], fb["confidence"]) == (fa["severity"], fa["confidence"]):
                continue  # unchanged id/severity/confidence (evidence order is run-to-run noise)
            change = "added" if fa and not fb else "removed" if fb and not fa else "changed"
            cur = fa or fb
            if change == "added":
                key = f"{short_of.get(stem)}:{fid}"
                if reviewed_app and key in new_verdicts:
                    status = "supported_by_evidence"
                    review = f"hand-reviewed after the fix: {new_verdicts[key]}"
                else:
                    status = "observed_unreviewed"
                    review = "not reviewed (outside the three hand-reviewed apps)"
            else:
                status = "existing_reviewed" if reviewed_app else "observed_unreviewed"
                pb = phase_b.get((short_of.get(stem, ""), fid))
                review = (
                    f"Phase B review verdict retained: {pb}"
                    if pb
                    else ("Phase B reviewed app; verdict retained" if reviewed_app else "not reviewed")
                )
            rows.append(
                {
                    "apk": stem,
                    "finding": fid,
                    "change": change,
                    "severity": [fb and fb["severity"], fa and fa["severity"]],
                    "confidence": [fb and fb["confidence"], fa and fa["confidence"]],
                    "boot_receivers": boot,
                    "permissions": sorted(
                        p
                        for p in perms
                        if p == "android.permission.RECEIVE_BOOT_COMPLETED"
                        or (fid == "SEC-COMB-PERSISTENT-LOC" and p in LOCATION_PERMS)
                    ),
                    "rule_evidence": [
                        f"{e['location']}: {e['description']}" for e in cur.get("evidence", [])
                    ],
                    "status": status,
                    "review": review,
                }
            )
    (HERE / "finding_changes.json").write_text(json.dumps(rows, indent=2) + "\n")

    md = [
        "# Security findings changed by the intent-filter fix",
        "",
        "Generated by `finding_changes.py` from the preserved evidence in",
        "`artifacts/intent-filter-fix/` (before = pre-fix inspector at 7415f67, after = fixed",
        "inspector). Findings whose id, severity and confidence are unchanged are omitted;",
        "evidence-order differences are run-to-run noise (known-limitations §15).",
        "",
        "Status: `supported_by_evidence` = hand-reviewed, the rule's factual claim holds (a",
        "boot receiver exists and starts a service). It is **not** a finding of malicious",
        "behaviour. `observed_unreviewed` = emitted on corrected data, not hand-reviewed.",
        "`existing_reviewed` = the finding existed before; only confidence/evidence changed.",
        "Confidence `confirmed` on `SEC-MAL-PERSISTENCE-BOOT` means the boot receiver is now",
        "observed in the manifest, not that persistence is malicious.",
        "",
        "| APK | finding | change | severity | confidence | boot receiver(s) (filter actions) | permission(s) | status | review |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        recv = "<br>".join(
            f"`{x['component']}` ({', '.join(a.rsplit('.', 1)[-1] for f in x['intent_filters'] for a in f['actions'])})"
            for x in r["boot_receivers"]
        ) or "—"
        sev = " → ".join(str(x) for x in r["severity"]) if r["severity"][0] != r["severity"][1] else r["severity"][1]
        conf = " → ".join(str(x) for x in r["confidence"])
        perms = ", ".join(p.rsplit(".", 1)[-1] for p in r["permissions"]) or "—"
        md.append(
            f"| {r['apk']} | `{r['finding']}` | {r['change']} | {sev} | {conf} | {recv} | {perms} | {r['status']} | {r['review']} |"
        )
    md += [
        "",
        "Observation, not interpretation: in AntennaPod, Fennec and NewPipe the only receiver",
        "with a boot action is androidx WorkManager's `RescheduleReceiver` (library code), and",
        "Fennec's HIGH `SEC-COMB-PERSISTENT-LOC` rests on that receiver plus location",
        "permissions. None of the `observed_unreviewed` rows has been checked by hand.",
        "",
        f"Total changed findings: {len(rows)} "
        f"(added {sum(r['change'] == 'added' for r in rows)}, "
        f"changed {sum(r['change'] == 'changed' for r in rows)}, "
        f"removed {sum(r['change'] == 'removed' for r in rows)}).",
        "Rule evidence strings per finding are in `finding_changes.json` (`rule_evidence`).",
        "",
    ]
    (HERE / "finding_changes.md").write_text("\n".join(md))


if __name__ == "__main__":
    main()
