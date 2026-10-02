"""Before/after comparison for the intent-filter extraction fix.

Reads before/, after/ and their rerun_noise_check/ subdirectories (written by capture.py)
and writes comparison.json:

- manifest: per APK, intent-filter totals per component kind, every component whose
  filter count changed, inspector status / intent-filter warnings, and whether anything
  other than intent_filters changed (component order is ignored; it is not stable run to run).
- security: per reviewed app, findings added / removed, and for retained findings any
  change of severity, confidence or other non-evidence field, plus evidence added/removed
  (compared as sets: ordering and sampling vary run to run, known-limitations §15).
- noise: the same security comparison between two runs of the same code (before vs
  before rerun, after vs after rerun), so run-to-run variation is not attributed to the fix.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
KINDS = ("activities", "services", "receivers")
APPS = ("openlink", "pcapdroid", "appmanager")


def load(p: Path) -> dict:
    return json.loads(p.read_text())


def by_name(m: dict, kind: str) -> dict[str, dict]:
    return {c["name"]: c for c in m[kind]}


def manifest_diff(before: dict, after: dict) -> dict:
    mb, ma = before["manifest"], after["manifest"]
    out: dict = {
        "inspector_status": [before["inspector_status"], after["inspector_status"]],
        "intent_filter_warnings": [
            [w for w in before["warnings"] if "intent-filter" in w],
            [w for w in after["warnings"] if "intent-filter" in w],
        ],
        "totals": {},
        "changed_components": [],
    }
    for kind in KINDS:
        cb, ca = by_name(mb, kind), by_name(ma, kind)
        out["totals"][kind] = {
            "components": [len(cb), len(ca)],
            "filters": [
                sum(len(c["intent_filters"]) for c in cb.values()),
                sum(len(c["intent_filters"]) for c in ca.values()),
            ],
        }
        for name in sorted(cb.keys() | ca.keys()):
            nb = len(cb[name]["intent_filters"]) if name in cb else None
            na = len(ca[name]["intent_filters"]) if name in ca else None
            if nb != na:
                out["changed_components"].append(
                    {"component": f"{kind}:{name}", "filters": [nb, na]}
                )

    # Everything except intent_filters must be identical (order-insensitive per kind).
    def strip(m: dict) -> dict:
        d = {k: v for k, v in m.items() if k not in KINDS}
        # Component and permission order come from Androguard sets and vary run to run.
        for kind in ("permissions", "declared_permissions"):
            d[kind] = sorted(json.dumps(p, sort_keys=True) for p in m[kind])
        for kind in (*KINDS, "providers"):
            d[kind] = sorted(
                (json.dumps({k: v for k, v in c.items() if k != "intent_filters"}, sort_keys=True)
                 for c in m[kind]),
            )
        return d

    out["non_filter_fields_identical"] = strip(mb) == strip(ma)
    return out


def ev_key(e: dict) -> str:
    return json.dumps(e, sort_keys=True)


IDENTITY_SKIP = {"evidence"}


def security_diff(before: dict, after: dict) -> dict:
    fb = {f["id"]: f for f in before["findings"]}
    fa = {f["id"]: f for f in after["findings"]}
    out: dict = {
        "count": [len(fb), len(fa)],
        "summary": [before["summary"], after["summary"]],
        "added": [fa[i] for i in sorted(fa.keys() - fb.keys())],
        "removed": [fb[i] for i in sorted(fb.keys() - fa.keys())],
        "changed": [],
    }
    for i in sorted(fa.keys() & fb.keys()):
        a, b = fa[i], fb[i]
        fields = {
            k: [b.get(k), a.get(k)]
            for k in (a.keys() | b.keys()) - IDENTITY_SKIP
            if a.get(k) != b.get(k)
        }
        eb, ea = {ev_key(e) for e in b["evidence"]}, {ev_key(e) for e in a["evidence"]}
        if fields or eb != ea:
            out["changed"].append(
                {
                    "id": i,
                    "fields": fields,
                    "evidence_count": [len(b["evidence"]), len(a["evidence"])],
                    "evidence_added": [json.loads(e) for e in sorted(ea - eb)],
                    "evidence_removed": [json.loads(e) for e in sorted(eb - ea)],
                }
            )
    return out


def main() -> None:
    before, after = HERE / "before", HERE / "after"
    result: dict = {
        "meta": {
            "before": load(before / "filter_counts.json")["_meta"],
            "after": load(after / "filter_counts.json")["_meta"],
        },
        "manifest": {},
        "security": {},
        "noise": {},
    }
    for f in sorted(before.glob("manifest_*.json")):
        result["manifest"][load(f)["_meta"]["id"]] = manifest_diff(load(f), load(after / f.name))
    for app in APPS:
        name = f"raw_{app}_security.json"
        result["security"][app] = security_diff(load(before / name), load(after / name))
        result["noise"][app] = {
            label: {
                k: v
                for k, v in security_diff(
                    load(d / name), load(d / "rerun_noise_check" / name)
                ).items()
                if k in ("count", "added", "removed", "changed")
            }
            for label, d in (("before_vs_before_rerun", before), ("after_vs_after_rerun", after))
        }
    (HERE / "comparison.json").write_text(json.dumps(result, indent=2))

    for apk, d in result["manifest"].items():
        t = d["totals"]
        print(
            f"{apk:42} status {d['inspector_status']} "
            + " ".join(f"{k[:3]} {t[k]['filters'][0]}->{t[k]['filters'][1]}" for k in KINDS)
            + f" changed={len(d['changed_components'])} other_fields_same={d['non_filter_fields_identical']}"
        )
    for app, d in result["security"].items():
        print(
            app, d["count"], "added", [f["id"] for f in d["added"]],
            "removed", [f["id"] for f in d["removed"]],
            "changed", [(c["id"], list(c["fields"]), c["evidence_count"]) for c in d["changed"]],
        )
    for app, d in result["noise"].items():
        for label, n in d.items():
            print(" noise", app, label, n["count"], len(n["added"]), len(n["removed"]),
                  [(c["id"], list(c["fields"])) for c in n["changed"]])


if __name__ == "__main__":
    main()
