"""C.5 OpenLink: does the diff now see intent-filter data? (after the fix)

Inputs: after/c5/c5-openlink-result.json (original APK and modified output path).
1. Inspect original and modified APK (manifest inspector) and record every receiver's
   intent filters on both sides, plus aapt2's filter count for the modified APK.
2. DiffEngine.diff(original, modified) on those inspections: list component changes and
   their intent_filter_diff.
3. Positive control: the same ComponentDiffer on a copy of the modified inspection with
   BOOT_COMPLETED removed from the target receiver must report actions_removed.
Writes after/c5/openlink_filter_check.json.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logging.disable(logging.CRITICAL)
try:
    from loguru import logger

    logger.remove()
except Exception:
    pass

from apkforge.diff.components import ComponentDiffer  # noqa: E402
from apkforge.diff.engine import DiffEngine  # noqa: E402
from apkforge.inspection.engine import InspectionEngine  # noqa: E402

HERE = Path(__file__).resolve().parent
res = json.loads((HERE / "after/c5/c5-openlink-result.json").read_text())["result"]
target = res["plan"]["receiver"]
orig, mod = Path(res["apk"]), Path(res["output_apk"])

insp = {k: InspectionEngine().inspect(p, keep_workspace=False) for k, p in (("original", orig), ("modified", mod))}
out: dict = {"target_receiver": target, "apks": {"original": str(orig), "modified": str(mod)}, "receivers": {}}
for side, i in insp.items():
    out["receivers"][side] = {
        r.name: {"enabled": r.enabled, "exported": r.exported,
                 "intent_filters": [f.model_dump(mode="json") for f in r.intent_filters]}
        for r in sorted(i.manifest.receivers, key=lambda r: r.name)
    }
    out.setdefault("inspector_status", {})[side] = i.inspector_statuses.get("manifest")
    out.setdefault("filter_totals", {})[side] = sum(
        len(c.intent_filters) for k in ("activities", "services", "receivers") for c in getattr(i.manifest, k)
    )
xml = subprocess.run(["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", str(mod)],
                     capture_output=True, text=True, check=True).stdout
out["aapt2_intent_filter_elements_modified"] = xml.count("E: intent-filter")

d = DiffEngine().diff(insp["original"], insp["modified"])
out["diff_status"] = str(d.status)
out["component_changes"] = [c.model_dump(mode="json", exclude_defaults=True) for c in d.components.changes] if hasattr(d.components, "changes") else d.components.model_dump(mode="json", exclude_defaults=True)
out["filters_identical_both_sides"] = {
    n: v["intent_filters"] for n, v in out["receivers"]["original"].items()
} == {n: v["intent_filters"] for n, v in out["receivers"]["modified"].items()}

ctrl = insp["modified"].model_copy(deep=True)
for r in ctrl.manifest.receivers:
    if r.name == target:
        for f in r.intent_filters:
            f.actions = [a for a in f.actions if a != "android.intent.action.BOOT_COMPLETED"]
cd = ComponentDiffer().diff(insp["original"], ctrl)
out["positive_control"] = {
    "mutation": f"BOOT_COMPLETED removed from {target} (in memory, modified side)",
    "result": cd.model_dump(mode="json", exclude_defaults=True),
}
(HERE / "after/c5/openlink_filter_check.json").write_text(json.dumps(out, indent=2))
print(json.dumps({k: out[k] for k in ("inspector_status", "filter_totals", "aapt2_intent_filter_elements_modified", "diff_status", "filters_identical_both_sides")}, indent=1))
print(json.dumps(out["component_changes"], indent=1)[:1500])
print(json.dumps(out["positive_control"], indent=1)[:1500])
