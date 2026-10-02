"""Independent check of the post-fix intent-filter data against ``aapt2 dump xmltree``.

aapt2 decodes the binary manifest with its own parser (no Androguard, no APKForge). For
every activity / service / receiver directly under <application>, the per-filter actions,
categories and number of <data> elements are compared with ``after/manifest_<id>.json``.

Usage: source tools/env.sh; .venv-validation/bin/python \
    artifacts/intent-filter-fix/verify_with_aapt2.py   (writes aapt2_verification.json)
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CORPUS = ROOT / "tests" / "corpus"
KINDS = {"activity": "activities", "service": "services", "receiver": "receivers"}
NAME = re.compile(r'android:name\(0x01010003\)="([^"]*)"')
ELEM = re.compile(r"^(\s*)E: (\S+)")


def parse(apk: Path) -> dict[str, list[dict[str, object]]]:
    out = subprocess.run(
        ["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    package = next(re.search(r'package="([^"]+)"', ln).group(1) for ln in out if "package=" in ln)  # type: ignore[union-attr]
    comps: dict[str, list[dict[str, object]]] = {}
    stack: list[tuple[int, str, dict[str, object]]] = []  # (indent, tag, node)
    for ln in out:
        m = ELEM.match(ln)
        if m:
            indent, tag = len(m.group(1)), m.group(2)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else None
            node: dict[str, object] = {"tag": tag}
            if tag in KINDS and parent == "application":
                node["filters"] = []
            elif tag == "intent-filter" and stack and stack[-1][1] in KINDS:
                node.update(actions=[], categories=[], data=0)
                stack[-1][2]["filters"].append(node)  # type: ignore[union-attr]
            elif tag in ("action", "category", "data") and parent == "intent-filter":
                f = stack[-1][2]
                if tag == "data" and "data" in f:
                    f["data"] = int(f["data"]) + 1  # type: ignore[call-overload]
                elif "actions" in f:  # skip filters of non-component parents (activity-alias)
                    node["_into"] = f
            stack.append((indent, tag, node))
            continue
        nm = NAME.search(ln)
        if nm and stack:
            node = stack[-1][2]
            tag = stack[-1][1]
            if tag in KINDS and "filters" in node and "name" not in node:
                name = nm.group(1)
                if name.startswith("."):
                    name = package + name
                elif "." not in name:
                    name = f"{package}.{name}"
                node["name"] = name
                comps.setdefault(f"{KINDS[tag]}:{name}", []).append(node)
            elif tag in ("action", "category") and "_into" in node:
                key = "actions" if tag == "action" else "categories"
                node["_into"][key].append(nm.group(1))  # type: ignore[index]
    return {k: [{**f} for f in v[0]["filters"]] for k, v in comps.items()}  # type: ignore[index]


def main() -> None:
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    report: dict[str, object] = {"tool": "aapt2 dump xmltree (build-tools 35.0.0)", "apks": {}}
    all_ok = True
    for entry in manifest["entries"]:
        ref = parse(CORPUS / entry["filename"])
        rec = json.loads(
            (HERE / "after" / f"manifest_{entry['id'].replace('@', '_')}.json").read_text()
        )["manifest"]
        mismatches = []
        n_ref = n_got = 0
        for kind in KINDS.values():
            for c in rec[kind]:
                key = f"{kind}:{c['name']}"
                got = [
                    {"actions": f["actions"], "categories": f["categories"], "data": len(f["data"])}
                    for f in c["intent_filters"]
                ]
                want = [
                    {"actions": f["actions"], "categories": f["categories"], "data": f["data"]}
                    for f in ref.get(key, [])
                ]
                n_ref += len(want)
                n_got += len(got)
                if key not in ref:
                    mismatches.append({"component": key, "problem": "not found by aapt2"})
                elif got != want:
                    mismatches.append({"component": key, "inspector": got, "aapt2": want})
        ok = not mismatches and n_ref == sum(len(v) for v in ref.values())
        all_ok &= ok
        report["apks"][entry["id"]] = {  # type: ignore[index]
            "aapt2_filters_total": sum(len(v) for v in ref.values()),
            "inspector_filters_total": n_got,
            "aapt2_components": len(ref),
            "match": ok,
            "mismatches": mismatches,
        }
        print(entry["id"], "match" if ok else "MISMATCH", n_got, sum(len(v) for v in ref.values()))
    report["all_match"] = all_ok
    (HERE / "aapt2_verification.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
