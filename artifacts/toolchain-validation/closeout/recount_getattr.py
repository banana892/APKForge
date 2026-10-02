#!/usr/bin/env python3
"""Recount getattr() occurrences under src/ at the committed baseline vs the working tree.

Reproduces the `totals` and `per_file_counts` blocks of getattr_audit.json.

Usage:  python artifacts/toolchain-validation/closeout/recount_getattr.py [baseline_ref]
"""

from __future__ import annotations

import json
import subprocess
import sys

BASELINE = sys.argv[1] if len(sys.argv) > 1 else "212227f"


def tracked_py_files(ref: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "src/"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    return [f for f in out if f.endswith(".py")]


def at_ref(ref: str, path: str) -> str | None:
    r = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def main() -> None:
    rows = []
    for path in tracked_py_files(BASELINE):
        baseline_src = at_ref(BASELINE, path)
        before = baseline_src.count("getattr(") if baseline_src else 0
        try:
            after = open(path).read().count("getattr(")
        except FileNotFoundError:
            after = 0
        if before or after:
            rows.append({
                "file": path,
                f"occurrences_at_{BASELINE}": before,
                "occurrences_now": after,
                "eliminated": before - after,
            })
    rows.sort(key=lambda r: -r["eliminated"])
    before_total = sum(r[f"occurrences_at_{BASELINE}"] for r in rows)
    after_total = sum(r["occurrences_now"] for r in rows)
    print(json.dumps({
        "baseline_ref": BASELINE,
        f"occurrences_at_{BASELINE}": before_total,
        "occurrences_now": after_total,
        "occurrences_eliminated": before_total - after_total,
        "files_with_getattr_at_baseline": sum(1 for r in rows if r[f"occurrences_at_{BASELINE}"]),
        "files_with_getattr_now": sum(1 for r in rows if r["occurrences_now"]),
        "per_file": rows,
    }, indent=2))


if __name__ == "__main__":
    main()
