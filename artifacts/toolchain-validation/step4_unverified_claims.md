# Step 4 — Unverified Claims Register

**Purpose.** To separate verified from unverified measurements in the Phase B record
without altering the historical reports.

**This document does not modify any historical report.** The Step 2/3 report
(`antennapod/result.md`, `openlink/result.md`) and the Step 5 report
(`step5_verifier_robustness.md`) are unchanged. Where a claim attributed to Step 4
could not be substantiated, it is recorded here as UNVERIFIED and the substantiated
measurement is given alongside it — the original claim is **not** overwritten with a
replacement claim.

**Status of the three claims: all three are UNVERIFIED.** No persistent artifact in
this repository, in any commit in its history, supports any of them.

---

## Search methodology

All searches were run at the Phase B close-out against the full working tree and the
complete commit history (3 commits: `e5ece2d`, `66e589c`, `212227f`).

| # | search | command |
|---|---|---|
| 1 | working tree, all text artifacts | `grep -rn "10,958\|10958" . --include="*.md" --include="*.json" --include="*.py" --include="*.txt"` |
| 2 | every blob in every commit | `git grep -n "10958\|10,958" $(git rev-list --all)` |
| 3 | narrative branch-widening claims | `grep -rn "goto/16\|goto-16\|branch widen\|widening" --include="*.md" .` |
| 4 | every recorded AntennaPod class count | `grep -rn "12065\|12,065" --include="*.md" --include="*.json" .` |

---

## Claim 1 — "21 AntennaPod classes changed"

**Claim as stated (origin: task brief for Phase B Step 5, restated in the Step 5 report
§5).** That a previous Step 4 report said 21 AntennaPod classes were reported changed
by the DEX diff.

**Artifact search performed.** Search 3 above, plus a full read of
`artifacts/toolchain-validation/antennapod/result.md`,
`artifacts/toolchain-validation/antennapod/original_baseline.json`,
`artifacts/toolchain-validation/antennapod/test_a/original_vs_noop_diff.json`,
`tests/corpus_results.json` and `tests/corpus_results_baseline.json`.

**Supporting evidence found: none.** No report, JSON result, or commit in this
repository states that any number of AntennaPod classes changed. Every artifact that
records the AntennaPod DEX diff records **zero** changed classes:

| artifact | recorded value |
|---|---|
| `artifacts/toolchain-validation/antennapod/result.md:47` | "All 12,065 classes, 70,360 methods, and API references remain semantically identical (0 classes added, 0 classes removed, 0 classes modified)" |
| `artifacts/toolchain-validation/antennapod/test_a/original_vs_noop_diff.json` | `dex.classes_modified: []`, `dex.classes_unchanged_count: 12065` |

**Verdict: UNVERIFIED.** The claim is not reproducible from any artifact present in
this repository and is not used as acceptance evidence anywhere.

**What *is* verified**, and recorded separately (not as a correction of the above):
`artifacts/toolchain-validation/step5/table_shift_experiment.json` and
`artifacts/toolchain-validation/closeout/table_shift_rerun.json` measure a *controlled*
table-index-shift scenario on OpenLink (delete 9 classes, rebuild) in which the
**pre-fix raw-byte hashing** produced 234 false-positive changed methods across 67
classes while the normalized hashing produced 0. That is a measured property of the old
hashing scheme; it is **not** a reconstruction of the "21 classes" number, and must not
be cited as one.

---

## Claim 2 — "10,958 classes"

**Claim as stated (origin: task brief for Phase B Step 5, restated in the Step 5 report
§9).** That Step 4 reported 10,958 AntennaPod classes, versus 12,065 in Step 2.

**Artifact search performed.** Searches 1, 2 and 4 above.

**Supporting evidence found: none.** The string `10958` / `10,958` does not occur in
the working tree except inside the Step 5 report's own discussion of its absence, and
does not occur in **any blob of any commit** in the repository history (search 2
returned no matches across all 3 commits).

**Every recorded measurement agrees on 12,065:**

| artifact | total_classes |
|---|---|
| `artifacts/toolchain-validation/antennapod/original_baseline.json:39` | 12065 |
| `artifacts/toolchain-validation/antennapod/result.md:17` | 12,065 |
| `tests/corpus_results_baseline.json:882` (pre-Step-4 baseline) | 12065 |
| `tests/corpus_results.json:909` (close-out run) | 12065 |
| `artifacts/toolchain-validation/closeout/antennapod_class_count_remeasure.json` (re-measured at close-out) | 12065 |

**Verdict: UNVERIFIED.** There is no 10,958 measurement in this repository to compare
against, so no discrepancy can be investigated and none is claimed to exist.

**Counting method, recorded for future comparability**
(`artifacts/toolchain-validation/closeout/antennapod_class_count_remeasure.json`,
source `src/apkforge/inspection/dex.py`): `DEXInspector.inspect()` enumerates APK
entries matching `classes\d*\.dex`, parses each with Androguard, counts
`len(DEX.get_classes())` per file, and sums into `DEXInspection.total_classes`. For
AntennaPod that is `classes.dex` 8,391 + `classes2.dex` 643 + `classes3.dex` 3,031 =
**12,065** classes / 70,360 methods, with 0 inspection warnings. Any future count that
differs should be compared against this per-DEX breakdown rather than the total alone.

---

## Claim 3 — the "goto → goto/16" branch-widening explanation

**Claim as stated (origin: task brief for Phase B Step 5, restated in the Step 5 report
§5).** That the changed AntennaPod classes were explained by branch widening, i.e. the
assembler re-encoding `goto` as `goto/16`.

**Artifact search performed.** Search 3 above. (Note: `grep` for `goto/16` across the
whole tree *does* return thousands of hits, but all of them are literal `goto/16`
instructions inside decoded smali under
`artifacts/toolchain-validation/*/test_a/decoded_original/smali/` — i.e. ordinary
application bytecode, not a report making a causal claim. Search 3 is restricted to
`*.md` for that reason.)

**Supporting evidence found: none.** No report in this repository advances the
branch-widening explanation, and because Claim 1 is itself unverified there is no
measured phenomenon for this explanation to explain.

**Verdict: UNVERIFIED.** The causal explanation is recorded here as unsubstantiated and
is **not** replaced with an alternative causal claim.

**What *is* verified about branch-width re-encoding**, recorded separately: the
normalized DEX representation deliberately keeps the instruction mnemonic as part of a
method's identity, so `goto` and `goto/16` hash **differently** by design
(`tests/unit/test_phase_b_step5.py::TestDEXNormalizedHashing::test_different_opcode_changes_normalized_instruction`).
It therefore remains *possible* for a smali round trip that re-selects branch widths to
show methods as changed. Whether that actually occurred in any AntennaPod run is
unknown, because no such run's artifacts exist here. Measured fact from the artifacts
that do exist: on the OpenLink no-op round trip, **0 of 108 classes** changed under
either hashing scheme
(`artifacts/toolchain-validation/closeout/table_shift_rerun.json`,
`results.vs_control_rebuild`), so no branch-width effect was observed there.

---

## Why these were not silently corrected

Per the evidence rule now in force for this project, a measurement with no persistent
supporting artifact is labelled UNVERIFIED, is not used as acceptance evidence, and is
not presented as an established project fact. Rewriting the historical Step 4 claim to
"12,065" would have destroyed the audit trail showing that an unsupported number once
circulated. Keeping the claim visible and labelled is the point of this register.

## Impact on the Phase B gate

None of the three claims is used as acceptance evidence for any Phase B criterion. The
DEX acceptance criteria are supported instead by:

- `artifacts/toolchain-validation/closeout/table_shift_rerun.json` — table-shift regression
- `artifacts/toolchain-validation/closeout/dex_exception_handler_experiment.json` — handler-only detection
- `artifacts/toolchain-validation/closeout/unit_test_run.txt` — unit regression
