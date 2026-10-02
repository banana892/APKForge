# Phase B Step 5 — Verifier Robustness, DEX Normalization & Corpus Regression

Status: Step 5 of Phase B. **Phase C has NOT started.** This report does not
replace or rewrite the Step 2/Step 3 evidence (`antennapod/result.md`,
`openlink/result.md`) — it is a new, additive report. History preserved:
Step 2/3 discovered the `enabled`-comparison and raw-byte-hash verifier
defects; this step fixes and validates them, plus a second, independently
discovered defect in the security-status escalation logic (item 13).

---

## 1. Files changed

```
 src/apkforge/diff/components.py        |  33 ++++++++--   (enabled-default normalization, directBootAware compare)
 src/apkforge/diff/files.py             |  72 +++++++++++-- (ARSC resource-identity rename pairing, match_basis tagging)
 src/apkforge/diff/resource_identity.py |  NEW              (ARSC -> type/name/qualifier identity resolver)
 src/apkforge/inspection/dex.py         | 123 ++++++++++---- (normalized instruction hashing, replaces raw-byte hash)
 src/apkforge/security/engine.py        |  13 +++---         (removed FAILED->COMPLETE escalation bug)
 tests/unit/test_cli.py                 |  12 ++-            (corrected a test asserting the old masked-failure behavior)
 tests/unit/test_security_engine.py     |  29 ++++-           (4 fixtures fixed + 1 new regression test)
 tests/unit/test_phase_b_step5.py       |  NEW (25 tests)    (DEX normalization, enabled defaults, directBootAware, ARSC rename)
```

6 files modified, 2 files added. `git diff --stat`: 259 insertions, 23 deletions (excluding the two new files).

No changes were made to `security/rules.py`, `security/malware.py`,
`security/spyware.py`, or `security/vulnerabilities.py` (rule logic itself)
— only the status-aggregation bug in `security/engine.py`, per scope.

---

## 2. Tests added / changed

- **`tests/unit/test_phase_b_step5.py`** (new, 25 tests):
  - `TestDEXNormalizedHashing` (7): table-index-shift stability and
    semantic-difference detection at the pure-function level (using fake
    `Instruction`/`Code` objects matching Androguard's documented tuple
    shapes), plus a determinism check against the real OpenLink corpus DEX.
  - `TestEnabledDefaultNormalization` (12): all four component types,
    covering missing↔true (unchanged) and missing↔false / true↔false
    (modified) transitions.
  - `TestDirectBootAwareComparison` (2): the newly-added sibling-attribute
    comparison for activities.
  - `TestResourceIdentityRenamePairing` (3): differently-encoded-bytes
    rename, genuinely-different resources (must stay remove+add), and an
    ambiguous multi-candidate match (must not be guessed).
- **`tests/unit/test_security_engine.py`**: fixed 4 pre-existing fixtures
  that omitted `status=` on `InspectionResult(...)` and were silently
  relying on the FAILED→COMPLETE escalation bug to pass; added
  `test_failed_inspection_never_reports_clean_security_verdict` (item 13C).
- **`tests/unit/test_cli.py`**: `test_analyze_stub_exits_zero` asserted
  exit code 0 for a 2-byte non-APK file (`b"PK"`); this was only true
  because of the same masked-failure bug. Renamed to
  `test_analyze_on_unparseable_file_exits_nonzero` and corrected to assert
  non-zero exit, matching the CLI's own (pre-existing, previously dead)
  `if sec_res.status == AnalysisStatus.FAILED: raise typer.Exit(code=1)`.

Full suite: **366 passed, 0 failed** (`pytest tests/unit`, 8.9s).

---

## 3. Full test result

```
366 passed in 8.90s
```

No test was loosened to make this pass; the 5 pre-existing tests that
changed were changed because they encoded the bug being fixed (see §12/13
below), not because their intent was wrong.

---

## 4. DEX table-shift experiment result

**Root cause fixed (item 1):** `DEXInspector` hashed
`code.get_bc().get_raw()` — the method's raw instruction bytes. DEX
instructions encode method/field/type/string-pool references as numeric
table indexes; removing or adding any class anywhere in the DEX can shift
those indexes for every *other* method that references a pool entry
sorting after the change, changing the raw bytes of an untouched method.

**Fix:** `_hash_method_code` (new) hashes a normalized instruction stream
instead. Each instruction is represented as
`(mnemonic, normalized_operands)`, where every pool reference operand is
replaced by Androguard's already-resolved symbolic identity (e.g.
`"Lcom/example/Foo;->bar(I)V"`, or the literal string content) instead of
the raw index; registers, literals, and branch offsets (already relative)
are preserved as-is. See the docstrings in `src/apkforge/inspection/dex.py`
(`_normalize_operand`, `_normalize_instruction`, `_hash_method_code`) for
the full, documented contract, including the one narrow fallback (the rare
`Kind.METH_PROTO` / `Kind.CALL_SITE` / odex-only kinds Androguard itself
cannot resolve symbolically — these fall back to the raw index,
deterministically, and are documented as not table-index-stable).

**Experiment** (real Apktool round trip, Docker-only pinned toolchain,
`de.audioattack.openlink_28.apk`, 108 classes):

| | common methods | false-positive `code_changed` | affected classes |
|---|---|---|---|
| No-op control (nothing removed) — OLD hash | 462 | 0 | 0 / 108 |
| No-op control (nothing removed) — NEW hash | — | 0 classes_modified | 108/108 unchanged |
| **9 classes removed** — OLD (raw-byte) hash | 367 | **234 (63.8%)** | **67 / 99** untouched classes |
| **9 classes removed** — NEW (normalized) hash | — | **0** classes_modified | **9 removed, 99/99 unchanged** |

Full data: `artifacts/toolchain-validation/step5/table_shift_experiment.json`.

Procedure: fresh `apktool d` decode → delete smali package `b/` (9 classes:
`b.a`, `b.a$a`..`b.a$f`, `b.b`, `b.c`) → `apktool b` → `zipalign -p -f 4` →
`apksigner sign` (debug.keystore) → `apksigner verify` → APKForge DEX
inspect + diff, all via `apkforge-toolchain:pinned` only (no host SDK). A
no-op control (decode→build, nothing removed) was built the same way to
separate "apktool recompilation noise" from "class-removal noise": the
control showed **zero** false positives even under the old raw-byte
hashing, confirming the false positives are specifically a table-index-
shift effect of the removal, not a generic recompilation artifact.

**Acceptance condition: PASS.** The 9 deliberately-removed classes are
reported `classes_removed`; all 99 untouched classes are `classes_modified
== 0`. Real semantic changes remain detectable (see
`test_hash_method_code_changes_for_real_semantic_difference` and
`test_different_resolved_reference_changes_normalized_instruction` in
`test_phase_b_step5.py`).

---

## 5. AntennaPod DEX discrepancy explanation

The task brief stated a prior report claimed "21 AntennaPod classes
changed" attributed to branch widening (`goto` → `goto/16`), and asked me
to verify that causal claim rather than repeat it.

**I could not find this claim in the repository.** I searched every
`*.md` and `*.json` file under `artifacts/` and `docs/` for "21", "goto/16"
narrative text, "branch widening", etc. No report in this repo makes that
claim. What the repository's own Step 2 evidence
(`artifacts/toolchain-validation/antennapod/result.md`) already recorded —
written *before* today's changes — is:

> "All 12,065 classes, 70,360 methods, and API references remain
> semantically identical (0 classes added, 0 classes removed, 0 classes
> modified)."

I re-ran the real original AntennaPod APK against the already-built
Apktool no-op rebuild (`antennapod_noop_signed.apk` from the earlier Step
2 session) with both the current (new, normalized) hashing and -- for
comparison -- the exact pre-fix raw-byte hashing logic, independently
re-implemented in a scratch script against the raw DEX. **Both produced
`classes_modified == 0` / `classes_unchanged_count == 12065` for this
exact original-vs-no-op pair.**

So: for the comparison that is actually reproducible from evidence in this
repository, there is no DEX discrepancy to explain, under either the old
or the new hashing. I cannot confirm, deny, or attribute a cause to a
"21 classes changed" result I could not locate or reproduce. I am
reporting this as **unverifiable from available evidence**, not asserting
an explanation for a result I could not measure — per the explicit
instruction not to claim a result that wasn't actually measured.

What I *did* measure and can state with evidence: the raw-byte-hashing
defect is real and severe (see §4's 63.8% false-positive rate on a
controlled, real table-index-shift), so *if* a comparison elsewhere
produced 21 spuriously-changed AntennaPod classes via the old hashing, a
table-index shift (not branch-width re-encoding) is the far more likely
mechanism — apktool's smali round trip reassigns pool indexes for the
*entire* unchanged class set whenever a release APK's original dx/d8
pool-index assignment differs from Apktool/baksmali/smali's own
reconstruction (the assignment algorithm doesn't have to match, since there
is no spec requirement that it does). This is a plausible mechanism, not a
confirmed cause of an unlocated number.

---

## 6. `enabled` normalization result

Android treats an absent `android:enabled` attribute as enabled by
default; `ComponentDiffer` was comparing the raw tri-state value directly
(`a.enabled != b.enabled`), so `None` (absent) vs `True` (explicit) was
flagged as a change -- and `None` vs `False` was *not* detected as
disabling a component via the "missing/explicit" path (the direct `!=`
_did_ already catch `None != False`, but with the wrong semantics: it
would falsely treat `None -> True` and `True -> None` as changes too).

Fix: `_effective_enabled(value) -> bool` (`None` resolves to `True`) is
used for the change-detection boolean in all four component differs
(activity/service/receiver/provider); the raw before/after values are
still reported in `enabled_before`/`enabled_after` for transparency.

| transition | expected | result |
|---|---|---|
| missing → explicit true | unchanged | PASS |
| explicit true → missing | unchanged | PASS |
| missing → false | modified | PASS |
| false → missing | modified | PASS |
| true → false | modified | PASS |
| false → true | modified | PASS |

All 6 transitions tested for all 4 component types where applicable (24
assertions total) in `TestEnabledDefaultNormalization`
(`tests/unit/test_phase_b_step5.py`); all pass.

---

## 7. Sibling attribute audit table

| field | inspected? | in model? | compared by differ? | notes |
|---|---|---|---|---|
| `enabled` (all 4 types) | yes | yes | yes (now default-normalized) | fixed this step |
| `exported` (all 4 types) | yes | yes | yes | pre-existing |
| `permission` (activity/service/receiver) | yes | yes | yes (resource-ref aware) | pre-existing |
| `permission`/`readPermission`/`writePermission` (provider) | yes | yes | yes (resource-ref aware) | pre-existing |
| `authorities` (provider) | yes | yes | yes (resource-ref aware) | pre-existing |
| `grantUriPermissions` (provider) | yes | yes | yes | pre-existing |
| `foregroundServiceType` (service) | yes | yes | yes | pre-existing |
| intent-filter actions/categories/data (all 4 types) | yes | yes | yes | pre-existing; data dict was missing `port`/`mime_type` in the output -- **fixed this step** (comparison already included them in the match key; only the reported dict was incomplete) |
| `directBootAware` (activity only -- not extracted for service/receiver/provider) | yes (activity only) | yes (activity only) | **no → fixed this step** | security-relevant: changes which encrypted-storage state a component can run in before first unlock |
| `process` (not extracted for any component type) | no | no | no | out of scope -- not inspected at all; adding it would be a speculative addition beyond audit scope, left as a documented gap, not implemented |

Only the `directBootAware` gap and the intent-filter-data reporting gap
were fixed — both are inspected-and-modeled-but-silently-ignored cases, per
the audit's own instruction not to add fields that aren't already
inspected. `process` is a genuine blind spot but is **not** inspected by
`ManifestInspector` today, so adding a comparison for it would require new
inspection-layer extraction, which is out of this step's stated scope
("Do not automatically add every field... Add only the comparisons
justified by the existing project scope"). Flagged as a candidate for a
future step, not implemented here.

Regression tests: `TestDirectBootAwareComparison` (2 tests).

---

## 8. Rename-matching before/after counts

| | OpenLink: added / removed / renamed | AntennaPod: added / removed / renamed |
|---|---|---|
| Before (content-hash only) | 30 / 46 / 36 | 869 / 942 / 349 |
| After (content-hash + ARSC resource-identity) | 2 / 18 / **64** | 4 / 77 / **1214** |
| Unmatched remove+add pairs eliminated | 56 → 20 (-64%) | 1,811 → 81 (-95.5%) |

Method (`src/apkforge/diff/resource_identity.py`): parses each APK's
`resources.arsc` public-resource table, resolves every file-backed
resource (value starting with `"res/"`) to a canonical
`type/name/qualifier` identity (e.g. `drawable/ic_call_answer/`), and pairs
a removed path with an added path only when they resolve to the exact same
identity on their respective sides **and** the match is unambiguous (1:1).
Multiple paths sharing one identity on either side are left unpaired
(falls through to plain ADDED/REMOVED) rather than guessed, per the
explicit instruction not to suppress genuine uncertainty.

`FileEntryDiff.details["match_basis"]` distinguishes `"content_hash"` from
`"resource_identity"` renames; `"content_changed"` records whether the
paired entry's SHA-256 also differs (genuine re-encoding is *not*
suppressed -- it's visible in `sha256_before`/`sha256_after` either way).

Full numbers and remaining-unmatched breakdown:
`artifacts/toolchain-validation/step5/rename_pairing_before_after.json`.
The 18 (OpenLink) / 77 (AntennaPod) paths still reported as unmatched
`removed` are overwhelmingly `META-INF/*` signature/version markers
(expected re-signing noise, not resources) plus a small number of
genuinely unresolvable `res/` paths (left as remove+add, per spec, rather
than guessed).

Regression tests: `TestResourceIdentityRenamePairing` (3 tests, covering
the differently-encoded-bytes case, the genuinely-different-resources
case, and the ambiguous-match case). The pre-existing byte-identical-rename
test already covered scenario 1.

---

## 9. AntennaPod class-count discrepancy explanation

The task brief stated Step 2 reported 12,065 classes and "Step 4 reported
10,958 classes," asking me to investigate the discrepancy.

**I could not find "10,958" anywhere in this repository**, searched the
same way as §5. Every artifact that records an AntennaPod class count —
`artifacts/toolchain-validation/antennapod/original_baseline.json`,
`artifacts/toolchain-validation/antennapod/result.md`,
`tests/corpus_results.json`, and `tests/corpus_results_baseline.json`
(an older, pre-Step-4 baseline retained in git) — all agree: **12,065**
classes, 70,360 methods, 3 DEX files. There is no 10,958 in this
repository's history to investigate a regression against.

As with §5, I am reporting this as **unverifiable from available
evidence** rather than inventing a counting-methodology explanation for a
number I cannot locate. The counting method itself (`DEXInspector`
iterates `dex.get_classes()` per DEX file and sums `class_count` across
all DEX files in the APK) is unchanged by this step's work and is
unaffected by multi-DEX handling, generated/synthetic classes, or
parser filtering in any way that changed between Step 4 and Step 5 — I
verified this by re-running the same AntennaPod APK through the current
`DEXInspector` and confirming 12,065, matching every other recorded
measurement.

---

## 10. Pinned-image no-op result

Performed via `apkforge-toolchain:pinned` (Docker image already built from
`artifacts/toolchain-validation/Dockerfile`, Apktool 2.10.0 + Android Build
Tools 34.0.0, checksum-pinned) **exclusively** -- no host Android SDK, no
host apktool/zipalign/apksigner (confirmed absent from host `PATH`).

`de.audioattack.openlink_28.apk`, fresh decode → build → zipalign → sign →
verify → APKForge inspect → APKForge diff, all through the pinned image:

```
apksigner verify: Verifies
  v1 scheme: true   v2 scheme: true   v3 scheme: true
APKForge inspect: Inspection Status COMPLETE, Security Status FINDINGS_PRESENT
APKForge diff (original vs. toolchain-only no-op rebuild):
  summary.classes_modified: 0
  summary.components_modified: 0
  summary.permissions_added/removed: [] / []
  files: 2 added, 18 removed, 64 renamed, 4 modified, certificate CHANGED (expected: debug re-sign)
```

All artifacts were written under the bind-mounted scratch workspace with
`-u $(id -u):$(id -g)`; no `chmod 777` workaround was used, and no
unexpected semantic diff occurred (the only non-trivial diff content is the
already-documented noise floor: DEX/manifest/resources.arsc re-encoding,
the expected 64 resource renames now correctly classified per §8, and the
re-signing artifacts). `--version` was not treated as sufficient
validation; the full round trip plus a real inspect/diff was run.

---

## 11. 9-APK corpus regression result

`tests/corpus_runner.py`, current code, full 9-APK Phase A corpus:

```
Total tests: 99   PASS: 96   PARTIAL: 3   FAIL: 0   N/A: 0
Duration: 326.5s
```

Compared against the Step 4 baseline (`git show 212227f:tests/corpus_results.json`):

| | Step 4 (before) | Step 5 (after) |
|---|---|---|
| PASS / PARTIAL / FAIL | 96 / 3 / 0 | 96 / 3 / 0 |
| Duration | 263.8s | 326.5s (+24%, from the more expensive normalized hashing) |
| PARTIAL capabilities | `org.mozilla.fennec_fdroid`: inspection_full, privacy, security | identical |

**Zero regressions.** The 3 PARTIALs are the same APK and the same three
capabilities before and after (Fennec/Firefox; pre-existing, unrelated to
this step's changes — not investigated further here as it is outside the
item list).

Per-APK highlights relevant to this step's changes:
- `io.github.muntashirakon.AppManager_451.apk` (225,186 DEX methods, the
  corpus's largest): inspection PASS, DEX normalization added ~0 observed
  regression risk — hashed in the corpus run without timeout or memory
  issue (see §4's standalone DEX-only timing: 46.3s for this APK, 214,715
  of 225,186 methods hashed, the remainder being abstract/native/interface
  methods with no code, correctly `code_hash=None`).
- `de.danoeh.antennapod_3120295.apk` (70,360 methods, 3 DEX files):
  DEX-only inspection timing 15.2s (up from near-instant raw-byte hashing,
  still well inside the corpus run's per-APK budget).

Full results: `tests/corpus_results.json` (this session's run,
superseding the file at that path — the Step 4 version remains recoverable
from git history at commit `212227f`).

---

## 12. Security-validation status (item 13)

**A. Hand-review of security findings — PCAPdroid, AppManager, Open Link With:**

- **PCAPdroid** (`com.emanuelef.remote_capture`): 9 findings, 0
  critical/high, 3 medium (`SEC-SPY-ACCESSIBILITY-001`,
  `SEC-SPY-ACCESSIBILITY-ABUSE`, `SEC-SPY-DEVICE-IDENTIFIERS`). PCAPdroid is
  a known FOSS no-root traffic-capture/firewall app that uses an
  Accessibility Service to associate network traffic with the foreground
  app on non-rooted devices, and reads device identifiers for its
  per-app/VPN configuration — both findings are consistent with its
  documented, legitimate feature set, not indicative of actual spyware
  behavior.
- **AppManager** (`io.github.muntashirakon.AppManager`): 45 findings, 21
  high. Of the 21 high findings: 13 are
  `SEC-MAL-PAYLOAD-APK-frameworks_android_android-{23..36}_apk` — these are
  the per-Android-API-level framework resource APKs AppManager legitimately
  bundles to parse other apps' manifests/resources across OS versions, not
  droppers. The remaining high findings
  (`SEC-MAL-CODE-EXEC`/`SEC-MAL-DYN-LOAD`/`SEC-MAL-DYNLOAD-001`/
  `SEC-MAL-EXEC-001`, `SEC-COMB-ACCESSIBILITY-OVERLAY`,
  `SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER`,
  `SEC-VULN-WEAK-CIPHER-001`) reflect AppManager's actual purpose (a
  package manager needs shell/command execution and dynamic class loading
  to manage other apps) and two findings worth a second look in a future
  pass (the private-key-header string match and the weak-cipher usage) —
  neither reviewed finding indicates the static evidence is wrong; the
  findings are accurate, explainable by the app's documented purpose, and
  correctly presented as neutral evidence rather than a malware verdict.
- **Open Link With** (`de.audioattack.openlink`): 5 findings, all low
  severity (`persistence`, `network`, `configuration`, `vulnerability`,
  `exported_component`), consistent with a minimal link-handling utility.

No finding reviewed indicated a defect in the security engine's evidence
extraction; all are explainable by each app's actual, documented purpose.

**B. Unsafe `getattr(..., default)` audit:** grepped every `getattr(` call
in `security/` and `privacy/` (≈55 call sites). The overwhelming majority
are structural accessors on evidence objects with a semantically-neutral
empty default (`[]`, `None`, `""`) — safe, because an absent attribute on
one *kind* of evidence object is not the same thing as a failed analysis.

**One confirmed, severe instance was found and fixed**, independent of
(but directly supporting) this audit's goal:
`security/engine.py` contained

```python
overall_status = inspection.status
if overall_status == AnalysisStatus.FAILED and (
    inspection.manifest or inspection.dex or inspection.package
):
    overall_status = AnalysisStatus.COMPLETE
```

`inspection.package` is set unconditionally by `InspectionEngine` before
any inspector runs (including on every path that returns
`status=AnalysisStatus.FAILED`), so this condition was true on **every**
genuine total-inspection-failure case, silently turning FAILED into
COMPLETE and (when no findings happened to fire) into
`SecurityStatus.NO_SIGNIFICANT_STATIC_FINDINGS` — a clean verdict for an
analysis that did not actually run. This directly contradicts the
project's own documented invariant
(`apkforge/core/models.py::AnalysisStatus`: "A result must never be
interpreted as clean if its status is PARTIAL or FAILED"). **Fixed** by
removing the escalation; `overall_status` now only ever reflects
`inspection.status` directly, demoted no further.

This fix surfaced that 4 pre-existing unit tests and 1 CLI test were
themselves relying on the bug (hand-built `InspectionResult(...)`
fixtures that omitted `status=` and depended on the escalation to read as
COMPLETE) — all 5 were corrected (§2) rather than the production fix being
reverted, since the fixtures' *intent* was always "a successful
inspection", and that intent is now expressed explicitly.

**C. Regression test:** added
`test_failed_inspection_never_reports_clean_security_verdict` in
`tests/unit/test_security_engine.py` — asserts that a default
`InspectionResult(status=AnalysisStatus.FAILED)` (no manifest/dex/package,
the shape `InspectionEngine` actually produces when every sub-inspector
fails) produces `SecurityResult.status == FAILED` and
`security_status == ANALYSIS_INCOMPLETE`, and explicitly asserts it is
**not** `NO_SIGNIFICANT_STATIC_FINDINGS`.

All three sub-tasks (A/B/C) completed; none left OPEN.

---

## 13. Remaining blockers before Phase C

1. **`process` component attribute is not inspected at all** (§7) — not a
   regression, but a known gap if cross-process component placement
   becomes security-relevant. Needs new extraction in
   `ManifestInspector`, out of this step's scope.
2. **The "21 AntennaPod classes / goto-16" and "10,958 classes" claims
   could not be located or reproduced from any evidence in this
   repository** (§5, §9). If those numbers came from a real prior run
   whose artifacts were not committed, they are not recoverable for
   comparison; if a future session surfaces the original source, it
   should be re-verified against the now-normalized hashing rather than
   assumed to still apply.
3. **`org.mozilla.fennec_fdroid`'s 3 PARTIAL capabilities are pre-existing
   and unexplained by this step** (§11) — carried over unchanged from the
   Step 4 baseline; investigating them was not in this step's item list
   and is flagged here rather than silently ignored.
4. **AppManager's `SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER` and
   `SEC-VULN-WEAK-CIPHER-001` findings** (§12A) were reviewed for
   plausibility but not traced to the specific string/cipher usage site —
   a deeper manual trace (not just plausibility review) would be needed
   before treating them as fully explained.
5. **Try/catch exception-handler ranges are not part of the DEX
   normalization** (§4) — the normalized hash covers instruction
   mnemonic/operands only, not a method's exception-handler table. This
   wasn't in the task's explicit preservation list, but a change to only
   the handler table (same instructions, different catch ranges) would
   currently go undetected. Flagged as a known limitation, not fixed here
   to keep this step's diff focused.

Phase C readiness: **blocked pending user review of items 1-5 above**;
items 1, 3, 5 are scope decisions for the user, items 2 and 4 are residual
investigation. The OpenLink acceptance test passing is explicitly **not**
sufficient on its own (per this step's brief) and is not being treated as
such here.
