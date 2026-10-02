# Phase B Close-Out

Nothing was committed. No Phase C work was started. No modification capability, external
patch framework, GUI, or runtime execution was added.

## 1. Security validation
**PASS**

All 59 findings across the three required APKs were hand-reviewed, each one traced back
to the APK artifact the detector cited and independently re-derived (zip listing /
extraction, `ManifestInspector`, `DEXInspector` api_references + strings + class
inventory, and the `SecurityEvidenceIndex` the rule engine actually evaluates). No
detector was found to cite evidence that does not exist in the APK; in every
FALSE_POSITIVE case the artifact is genuinely present and the defect is the inference
drawn from it.

| app | findings | TRUE_POSITIVE | FALSE_POSITIVE | UNCLEAR | FP rate |
|---|---|---|---|---|---|
| OpenLink | 5 | 5 | 0 | 0 | 0.0% |
| PCAPdroid | 9 | 6 | 2 | 1 | 22.2% |
| AppManager | 45 | 24 | 20 | 1 | 44.4% |
| **total** | **59** | **35** | **22** | **2** | **37.3%** |

AppManager's findings were traced individually as required; the 14 embedded
`frameworks/android/android-NN.apk` entries were extracted and shown to contain only
`resources.arsc` + `AndroidManifest.xml` (no code), while `assets/am.jar` and
`assets/main.jar` were shown to contain real `classes.dex` — so the payload rule is wrong
about the former and right about the latter. 12 proposed rule changes (`PRC-01`…`PRC-12`)
are **recorded only**; no severity, confidence, score or threshold was modified.

PASS is the verdict for the *review task*. The 37.3% false-positive rate is itself an
unresolved rule-precision defect, carried as a Phase C blocker in the final gate below.

## 2. getattr audit
**PASS**

86 `getattr()` occurrences across 16 files at the committed baseline → **8 occurrences
across 3 files**, all retained deliberately with recorded reasons. Two real defects were
found by the audit:

- **DEFECT-1 (functional):** `modification/rules.py` read `is_obfuscated`; the model field
  is `is_likely_obfuscated`, so `has_obfuscation()` returned `False` unconditionally and
  every obfuscation-gated modification rule was permanently unreachable. Fixed.
- **DEFECT-2 (dead code):** a `framework_api_calls` loop over a field that exists nowhere
  in the repository. Removed.

Plus 15 provably-dead fallback branches removed (fields absent from `DEXInspection`,
`DEXFileInspection`, `ManifestInspection`, `EvidenceSource`) — all verified unreachable by
model introspection, so no behaviour changed.

## 3. DEX exception-handler normalization
**PASS**

The normalized method representation now covers try/catch ranges, caught exception types
**in test order**, handler targets and catch-all handlers, expressed as resolved type
descriptors and instruction ordinals. Raw `handler_off` byte offsets and absolute
file offsets are used only to join tries to handlers and are excluded from the hash.

Real-APK acceptance (pinned Docker toolchain, one `.catch` type changed from
`Ljava/lang/Exception;` to `Ljava/lang/Throwable;`, no instruction touched):

| hashing | common methods | methods reported changed | target detected |
|---|---|---|---|
| instructions only (pre-close-out) | 462 | **0** | no |
| instructions + exception handlers | 462 | **1** | yes |

APKForge's DEX diff on the same pair: 1 class modified (`…ui.MenuActivity`), 1 method
(`a`) with `code_changed=true`, 107 classes unchanged, 0 collateral false positives.

Table-shift regression re-run after the change (delete 9 classes, rebuild): 9 classes
reported removed, **0** untouched classes reported modified, 99 unchanged — while the old
raw-byte hashing still shows 234 false-positive methods across 67 classes on the identical
rebuild. 11 new unit tests for the handler representation (`tests/unit/test_phase_b_closeout.py::TestExceptionHandlerNormalization`); no existing DEX normalization test regressed.

## 4. process attribute
**PASS**

`android:process` was missing from inspection, model and diff. Implementation was
straightforward and consistent with the existing architecture, so it was implemented:
`process: str | None` on all four component models, extraction via
`apk.get_attribute_value(<type>, "process", …)` for all four types, and exact-match
semantic diffing folded into each component's `is_mod` with `details.process_before` /
`details.process_after`. 9 focused tests.

Verified against all 9 corpus APKs: Fennec 94 components with `android:process`, NewPipe 5,
PCAPdroid 1 (`:error_activity`), AppManager 1 (`:audio_player`), others 0.

One residual nuance (recorded in known-limitations §5): comparison is exact string
equality, so the `:name` shorthand vs the fully-qualified `<package>:name` spelling would
compare unequal. No corpus APK exhibits this.

## 5. Step 4 unverified claims
**PASS**

`artifacts/toolchain-validation/step4_unverified_claims.md` registers all three claims as
**UNVERIFIED**, without modifying any historical report and without substituting a
replacement claim:

- "21 AntennaPod classes changed" — no artifact or commit states any non-zero AntennaPod
  class change; every artifact records 0.
- "10,958 classes" — the string occurs in no blob of any commit (all 3 commits searched);
  five independent artifacts record 12,065.
- "goto → goto/16" — no report advances this explanation, and with Claim 1 unverified
  there is no measured phenomenon for it to explain.

Each entry records the exact search commands, what was found, and (separately, clearly
not as a correction) what *is* verified in the same area.

## 6. Known limitations
**PASS**

`docs/known-limitations.md` created with 9 entries, each explicitly classified as
**accepted behaviour**, **known limitation**, or **unresolved defect** — the security
rule-precision issues and the `ManifestInspection` silent-drop are recorded as unresolved
defects, not downgraded to "accepted" to clear the gate.

Two corrections to the brief's description of the Fennec limit, made from source rather
than restated: the embedded-inspection threshold is **64 MiB** (`_MAX_DETECT_SIZE`,
`src/apkforge/inspection/embedded.py:53`), not 100 MB, and it is a **module constant, not
configurable**. The triggering entry is `lib/arm64-v8a/libxul.so` at 156,864,024 bytes.

The residual rename figures requested (OpenLink 20, AntennaPod 81) **are** supported by the
Step 5 artifacts and are reported; OpenLink's 20 was independently reproduced in this
task's acceptance run.

## 7. Full unit regression
**PASS**

| metric | value |
|---|---|
| total tests | 386 |
| passed | 386 |
| failed | 0 |
| skipped | 0 |
| errors | 0 |
| runtime | 8.98 s |

No test was skipped, xfailed, or substituted for a required regression. 20 tests are new
in this task — 11 exception-handler + 9 `process`, all in
`tests/unit/test_phase_b_closeout.py` — taking the suite from 366 to 386.
`tests/integration/` contains only
`__init__.py` — pre-existing, recorded as known-limitations §9.

Static analysis, measured by set-differencing against the committed baseline: **no new
mypy error outside `inspection/manifest.py`**, where the four new `process` extraction
calls add 8 instances of one pre-existing pattern (`apk` is annotated `object`) while 3
pre-existing errors were fixed (119 → 124). Ruff findings went 25 → 6 with **zero** new
findings.

## 8. 9-APK corpus regression
**PASS**

| | Step 5 baseline | close-out | delta |
|---|---|---|---|
| total tests | 99 | 99 | 0 |
| PASS | 96 | 96 | 0 |
| PARTIAL | 3 | 3 | 0 |
| FAIL | 0 | 0 | 0 |
| duration | 326.5 s | 343.3 s | +16.8 s (+5.1%) |

Verdict counts for the Step 5 baseline row are from `git show 212227f:tests/corpus_results.json`
(the committed results file, whose PASS/PARTIAL/FAIL profile is identical in Step 4 and
Step 5); the Step 5 **duration** is from `step5_verifier_robustness.md` §11, because the
corpus runner overwrites `tests/corpus_results.json` on every run. The committed file's own
duration, 263.8 s, is the Step 4 run.

No capability is worse than baseline; no APK moved PASS → PARTIAL/FAIL or PARTIAL → FAIL.
The 3 PARTIALs are the same APK and the same three capabilities as the baseline
(`org.mozilla.fennec_fdroid`: `inspection_full`, `privacy`, `security`), with the same
root cause (known-limitations §1). No result count was edited.

The runtime trend across the whole of Phase B, recorded rather than hidden: 263.8 s at Step 4,
326.5 s after Step 5 added normalized instruction hashing, 343.3 s after this task added
exception-handler normalization on top (+16.8 s / +5.1% for this task; +30.1% cumulative
since Step 4).

## 9. OpenLink acceptance
**PASS**

Full workflow through the pinned Docker image only. Host has no `apktool`, `apksigner` or
`zipalign` on `PATH` and both `ANDROID_HOME` and `ANDROID_SDK_ROOT` are unset — recorded
in `openlink_acceptance/toolchain_versions.txt` (Apktool 2.10.0, apksigner 0.9, OpenJDK
17.0.20.1, image `sha256:79434918ee5e…`).

decode → build → zipalign → sign → verify → APKForge intake → inspection → semantic diff:
all PASS. `apksigner verify`: Verifies, v1=true, v2=true, v3=true.

**No-op** (original vs no-op rebuild): 0 permission changes, 0 component changes, 0
manifest attribute changes, 0 DEX class changes (108 unchanged), 0 network changes.
File-level noise floor only: 2 added / 18 removed / 4 modified / 64 renamed (28 of those
renames resolved by ARSC resource identity, 36 by content hash), certificate CHANGED from
the debug re-sign.

**Modified** (no-op vs modified): **exactly the two planned semantic modifications and
nothing else** —

1. `permissions.removed == ["android.permission.RECEIVE_BOOT_COMPLETED"]`
2. `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver` → MODIFIED,
   `enabled_before=True`, `enabled_after=False`

with `components.total_modified == 1`, 0 manifest attribute changes, 0 DEX changes (108
unchanged), 0 network changes, 0 files added/removed/renamed, certificate SAME. The 4
modified files are `AndroidManifest.xml` (the intended change) plus the three signature
files regenerated by re-signing.

## 10. Evidence/history preservation
**PASS**

All 7 tracked historical evidence files verified byte-identical to `HEAD` (`git diff
--quiet` per file). Step 5's three artifacts are present and their measured values
re-read and confirmed identical. Step 4 produced no standalone report; its persisted
outputs (`tests/corpus_results.json`, `tests/unit/test_diff_gap_fixes.py`) are preserved —
the test file is unmodified, and because the corpus runner overwrites its results file by
design, the close-out run was snapshotted to `closeout/corpus_results_closeout.json` while
the Step 4 version stays retrievable via `git show 212227f:tests/corpus_results.json`.

All close-out evidence is additive; no historical report was overwritten. 9 corpus APKs
intact. No stash left behind. Nothing committed.

Transparency note: Step 5 artifact **mtimes** changed during this task because two
`git stash push --include-untracked` / `git stash pop` cycles (used to measure the
mypy/ruff baseline at `HEAD`) remove and restore untracked files. Content was verified
intact afterwards; no Step 5 value changed.

One artifact-policy defect was found and fixed: the blanket `*.log` ignore was swallowing
the apktool/zipalign/apksigner evidence logs that the acceptance report cites, so a
reviewer would not have received them. `.gitignore` now carries a single narrow negation
for `artifacts/toolchain-validation/closeout/**/*.log`. Verified that non-close-out `*.log`,
APKs, keystores and decoded trees all remain ignored.

---

## Quantitative evidence

Every number in this report, with its artifact. Paths are repo-relative;
`CO/` = `artifacts/toolchain-validation/closeout/`, `SV/` = `artifacts/security-validation/`.

| # | claim | value | evidence |
|---|---|---|---|
| 1 | findings reviewed / TP / FP / UNCLEAR | 59 / 35 / 22 / 2 | `SV/findings_review.json` → `totals`; recomputed by `SV/build_review.py` |
| 2 | FP rate per app | 0.0% / 22.2% / 44.4% | `SV/findings_review.json` → `apps.*.false_positive_rate` |
| 3 | raw findings per app | 5 / 9 / 45 | `SV/raw_openlink_security.json`, `raw_pcapdroid_security.json`, `raw_appmanager_security.json` |
| 4 | embedded framework APKs = resources only | `resources.arsc` 546,652 B + `AndroidManifest.xml` 1,396 B, no DEX | `SV/findings_review.json` → the 14 `SEC-MAL-PAYLOAD-APK-*` entries' `independent_verification` |
| 5 | `am.jar` / `main.jar` contain DEX | 40,388 B / 12,444 B `classes.dex` | same, `SEC-MAL-DYN-LOAD` entry |
| 6 | BouncyCastle classes bundled in AppManager | 6,139 | same, `SEC-VULN-WEAK-CIPHER-001` / `…SECRET…` entries |
| 7 | getattr occurrences before → after | 86 (16 files) → 8 (3 files), 78 eliminated | `CO/getattr_audit.json` → `totals`; reproducible via `CO/recount_getattr.py` |
| 8 | real defects found by the audit | 2 | `CO/getattr_audit.json` → `real_defects_found_and_fixed` |
| 9 | handler-only change: instructions-only hashing | 462 common, **0** changed | `CO/dex_exception_handler_experiment.json` → `counterfactual_hashing.instructions_only` |
| 10 | handler-only change: with handlers | 462 common, **1** changed, target detected | same → `counterfactual_hashing.instructions_plus_handlers` |
| 11 | handler experiment APKForge diff | 1 class / 1 method modified, 107 unchanged | same → `apkforge_dex_diff` |
| 12 | table-shift re-run, normalized | 9 removed, 0 modified, 99 unchanged | `CO/table_shift_rerun.json` → `results.*.new_normalized_hash` |
| 13 | table-shift re-run, raw-byte | 367 common, 234 changed, 67 classes | same → `results.*.old_raw_byte_hash` |
| 14 | `process` components per corpus APK | Fennec 94, NewPipe 5, PCAPdroid 1, AppManager 1, rest 0 | `CO/process_attribute_evidence.json` → `real_corpus_extraction` |
| 15 | AntennaPod class count | 12,065 (8,391 + 643 + 3,031), 70,360 methods | `CO/antennapod_class_count_remeasure.json`; corroborated by `tests/corpus_results.json`, `antennapod/original_baseline.json`, `antennapod/result.md`, `tests/corpus_results_baseline.json` |
| 16 | "10,958" occurrences in history | 0 across all 3 commits | `step4_unverified_claims.md` → search 2 |
| 17 | unit tests total / passed / failed / skipped / runtime | 386 / 386 / 0 / 0 / 8.98 s | `CO/unit_test_run.txt` |
| 18 | mypy baseline → close-out | 119 → 124 errors, 0 new outside `inspection/manifest.py` | `CO/mypy_baseline_HEAD_212227f.txt`, `CO/mypy_closeout.txt` |
| 19 | ruff baseline → close-out | 25 → 6 findings, 0 new | `CO/ruff_baseline_HEAD_212227f.txt`, `CO/ruff_closeout.txt` |
| 20 | corpus: tests / PASS / PARTIAL / FAIL | 99 / 96 / 3 / 0 | `CO/corpus_run_stdout.txt`, `CO/corpus_results_closeout.json` |
| 21 | corpus baseline verdicts for comparison | 99 / 96 / 3 / 0 | `git show 212227f:tests/corpus_results.json` (that file's own duration, 263.8 s, is the Step 4 run) |
| 22 | corpus duration Step 5 → close-out | 326.5 s → 343.3 s | `step5_verifier_robustness.md` §11 (Step 5); `CO/corpus_results_closeout.json` → `meta` (close-out) |
| 23 | Fennec PARTIAL cause | `libxul.so` 156,864,024 B > 64 MiB | `CO/corpus_results_closeout.json` warnings; `src/apkforge/inspection/embedded.py:53` |
| 24 | OpenLink no-op file deltas | 2 added / 18 removed / 4 modified / 64 renamed | `CO/openlink_acceptance/acceptance.json` → `noop_result.files`; raw in `diff_original_vs_noop.json` |
| 25 | rename match basis (no-op) | 28 resource_identity + 36 content_hash | `CO/openlink_acceptance/diff_original_vs_noop.json` → entries' `details.match_basis` |
| 26 | OpenLink modified: semantic changes | exactly 2 (1 permission removed, 1 receiver `True`→`False`) | `CO/openlink_acceptance/acceptance.json` → `modified_result`; raw in `diff_noop_vs_modified.json` |
| 27 | OpenLink modified: file deltas | 0 added / 0 removed / 0 renamed / 4 modified | same → `modified_result.files` |
| 28 | apksigner verify both builds | Verifies, v1/v2/v3 true | `CO/openlink_acceptance/noop_verify.log`, `mod_verify.log` |
| 29 | toolchain versions, no host SDK | Apktool 2.10.0, apksigner 0.9, JDK 17.0.20.1; host tools absent, SDK vars unset | `CO/openlink_acceptance/toolchain_versions.txt` |
| 30 | residual unmatched rename pairs | OpenLink 20, AntennaPod 81 | `step5/rename_pairing_before_after.json`; OpenLink reproduced in `CO/openlink_acceptance/acceptance.json` |
| 31 | historical evidence unchanged | 7/7 files byte-identical to HEAD | `CO/history_check.json` |

## Remaining limitations

Genuine remaining limitations, all documented in `docs/known-limitations.md`:

1. **Security rule precision** — 22 verified false positives, including 2 HIGH, driven
   mainly by bundled-library string attribution and code-free-archive payload
   classification. *Unresolved defect.* (`PRC-01`…`PRC-12`)
2. **Embedded-file inspection skips entries over 64 MiB**, making Fennec PARTIAL.
   *Accepted behaviour* — transparent, never a silent skip.
3. **Residual unmatched rename pairs** (OpenLink 20, AntennaPod 81), almost entirely
   `META-INF/*` re-signing churn; only 2+2 genuine AntennaPod resource paths. *Known
   limitation* — ambiguity is deliberately not guessed.
4. **Manifest resource resolution** is first-configuration-wins, numeric-`@hex`-only, and
   limited to selected attributes. *Known limitation*, mitigated in the diff layer.
5. **DEX**: unresolvable operand kinds (`METH_PROTO`, `CALL_SITE`, odex-only) and
   off-boundary addresses fall back to raw indexes/addresses. *Known limitation.* Branch
   width remaining part of method identity is *accepted behaviour*.
6. **`android:process`** exact-string comparison does not equate `:name` with
   `<package>:name`. *Known limitation.*
7. **`ManifestInspection` silently drops unknown kwargs** (Pydantic `extra="ignore"`),
   which is how one dead fallback tier and one misleading test fixture arose. *Unresolved
   defect* (latent).
8. **mypy baseline 124 errors**, dominated by `apk: object` in `inspection/manifest.py`.
   *Known limitation.*
9. **No integration test suite**; end-to-end coverage lives in the corpus runner and the
   Docker acceptance runs, neither under pytest. *Known limitation.*

## Proposed logical commits

Derived from the actual working tree (19 modified tracked files, 9 new paths). Nothing was
committed.

1. **fix(security): never report a FAILED inspection as a clean verdict** —
   `src/apkforge/security/engine.py` (status-escalation removal),
   `tests/unit/test_security_engine.py` (4 fixtures corrected + 1 new regression test),
   `tests/unit/test_cli.py` (exit-code expectation corrected). *Carried over from Step 5;
   the invariant fix and the tests that depended on the bug belong together.*
2. **feat(inspection): normalized DEX method hashing with resolved operands** —
   `src/apkforge/inspection/dex.py` (`_normalize_operand`, `_normalize_instruction`,
   `_hash_method_code`), `tests/unit/test_phase_b_step5.py` (DEX portion).
3. **feat(inspection): include exception-handler semantics in the DEX method hash** —
   `src/apkforge/inspection/dex.py` (`_build_address_index`, `_resolve_handler_target`,
   `_normalize_exception_handlers`), `tests/unit/test_phase_b_closeout.py` (handler
   portion).
4. **feat(diff): component enabled-default, directBootAware and intent-data reporting** —
   `src/apkforge/diff/components.py`, `tests/unit/test_phase_b_step5.py` (component
   portion).
5. **feat(inspection,diff): android:process support** —
   `src/apkforge/inspection/models.py`, `src/apkforge/inspection/manifest.py`,
   `src/apkforge/diff/components.py`, `tests/unit/test_phase_b_closeout.py` (process
   portion).
6. **feat(diff): ARSC resource-identity rename pairing** —
   `src/apkforge/diff/resource_identity.py` (new), `src/apkforge/diff/files.py`,
   `tests/unit/test_phase_b_step5.py` (rename portion).
7. **refactor: replace dynamic attribute access with typed access; fix obfuscation-flag
   defect** — `src/apkforge/modification/rules.py`, `modification/planner.py`,
   `modification/framework.py` (unchanged, documented), `src/apkforge/diff/dex.py`,
   `diff/manifest.py`, `src/apkforge/privacy/{engine,endpoints,permissions}.py`,
   `src/apkforge/security/{engine,diff_analyzer}.py`,
   `src/apkforge/intake/certificates.py`, `src/apkforge/cli/main.py`.
8. **chore(lint): wrap long lines, extract diff entry/intent-data helpers** —
   `src/apkforge/diff/files.py`, `src/apkforge/diff/components.py` (the E501/B905/ANN401/
   S112 cleanups). *Separable from 6/4 if a reviewer prefers behaviour-only diffs.*
9. **docs: known limitations register** — `docs/known-limitations.md`.
10. **chore(gitignore): keep close-out toolchain evidence logs trackable** — `.gitignore`.
11. **evidence(phase-b): security validation review** — `artifacts/security-validation/**`.
12. **evidence(phase-b): close-out regression, acceptance and audit artifacts** —
    `artifacts/toolchain-validation/closeout/**`, `tests/corpus_results.json` (regenerated).
13. **evidence(phase-b): Step 5 report and artifacts** —
    `artifacts/toolchain-validation/step5_verifier_robustness.md`,
    `artifacts/toolchain-validation/step5/**`. *Still uncommitted from Step 5.*
14. **evidence(phase-b): Step 4 unverified-claims register and close-out report** —
    `artifacts/toolchain-validation/step4_unverified_claims.md`,
    `artifacts/toolchain-validation/phase_b_closeout.md`.

## Final gate

All ten close-out criteria are PASS, and every Phase B acceptance criterion is backed by a
persistent artifact listed in the evidence table above:

- The verifier detects an exception-handler-only modification that was previously
  invisible (0 → 1 of 462 methods), while still reporting **0** false positives on a real
  table-index-shift rebuild.
- The OpenLink acceptance workflow reports **exactly** the two planned semantic
  modifications and nothing beyond the documented noise floor, using only the pinned
  Docker toolchain with no host Android SDK.
- The 9-APK corpus is unchanged at 96 PASS / 3 PARTIAL / 0 FAIL, with the one PARTIAL
  cause traced to a source constant and classified as accepted behaviour.
- 386/386 unit tests pass with nothing skipped; no new mypy error class and no new ruff
  finding.
- Dynamic attribute access is down to 8 deliberate, documented sites, and the audit caught
  a silently-disabled feature.
- Historical Step 2/3/4/5 evidence is verified intact and all new evidence is additive.

The remaining limitations in §Remaining limitations are the honest residue. Eight of the
nine are accepted behaviour or known limitations that do not block Phase C. **One does:**
the security rule engine has a measured 37.3% false-positive rate (44.4% on AppManager),
including two HIGH-severity false positives whose cause is understood and reproducible
(`SV/findings_review.json`). Phase C builds modification capability on top of this
analysis layer, and letting a known-wrong HIGH-severity signal drive modification
decisions would propagate the defect rather than contain it. That is a scope decision
rather than a technical unknown — the fixes are specified in `PRC-05`, `PRC-07` and
`PRC-08` and were deliberately not applied here because this task prohibited changing rule
behaviour.

Blocking issue, with its evidence:

| blocker | evidence | proposed fix (not applied) |
|---|---|---|
| 22 verified false positives (2 HIGH) in the security rule engine; 37.3% overall rate, 44.4% on AppManager | `SV/findings_review.json` → `totals`, `apps.appmanager.verdict_counts`; per-finding `independent_verification` | `PRC-05` (check nested APK for code before `payload`), `PRC-07` (require key body, not PEM armor), `PRC-08` (attribute crypto strings to owning package) |

PHASE C NOT READY
