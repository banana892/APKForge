# Phase H.3 — First Narrowly Scoped Transformation (H-TRANS-001)

> H.3 applies exactly one validated, ELIGIBLE H.2 plan of H-TRANS-001 (remove isolated
> class) to a copy of the APK, rebuilds/aligns/signs/verifies it with the existing
> BuildService and proves, with H.1 re-analysis and the Phase E diff, that exactly the
> planned class was removed and nothing else changed. It has no override, never writes the
> input APK, and never states that an application is safe, benign or malware-free.

## 1. Starting point

- Starting commit: `4667dce` (Phase H.2; H.1 at `4013e9e`), working tree clean at start.
- The validation runs were executed on the uncommitted H.3 tree on top of `4667dce`
  (`git_head` in the summaries therefore reads `4667dce`).
- H.3 implementation commit: the commit that adds this file (see `git log`).

## 2. Transformation supported

Only **H-TRANS-001 — remove isolated class**. H-TRANS-002 (remove isolated method) remains
planning-only: an ELIGIBLE H-TRANS-002 plan is refused with `UNSUPPORTED_TRANSFORMATION`
(`tests/unit/test_phase_h3_transformation.py::test_integrity_h_trans_002_is_not_applied`).

## 3. Architecture

```text
APK -> H.1 reference analysis -> H.2 eligibility -> H.2 plan (JSON)
  -> H.3 load_plan -> source SHA-256 -> plan id (H.2 rules) -> ELIGIBLE?
  -> H.1 + the same H.2 planner re-run: ELIGIBLE and field-identical plan
  -> expected Phase E changes (class, string-pool entries, API refs) + noise floor
  -> ModificationPipeline (Phase D): BuildService.decode -> target checks
     -> remove ONE smali file -> class census -> build -> align -> sign -> verify
     -> DiffEngine + content-aware expected-vs-actual classification + Phase E matrix
  -> H.1 re-analysis of the output -> H.3 verification matrix
  -> atomic publish of the output APK only when VERIFIED
```

| Module (`src/apkforge/transformation/`) | Role |
|---|---|
| `application.py` | `ApplicationStatus`, `ApplicationReason`, `ApplicationStage`, `MutationRecord`, `PostAnalysis`, `MatrixRow`, `TransformationApplicationResult` (schema 1) |
| `executor.py` | `TransformationExecutor.run`, `load_plan`: integrity checks, consequence prediction, pipeline run, post-analysis, matrix, publish |
| `modifier.py` | `RemoveIsolatedClassModifier` (`h3.remove_isolated_class`): plan-bound Phase D modifier, not registered in the default catalog |
| `dexstate.py` | class census of a decoded project, smali string-pool tokenisation, per-class API attribution mirroring the Phase E DEX inspector |
| `report.py` | `format_application_report` (Markdown) |
| `cli/main.py` | `apkforge transform APK --plan PLAN.json [--apply -o OUT] [--noop-baseline F] [--keep-workspace] [--json] [--report]` |

No second build, diff, verification or eligibility engine exists: decode/build/align/
sign/verify are BuildService's, mutation ordering/source checks/rollback are the Phase D
pipeline's, comparison and classification are Phase E's, eligibility is H.2's.

## 4. H.2 plan consumption and eligibility enforcement

Checked in order, before anything is written: plan exists / is JSON / matches the H.2
schema with current schema versions and one `remove_class` change (`PLAN_NOT_FOUND`,
`PLAN_INVALID`); the H.2 decision produced a plan (`PLAN_NOT_ELIGIBLE`); source SHA-256
equals the plan's (`SOURCE_SHA_MISMATCH`); plan id recomputed with `decision_id_for`
(`PLAN_ID_MISMATCH`); transformation is H-TRANS-001 (`UNSUPPORTED_TRANSFORMATION`);
eligibility `ELIGIBLE` without conditions (`PLAN_NOT_ELIGIBLE`); H.1 + the unchanged H.2
planner, re-run on the APK, decide `ELIGIBLE` (`PLAN_NOT_ELIGIBLE`) and produce a
field-identical plan (`PLAN_MISMATCH`; the APK file name is excluded, identity is the
SHA-256). The CLI has no `--force`/`--unsafe`/`--ignore-checks`; `--apply` without `--plan`
exits 2, so planning and mutation are never combined in one step.

A forged plan (an ELIGIBLE plan rebound to a REFUSED/UNDETERMINED target's APK with a
*correctly recomputed* id) is refused by the re-evaluation (scenario `E_forged_*`).

## 5. Mutation semantics

Pre-mutation (decoded workspace): target defined exactly once, in the planned file and
DEX; workspace class count == H.1 count; the DEX keeps another class; every smali file
parseable (`TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS`, `TARGET_STATE_MISMATCH`,
`ANALYSIS_INCOMPLETE`, `TRANSFORMATION_PRECONDITION_FAILED` → `REFUSED`). Mutation: the
target file's SHA-256 and the class census are re-checked, exactly one smali file is
deleted, and before building H.3 confirms target present before / absent after, exactly
one class removed, no other class removed/added/moved, count −1 (`UNEXPECTED_MUTATION` →
`FAILED`, nothing built). The pipeline's source check independently rejects unplanned file
changes. Nothing else is edited; no code is injected and no call site is rewritten.

Mutation record of the positive synthetic run:

```json
{"transformation_id": "H-TRANS-001", "operation": "REMOVE_CLASS",
 "target": "com.example.h1.B", "target_file": "smali/com/example/h1/B.smali",
 "target_dex": "classes.dex", "count": 1, "post_transform_sha256": null,
 "classes_before": 3, "classes_after": 2, "removed_classes": ["com.example.h1.B"],
 "added_classes": []}
```

## 6. Build/sign pipeline and post-transform verification

BuildService build → align → sign (development key) → verify (zipalign, apksigner v1/v2/v3,
expected signer, ZIP integrity). Phase E: DiffEngine and the content-aware classification
against the APK's measured no-op baseline; every expected change is declared *before*
mutation (the class, every DEX string-pool entry and framework API reference only the
target contributes); any undeclared/unknown observation or unobserved declaration fails
(`UNEXPECTED_DIFF`). H.1 re-analysis of the output: target not defined, no other class
removed/added, count −1, no structural or indirect reference to the target, no component
weaker than before and DEX COMPLETE (else `ANALYSIS_INCOMPLETE` → `UNKNOWN`).

## 7. Synthetic results

`tests/fixtures/h3_apks.py`: six real APKs (package `com.example.h1`) built with
BuildService, round-tripped once and signed v2/v3-only by a separate publisher key — so
their no-op rebuild is `EQUIVALENT` and the H.3 output is re-signed as for any real app.

- Eligible synthetic plans: 1; scenarios: 23; applied (mutated): 4; verified: 2; refused: 18; failed: 2; dry run: 1
- Noise floor of the positive fixtures: {'h3_isolated': 'EQUIVALENT', 'h3_isolated_alt': 'EQUIVALENT'}

| Scenario | Expected | Got | Stage | Mutated | Source unchanged | Result |
|---|---|---|---|---|---|---|
| A_positive | VERIFIED | VERIFIED | - | 1 | True | PASS |
| A_dry_run | PLANNED | PLANNED | - | 0 | True | PASS |
| B_caller | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| C_reflection | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| D_native_method | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| D_native_code | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| E_manifest | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| E_forged_h3_caller | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| E_forged_h3_reflection | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| E_forged_h3_manifest | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| F_target_missing | REFUSED / TARGET_NOT_FOUND | REFUSED / TARGET_NOT_FOUND | pre_transform | 0 | True | PASS |
| G_source_sha | REFUSED / SOURCE_SHA_MISMATCH | REFUSED / SOURCE_SHA_MISMATCH | plan_integrity | 0 | True | PASS |
| H_target_edited | REFUSED / PLAN_ID_MISMATCH | REFUSED / PLAN_ID_MISMATCH | plan_integrity | 0 | True | PASS |
| H_plan_id_edited | REFUSED / PLAN_ID_MISMATCH | REFUSED / PLAN_ID_MISMATCH | plan_integrity | 0 | True | PASS |
| H_eligibility_edited | REFUSED / PLAN_NOT_ELIGIBLE | REFUSED / PLAN_NOT_ELIGIBLE | eligibility | 0 | True | PASS |
| H_expectation_edited | REFUSED / PLAN_MISMATCH | REFUSED / PLAN_MISMATCH | plan_integrity | 0 | True | PASS |
| H_schema_edited | REFUSED / PLAN_INVALID | REFUSED / PLAN_INVALID | plan_load | 0 | True | PASS |
| H_trans_002 | REFUSED / PLAN_ID_MISMATCH | REFUSED / PLAN_ID_MISMATCH | plan_integrity | 0 | True | PASS |
| H_invalid_json | REFUSED / PLAN_INVALID | REFUSED / PLAN_INVALID | plan_load | 0 | True | PASS |
| H_missing_plan | REFUSED / PLAN_NOT_FOUND | REFUSED / PLAN_NOT_FOUND | plan_load | 0 | True | PASS |
| I_unexpected_mutation | FAILED / UNEXPECTED_MUTATION | FAILED / UNEXPECTED_MUTATION | mutation | 2 | True | PASS |
| J_build_failure | FAILED / BUILD_FAILED | FAILED / BUILD_FAILED | build | 1 | True | PASS |
| K_repeat | VERIFIED | VERIFIED | - | 1 | True | PASS |

Reproducibility: result equal True, entry content equal True, APK bytes equal False.

Positive transformation, declared and observed changes:

- dex_class removed com.example.h1.B
- dex_string removed B.java
- dex_string removed Landroid/os/Looper;
- dex_string removed Lcom/example/h1/B;
- dex_string removed Ljava/lang/String;
- dex_string removed getMainLooper
- dex_string removed h3-only-in-b
- dex_string removed stamp
- dex_api_reference removed android.os.Looper;->getMainLooper()Landroid.os.Looper

| Check | Expected | Actual | Status |
|---|---|---|---|
| Source SHA | matches the plan | f3a9a145fe21e5df3dc164fa42f9e8efd462ed98aa8bd7e9beba4f0c7ab59ed0 | PASS |
| Plan ID | exact match | plan-8c920872a6437a1a0f77 | PASS |
| Eligibility | ELIGIBLE | plan ELIGIBLE, re-evaluated ELIGIBLE | PASS |
| Target class before | present | present | PASS |
| Target class after | absent | absent (decoded project and H.1 re-analysis) | PASS |
| Classes removed | 1 | 1 | PASS |
| Other classes removed | 0 | 0 removed, 0 added | PASS |
| Build | success | PASS | PASS |
| Align | success | PASS | PASS |
| Sign | success | PASS | PASS |
| Signature verification | success | PASS | PASS |
| Post-transform analysis | sufficient | COMPLETE; weakened none | PASS |
| Unexpected semantic changes | none | 0 unexpected/unknown, 0 expected change(s) missing | PASS |
| Original APK SHA | unchanged | f3a9a145fe21e5df3dc164fa42f9e8efd462ed98aa8bd7e9beba4f0c7ab59ed0 | PASS |

Publish time for 6 fixtures: 14.2 s. Workspaces left behind: 0.

## 8. Real corpus results

- Targets attempted: 226; ELIGIBLE: 0; applied: 0; verified: 0; refused: 226; failed: 0; outputs published: 0

| APK | SHA-256 (12) | Targets | ELIGIBLE | REFUSED | UNSUPPORTED | UNDETERMINED | H.3 refused | Applied | Unchanged | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | `e03f79082278` | 25 | 0 | 25 | 0 | 0 | 25 | 0 | True | PASS |
| com.oF2pks.applicationsinfo_19.apk | `c0188f5f1f56` | 22 | 0 | 22 | 0 | 0 | 22 | 0 | True | PASS |
| de.audioattack.openlink_28.apk | `3d28923f08bd` | 23 | 0 | 21 | 0 | 2 | 23 | 0 | True | PASS |
| de.danoeh.antennapod_3120295.apk | `3f43a4337a69` | 25 | 0 | 25 | 0 | 0 | 25 | 0 | True | PASS |
| eu.siacs.conversations_4218104.apk | `3fae646e33b5` | 25 | 0 | 25 | 0 | 0 | 25 | 0 | True | PASS |
| godau.fynn.usagedirect_10.apk | `c55079192a77` | 25 | 0 | 24 | 0 | 1 | 25 | 0 | True | PASS |
| io.github.muntashirakon.AppManager_451.apk | `e1f6ba10812c` | 25 | 0 | 23 | 0 | 2 | 25 | 0 | True | PASS |
| org.mozilla.fennec_fdroid_1560020.apk | `27f2951376ca` | 31 | 0 | 31 | 0 | 0 | 31 | 0 | True | PASS |
| org.schabi.newpipe_1015_cb84069.apk | `18447bfb1e06` | 25 | 0 | 25 | 0 | 0 | 25 | 0 | True | PASS |

Max RSS: 2289 MB

Every attempted target's H.2 eligibility is identical to the committed H.2 corpus artifact (`h2-corpus-summary.json`, 226/226). Every H.3 attempt was refused with `PLAN_NOT_ELIGIBLE` at stage `eligibility`, before any decode for mutation, build or signing. 0 transformations applied; 0 outputs published. The eligibility rules were not relaxed. Per-target decisions: `h3-corpus-summary.json`.

## 9. SHA preservation

- `sha256sum tests/corpus/*.apk` was identical before the H.3 corpus runs and after the full chain (corpus runs, Phase D–G regressions, final `all --write` run).
- Every synthetic scenario and every corpus attempt recorded `source_apk_sha256 == source_apk_sha256_after` (`original_unchanged: true`); every synthetic fixture SHA-256 was re-checked on disk after each scenario.
- The output path can never be the source (`OUTPUT_INVALID`, tested), and an unverified run never leaves an output file (checked in every scenario).

## 10. Phase D–G regression

| Gate | Result |
|---|---|
| Full pytest (`FORCE_COLOR=3`) | **1135 passed, 10 skipped, 0 failed** (H.2 baseline 1082 passed, 10 skipped; +53 H.3 tests) |
| H.3 synthetic + corpus runner (`all --write`) | PASS (23 scenarios + reproducibility; 226 corpus attempts) |
| Phase D `run_phase_d_validation.py` | A, B, C verified; D, F expected failures; E dry-run — all as expected |
| Phase E `run_phase_e_validation.py baseline` (no `--write`) | 8 VERIFIED, Fennec UNDETERMINED — same as the recorded baseline (AntennaPod drift note already present in committed `artifacts/phase-e`) |
| Phase F `run_phase_f_validation.py --output-dir work/h3-regression/phase-f` | 102 findings vs 105 in committed `artifacts/phase-f/` — the known persistence drift (7 -> 4), see note |
| Phase G runner redirected to `work/h3-regression/phase-g` | corpus summary identical to committed `artifacts/phase-g` (timing fields excluded) |
| ruff check / format / mypy (repo-wide) | 517 / 56 / 102 — identical to a clean `4667dce` worktree; all touched files clean |

Phase F drift (pre-existing, documented since H.1/H.2): committed `artifacts/phase-f/` was
generated at `e0d8e9b`, before Phase G changed `privacy/behavior.py`; the current code reports
3 fewer informational `persistence` findings. H.3 touches no privacy code; the historical
artifact was not overwritten. Phase D/E/G runners were run without `--write`; no committed
D–G artifact changed.

## 11. Known limitations

- H.3 inherits every H.2 rule; no corpus target is ELIGIBLE, so no real-world APK is
  transformed (the rules were not relaxed).
- Verification is static (rebuild, diff, re-analysis); the output is not installed or run.
- The output is re-signed with the configured/development key.
- Every disappearing string-pool entry / API reference must be predicted before mutation;
  mispredictions fail (never pass). >50 string removals is refused (`ANALYSIS_INCOMPLETE`);
  URL/host removals fail as `UNEXPECTED_DIFF`.
- A usable no-op noise floor is required (`NOISE_BASELINE_UNAVAILABLE` otherwise); it is
  measured by default with one extra rebuild.
- Output APK bytes are not reproducible (ZIP metadata); result and entry contents are.

## 12. Toolchain

- python: `3.14.7`
- platform: `Linux-7.2.7-200.fc44.x86_64-x86_64-with-glibc2.43`
- apktool: `3.0.3`
- java: `openjdk version "25.0.4.1" 2026-08-18`
- git_head: `4667dce`
- Apktool 3.0.3, Android build-tools 35.0.0 (zipalign 35.0.0, apksigner 0.9), platform android-35
- OpenJDK 25.0.4.1, Python 3.14.7, androguard 4.1.4, pydantic 2.13.5
- pytest 8.4.2, ruff 0.16.9, mypy 1.20.2; Linux 7.2.7 (Fedora 44)

## 13. Schema versions

| Schema | Version |
|---|---|
| H.3 application result (`APPLICATION_SCHEMA_VERSION`) | 1 (new) |
| H.2 planning (`PLANNING_SCHEMA_VERSION`) | 1 (unchanged) |
| H.1 analysis (`SCHEMA_VERSION`) used by H.2/H.3 | 2 (current) |
| Phase E normalization / semantic | 1 / 3 (unchanged) |

Historical H.1 artifacts in this directory (`H1-REFERENCE-ANALYSIS.md`,
`corpus-summary.json`, `synthetic-summary.json`, `validation-summary.md`, generated at
`4013e9e`) are **schema 1** and were not regenerated. H.2 and H.3 use the current H.1
**schema 2** analysis; H.2 artifacts (`h2-*`) are unchanged. H.3 adds only `h3-*` files and
this document.

## 14. Files changed

New:
- `src/apkforge/transformation/application.py`, `executor.py`, `modifier.py`, `dexstate.py`
- `tests/fixtures/h3_apks.py`, `tests/unit/test_phase_h3_transformation.py`,
  `tests/integration/test_phase_h3_transformation.py`
- `build-tests/run_phase_h3_validation.py`
- `artifacts/phase-h/H3-CONTROLLED-TRANSFORMATION.md`, `h3-synthetic-summary.json`,
  `h3-corpus-summary.json`, `h3-validation-summary.md`

Modified:
- `src/apkforge/transformation/__init__.py` (exports), `report.py` (`format_application_report`)
- `src/apkforge/cli/main.py` (`transform --plan/--apply/--output/--noop-baseline/--keep-workspace`;
  `--apply` without `--plan` still exits 2 with the H.2 "planning-only" message)
- `README.md`, `docs/transformation.md`, `docs/architecture.md`, `docs/known-limitations.md`

Unchanged: every H.2 module, H.1 (`apkforge.reference`), Phase D–G code, all H.1/H.2/D–G artifacts.

## 15. Reproduction

```bash
git checkout <this commit>
source tools/env.sh
FORCE_COLOR=3 .venv-validation/bin/python -m pytest -q
.venv-validation/bin/python -m pytest -q tests/unit/test_phase_h3_transformation.py tests/integration/test_phase_h3_transformation.py
.venv-validation/bin/python build-tests/run_phase_h3_validation.py all --write   # ~25 min
.venv-validation/bin/python build-tests/run_phase_d_validation.py
.venv-validation/bin/python build-tests/run_phase_e_validation.py baseline        # ~20 min
.venv-validation/bin/python build-tests/run_phase_f_validation.py --output-dir work/h3-regression/phase-f
# Phase G: run run_phase_g_validation() with ARTIFACTS_DIR redirected (see work/h3-regression/run_g.py)
```
