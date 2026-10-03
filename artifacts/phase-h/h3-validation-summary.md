# Phase H.3 validation summary (controlled transformation)

- Overall: **PASS**
- Run: `20261003T152718Z`

## Toolchain

- python: `3.14.7`
- platform: `Linux-7.2.7-200.fc44.x86_64-x86_64-with-glibc2.43`
- apktool: `3.0.3`
- java: `openjdk version "25.0.4.1" 2026-08-18`
- git_head: `4667dce`

## Synthetic scenarios (PASS)

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

## Corpus (PASS)

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

