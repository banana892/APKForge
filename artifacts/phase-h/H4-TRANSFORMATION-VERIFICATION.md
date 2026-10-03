# Phase H.4 — Transformation Verification Hardening (H-TRANS-001)

> H.4 establishes what APKForge can prove statically about a transformed APK, what it
> cannot, how the toolchain noise floor is measured and how unexpected changes are
> detected. It verifies an H-TRANS-001 output against its original **and** an unmodified
> control rebuild, per verification domain, with explicit completeness. It adds no
> transformation and does not broaden H.3.
>
> **Static verification does not establish that the transformed application is safe,
> malware-free, spyware-free, or functionally correct when executed.**
>
> **APK byte differences between independent rebuilds are not automatically treated as
> transformation differences; the control rebuild establishes the observed toolchain noise
> floor.**

## 1. Starting point

- Starting commit: `563178d` (H.3; H.2 `4667dce`, H.1 `4013e9e`), working tree clean.
- Validation runs were executed on the uncommitted H.4 tree on top of `563178d`
  (`git_head` in the summaries therefore reads `563178d`).

## 2. H.4 commit

The commit that adds this file (see `git log`). H.1, H.2 and H.3 artifacts are not
rewritten; H.4 adds only `h4-*` files and this document under `artifacts/phase-h/`.

## 3. Verification architecture

```text
A original ─── unmodified BuildService round trip ─► B control      A -> B  noise floor
     └──────── H.3 TransformationExecutor ─────────► C transformed  A -> C  observed change
                                                                    B -> C  signal
TransformationVerifier(A, B, C, plan)
  plan: H.3 load_plan + plan id + source SHA-256 + supported transformation -> else UNVERIFIED
  declared changes: decode A, H.3 derivation (class, sole-use strings / API refs, classes.dex)
  A -> B : DiffEngine + Phase E classify_noop_diff -> content fingerprint (measured)
  A -> C : Phase E pair.classify against that fingerprint
  B -> C : Phase E verify_expectations (only the declared change + regenerated v1 signature)
  cross-leg attribution -> NOISE / EXPECTED_TRANSFORMATION / UNEXPECTED_CHANGE / UNKNOWN
  apksigner (C, signer of B), DEX inventories of A/B/C, H.1 re-analysis of C -> invariants
  per-domain completeness -> status (never stronger than the weakest mandatory domain)
```

| Module (`src/apkforge/transformation/`) | Role |
|---|---|
| `verification.py` | result model (schema 1): `DifferenceClass`, `Completeness`, `TransformationVerificationStatus`, `VerificationDomain`, `ClassifiedDifference`, `DomainReport`, `InvariantCheck`, `LegSummary`, `RebuildRecord`, `TransformationVerificationResult` |
| `verifier.py` | `TransformationVerifier.verify` / `verify_noop`, `domain_of` |
| `experiment.py` | `ControlExperiment.run` (A, B, C + H.3 + H.4), `.noise_floor` (two unmodified rebuilds), `.rebuild_control` |
| `report.py` | `format_verification_report` (Markdown) |
| `cli/main.py` | `apkforge verify ORIGINAL TRANSFORMED --plan PLAN.json (--control B [--built-locally] \| --build-control) [--json] [--report]` |

No comparison, classification, plan-check or expectation logic is duplicated: DiffEngine
compares; Phase E (`classify_noop_diff`, `pair.classify`, `verify_expectations`,
`NoiseFingerprint`) classifies; H.3's `load_plan`, `plan_id_for`, `removal_consequences`,
`strings_removed`, `removal_expectations` and `assess_post_analysis` (factored out of the
H.3 executor/modifier without behaviour change) check the plan, derive the declared
changes and assess the H.1 re-analysis.

**H.3 / H.4 boundary.** H.3 keeps applying, building, signing and its own post-transform
verification and publishes only when that passes. H.3 does not call H.4: H.4 needs a kept
control APK and a separate (third) comparison, and H.3's internal noise measurement
discards its rebuild. Instead both use the same functions, so there are no divergent
implementations; `ControlExperiment` runs H.3 with B as its noise floor and then H.4.
H.4 checks plan identity and source SHA-256 but does not re-run the H.2 eligibility
evaluation (that is H.2/H.3's responsibility).

## 4. Noise-floor methodology

The noise floor is **measured, never assumed**: B is an unmodified BuildService round trip
of A with the same toolchain and key. `classify_noop_diff(A -> B)` classifies every A -> B
difference with the documented Phase E rules and records each accepted difference with its
content (SHA-256 before/after, certificate fingerprints, exact detail) in a
`NoiseFingerprint`. An A -> C difference is noise only if that fingerprint holds the same
difference with the same content (v1 signature files: same path and kind; certificate:
same original certificate and C signed with B's certificate). A path-rule match with
different content is `UNEXPECTED_CHANGE`. No new noise rule was added: every accepted rule
is a Phase E rule that the control rebuild exhibits for this APK.

A change that every rebuild makes (a faulty toolchain) is not absorbed: Phase E marks it
unexpected in A -> B, the control is `NOT_EQUIVALENT` and the verification `UNVERIFIED`
(unit test `test_unusable_control_is_unverified`; observed in practice when a build fault
was first injected into every build).

## 5. Control rebuild methodology

- B and C always use separate output paths under the experiment directory; A is never
  written and its SHA-256 is compared before and after every verification.
- B must be structurally valid, and A -> B must be `EQUIVALENT` / `EQUIVALENT_WITH_RESIDUE`
  (or a content-aware `BASELINE_PARTIAL`) with the same toolchain identity; otherwise H.4 is
  `UNVERIFIED` and classifies nothing.
- `ControlExperiment.noise_floor` builds two independent controls B1, B2 and verifies B2
  against A with B1 as control (`verify_noop`): case 3 and the corpus experiment.

## 6. Semantic verification

| H.4 class | Condition |
|---|---|
| `NOISE` | Phase E `REBUILD_NOISE`; the control shows the same difference with the same content (v1 signature: same path/kind); B and C agree on it |
| `EXPECTED_TRANSFORMATION` | declared (Phase E `EXPECTED_MODIFICATION` / `PLANNED_ENTRY`) **and** present in the B -> C signal |
| `UNEXPECTED_CHANGE` | Phase E `UNEXPECTED` |
| `UNKNOWN` | Phase E `UNKNOWN`, or the legs disagree (declared but absent from the signal, noise not reproduced by the control, B and C differ where C equals A) |

Each difference records: leg, Phase E class and rule, `in_control` (`same_content`,
`different_content`, `absent`), `in_signal`, `attributable`, reason — i.e. *observed* →
*exists in the unmodified rebuild?* → *attributable to the transformation?* → *still
unexplained?*

Invariants (H-TRANS-001): `plan_integrity`, `control_rebuild_equivalent`,
`target_defined_before` (A and B), `target_absent_after` (DEX inventory of C and H.1),
`exactly_one_class_removed` and `no_other_class_changed` on **both** A -> C and B -> C,
`class_count` (−1), `h1_reference_state`, `declared_changes_observed` (both legs),
`no_unexpected_change`, `no_unclassified_difference`, `signature_verified`,
`original_unchanged`.

## 7. Verification domains

| Domain | Phase E comparators (all three legs) | Extra | What is compared |
|---|---|---|---|
| dex | dex, strings | H.1 re-analysis (DEX COMPLETE, no reference) | classes, methods (code hash), fields, string pool, framework API refs |
| manifest | identity, manifest, manifest_tree, permissions, components, intent_filters | | decoded manifest tree; components, permissions, intent filters |
| resources | resources, resource_table | | content hash per `res/` entry and `resources.arsc` (not decoded) |
| assets | assets | | content hash per `assets/` entry |
| native | native | | content hash + ELF metadata; **native code is not analysed** |
| archive | files, embedded | | entries added/removed/changed by content; ZIP metadata and entry order recorded as packaging |
| signing | certificate | apksigner verify of C with B's signer | certificate identity; v1 signature files path-only between B and C |
| endpoints | network | | URLs, domains, IPs extracted statically |

Signing: the original -> transformed certificate change is attributed to re-signing because
the *same* change occurs in the unmodified control and B and C share one certificate
(`resigned_by_apkforge: true`), not because "signatures always change".

## 8. Completeness semantics

Per domain, the weakest comparator status over the three legs: complete → `COMPLETE`;
`partial` / `not_comparable` → `PARTIAL`; `undetermined` / missing → `UNKNOWN`; leg not
run → `NOT_ANALYZED`; DEX additionally requires a sufficient H.1 re-analysis, signing a
conclusive apksigner result. All eight domains are mandatory for H-TRANS-001; the overall
completeness is the weakest mandatory domain.

| Status | Rule |
|---|---|
| `VERIFIED` | all mandatory domains COMPLETE, all invariants pass, every difference NOISE or EXPECTED_TRANSFORMATION |
| `VERIFIED_WITH_LIMITATIONS` | as VERIFIED but ≥ 1 mandatory domain PARTIAL; each listed as `[domain] PARTIAL: reason` |
| `UNVERIFIED` | not performable (plan invalid / foreign / H-TRANS-002, B or C missing or invalid, control not a usable noise floor, declared changes not derivable) |
| `FAILED` | any UNEXPECTED_CHANGE, failed invariant, or changed original |
| `UNKNOWN` | a mandatory domain UNKNOWN / NOT_ANALYZED or an unclassified difference |

Precedence FAILED > UNVERIFIED > UNKNOWN > VERIFIED_WITH_LIMITATIONS > VERIFIED; no
numerical score. A re-encoded `resources.arsc` stays PARTIAL even when byte-identical to
the control (stricter than the Phase E matrix, which treats content-assured noise as
covered): byte identity with B is established, semantic identity with A is not.

## 9. Synthetic results

`build-tests/run_phase_h4_validation.py synthetic` (fixtures: `tests/fixtures/h3_apks.py`
published v2/v3-only by a separate publisher key, plus `tests/fixtures/h4_apks.py`):
**17/17 cases PASS**, every fixture SHA-256 unchanged, no workspace left behind.

| Case | H.2 | H.3 | Expected H.4 | H.4 | Completeness | H.4 s |
|---|---|---|---|---|---|---|
| 1 clean | ELIGIBLE | VERIFIED | VERIFIED | VERIFIED | COMPLETE | 3.5 |
| 2 repeated | ELIGIBLE | VERIFIED | VERIFIED | VERIFIED | COMPLETE | 3.4 |
| 3 natural build noise (B2 vs B1) | - | - | VERIFIED | VERIFIED | COMPLETE | 0.5 |
| 4a H.3 faulty mutation (B and C removed) | - | FAILED / UNEXPECTED_MUTATION | UNVERIFIED (nothing built) | UNVERIFIED | NOT_ANALYZED | 1.2 |
| 4b other class removed (late fault) | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 3.8 |
| 4c other class modified | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 3.3 |
| 5 resource modified | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | PARTIAL | 3.7 |
| 6 manifest modified | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 3.3 |
| 7a native library added | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | UNKNOWN | 3.2 |
| 7b native library modified (no plan) | UNSUPPORTED | - | FAILED | FAILED | COMPLETE | 0.6 |
| asset added | - | FAILED / UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 3.4 |
| 8a strings truncated | - | - | UNKNOWN | UNKNOWN | PARTIAL | 3.5 |
| 8b native comparator failed | - | - | UNKNOWN | UNKNOWN | UNKNOWN | 3.8 |
| 8c H.1 re-analysis insufficient | - | - | UNKNOWN | UNKNOWN | UNKNOWN | 3.4 |
| target not removed (no-op as output) | - | - | FAILED | FAILED | COMPLETE | 3.3 |
| re-encoded resource table | ELIGIBLE | VERIFIED | VERIFIED_WITH_LIMITATIONS | VERIFIED_WITH_LIMITATIONS | PARTIAL | 3.4 |
| H-TRANS-002 plan | - | - | UNVERIFIED | UNVERIFIED | NOT_ANALYZED | 0.0 |

Case 1 (positive): exactly one class removed (`com.example.h1.B`, classes 3 → 3 → 2 for
A → B → C); all 15 invariants pass; every domain COMPLETE.

| Leg | Observations | Phase E | Raw entries (content) | ZIP metadata-only | Entry order changed |
|---|---|---|---|---|---|
| original -> control | 4 | rebuild_noise 4 | added 3, unchanged 3 | 3 | yes |
| original -> transformed | 14 | expected 9, planned_entry 1, rebuild_noise 4 | added 3, modified 1, unchanged 2 | 2 | yes |
| control -> transformed | 13 | expected 9, planned_entry 1, rebuild_noise 3 | modified 4, unchanged 2 | 2 | no |

- EXPECTED_TRANSFORMATION (10, all in the signal, absent from the control): `dex_class
  removed com.example.h1.B`, `dex_api_reference removed
  android.os.Looper;->getMainLooper()Landroid.os.Looper`, 7 `dex_string removed` (`B.java`,
  `Landroid/os/Looper;`, `Lcom/example/h1/B;`, `Ljava/lang/String;`, `getMainLooper`,
  `h3-only-in-b`, `stamp`), `file modified classes.dex` (planned entry). Identical to the
  declarations H.3 made before mutation.
- NOISE (7, all signing): certificate (`certificate_replaced`, control `same_content`);
  `META-INF/APKFORGE.RSA|.SF|MANIFEST.MF` added A -> C (control: same path, content a
  function of the other entries) and modified B -> C (regenerated because `classes.dex`
  changed; apksigner verifies C with B's signer).

Case 2: plan id identical, `comparable()` verification results identical, transformed
entry content identical, APK bytes **not** identical. Case 3: B1/B2 APK bytes differ, entry
content identical, accepted-noise fingerprints identical, 0 B1 -> B2 observations, 6
metadata-only entries.

## 10. Unexpected-change tests

Faults were injected into the *transformed* build only (after H.3's mutation and source
checks, so the output is built, aligned and signed; the control stays EQUIVALENT). In every
case H.3 refused to publish (`UNEXPECTED_DIFF`) and H.4 independently rejected the built
APK with the change attributed to exactly the faulty domain, never reproduced by the
control:

| Fault | H.4 UNEXPECTED_CHANGE |
|---|---|
| other class removed | `[dex] dex_class removed com.example.h1.C` (+ its strings) |
| other class modified | `[dex] dex_class modified com.example.h1.C` |
| resource modified | `[resources] file modified resources.arsc` (control: different content) |
| manifest modified | `[manifest] uses_permission added android.permission.INTERNET`, `file modified AndroidManifest.xml` |
| native library added | `[native] native_library added lib/arm64-v8a/libinjected.so`, `native_abi`, file |
| native library modified (no plan) | `[native] native_library modified lib/arm64-v8a/libh3native.so`, file |
| asset added | `[assets] file added assets/injected.txt` |
| nothing removed | invariants `target_absent_after`, `declared_changes_observed` FAILED |

Native: no ELIGIBLE plan exists for an APK with a native library (H.2:
`NATIVE_DEPENDENCY_UNKNOWN` / `NATIVE_METHOD_DECLARED`), so a *modified* existing library is
demonstrated with the plan-less control experiment. Detection is by content hash and ELF
metadata; the code is not interpreted. For the injected unparsable `.so` the native
inspector reported warnings, so the domain is UNKNOWN as well as FAILED — incompleteness
is reported, not hidden.

## 11. Real corpus results

`run_phase_h4_validation.py corpus`: H.1 + the H.2 class targets of the H.2/H.3 validation
→ **226 targets, 0 ELIGIBLE, 0 transformations** (rules not relaxed; identical to H.3), and
the H.4 noise-floor experiment per APK (B1, B2, `verify_noop(A, B1, B2)`):

| APK | SHA-256 (12) | ELIGIBLE | Control no-op (B1/B2) | Bytes equal | Content equal | H.4 | Non-complete | H.1 s | H.4 s |
|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95 | `e03f79082278` | 0 | EQUIVALENT_WITH_RESIDUE ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 18.7 | 157.3 |
| com.oF2pks.applicationsinfo_19 | `c0188f5f1f56` | 0 | EQUIVALENT_WITH_RESIDUE ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 1.1 | 7.5 |
| de.audioattack.openlink_28 | `3d28923f08bd` | 0 | EQUIVALENT ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 1.3 | 8.9 |
| de.danoeh.antennapod_3120295 | `3f43a4337a69` | 0 | EQUIVALENT_WITH_RESIDUE ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 39.0 | 262.6 |
| eu.siacs.conversations_4218104 | `3fae646e33b5` | 0 | EQUIVALENT ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 34.9 | 238.9 |
| godau.fynn.usagedirect_10 | `c55079192a77` | 0 | EQUIVALENT ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 24.7 | 132.3 |
| io.github.muntashirakon.AppManager_451 | `e1f6ba10812c` | 0 | EQUIVALENT_WITH_RESIDUE ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 125.0 | 712.6 |
| org.mozilla.fennec_fdroid_1560020 | `27f2951376ca` | 0 | UNDETERMINED ×2 | no | yes | UNKNOWN | resources, archive (embedded partial) | 120.0 | 906.8 |
| org.schabi.newpipe_1015_cb84069 | `18447bfb1e06` | 0 | EQUIVALENT ×2 | no | yes | VERIFIED_WITH_LIMITATIONS | resources | 41.8 | 252.6 |

- No unexpected or unknown difference on any APK; 42–2518 differences per APK, all NOISE
  reproduced by the control with identical content.
- Every APK: two independent rebuilds have different APK bytes but byte-identical entry
  contents — the measured basis for not treating byte differences as changes.
- The only limitation on 8 APKs is `[resources] PARTIAL`: `resources.arsc` is re-encoded
  by AAPT2; B1 and B2 are byte-identical there but its entries are not compared
  semantically. Fennec stays UNKNOWN (its no-op diff is UNDETERMINED: embedded inspector
  warnings), consistent with Phase E.
- Max RSS 2247 MB.

## 12. SHA preservation

- `sha256sum tests/corpus/*.apk` before all runs equals the value after all runs
  (`work/h4-corpus-sha-before.txt`), and the corpus run recorded
  `corpus_sha256_unchanged: true` with per-APK before/after hashes.
- Every H.4 result records `source_apk_sha256` and `source_apk_sha256_after`
  (`original_unchanged`); every synthetic case re-checked every fixture on disk.
- Control and transformed rebuilds are always written to separate paths; passing the
  original as its own control or output is refused (`UNVERIFIED`).

## 13. Phase D–G regression

| Gate | Result |
|---|---|
| Full pytest (`FORCE_COLOR=3`) | **1194 passed, 10 skipped, 0 failed** (H.3 baseline 1135 / 10; +59 H.4 tests) |
| Phase D `run_phase_d_validation.py` | A, B, C verified; D, F expected failures; E dry-run — all as established |
| Phase E `run_phase_e_validation.py baseline` (no `--write`) | 8 VERIFIED, Fennec UNDETERMINED — the established baseline (AntennaPod `manifest_reference_inlined` drift note as already recorded in `artifacts/phase-e`) |
| Phase F `--output-dir work/h4-regression/phase-f` | 102 findings vs 105 committed; persistence 7 → 4 — the known pre-existing drift, identical to the H.3 regression run |
| Phase G (redirected to `work/h4-regression/phase-g`) | `corpus-summary.json` identical to committed `artifacts/phase-g` (timing fields excluded) |
| ruff check / format / mypy (repo-wide) | 517 / 56 / 102 — identical to a clean `563178d` worktree; all touched files clean |

## 14. H.1 / H.2 / H.3 regression

| Gate | Result |
|---|---|
| H.1 `run_phase_h1_validation.py all` (no `--write`) | PASS; corpus analysis states, component states, class counts and evidence counts identical to the committed H.1 artifact for all 9 APKs |
| H.2 `run_phase_h2_validation.py all` (no `--write`) | PASS; all 378 corpus decisions identical to `h2-corpus-summary.json`; 0 plans |
| H.3 `run_phase_h3_validation.py all` (no `--write`) | PASS; 23 synthetic scenarios as expected (A_positive VERIFIED, K repeat VERIFIED, every refusal/failure with its code); 226 corpus attempts refused, 0 applied |

## 15. Known limitations

- Static only; nothing is installed or executed. No claim about safety or runtime behaviour.
- Real apps: H.2 yields no ELIGIBLE target on the corpus, so H.4 is exercised on real APKs
  only through the noise-floor experiment; no real APK was transformed.
- Re-encoded `res/` binary XML / `resources.arsc`: byte identity with the control is
  established, semantic identity with the original is not (→ at most
  VERIFIED_WITH_LIMITATIONS on every corpus APK).
- Native code is not analysed (hash + ELF metadata only); native modification can only be
  shown without a plan.
- v1 signature files between control and transformed rebuild are accepted by path only;
  their correctness rests on apksigner.
- H.4 does not re-run H.2 eligibility; it verifies conformance of the output to the plan.
- A control built elsewhere is only content-compared with `TOOLCHAIN_UNKNOWN` semantics
  unless `--built-locally` is asserted.
- Entry order and ZIP metadata are recorded, never compared as content.

## 16. Toolchain

- Apktool 3.0.3, Android build-tools 35.0.0 (zipalign 35.0.0, apksigner 0.9), platform android-35
- OpenJDK 25.0.4.1, Python 3.14.7, androguard 4.1.4, pydantic 2.13.5
- pytest 8.4.2, ruff 0.16.9, mypy 1.20.2; Linux 7.2.7 (Fedora 44)
- git_head during validation: `563178d` (+ uncommitted H.4 tree)

## 17. Schema versions

| Schema | Version |
|---|---|
| H.4 verification result (`VERIFICATION_RESULT_SCHEMA_VERSION`) | 1 (new) |
| H.3 application result (`APPLICATION_SCHEMA_VERSION`) | 1 (unchanged) |
| H.2 planning (`PLANNING_SCHEMA_VERSION`) | 1 (unchanged) |
| H.1 analysis (`SCHEMA_VERSION`) | 2 (unchanged) |
| Phase E normalization / semantic | 1 / 3 (unchanged) |
| Phase E verification matrix | 1 (unchanged) |

## 18. Files changed

New:
- `src/apkforge/transformation/verification.py`, `verifier.py`, `experiment.py`
- `tests/fixtures/h4_apks.py`, `tests/unit/test_phase_h4_verification.py`,
  `tests/integration/test_phase_h4_verification.py`
- `build-tests/run_phase_h4_validation.py`
- `artifacts/phase-h/H4-TRANSFORMATION-VERIFICATION.md`, `h4-synthetic-summary.json`,
  `h4-corpus-summary.json`, `h4-validation-summary.md`

Modified:
- `src/apkforge/transformation/executor.py` (`assess_post_analysis` extracted; public
  aliases `PlanRefusal`, `plan_id_for`, `removal_consequences`), `modifier.py`
  (`strings_removed`, `removal_expectations` extracted) — no behaviour change (H.3 tests and
  runner unchanged and passing)
- `src/apkforge/transformation/__init__.py` (exports), `report.py`
  (`format_verification_report`)
- `src/apkforge/cli/main.py` (`verify --plan --control/--build-control`)
- `README.md`, `docs/transformation.md`, `docs/architecture.md`, `docs/known-limitations.md`

Unchanged: H.1 (`apkforge.reference`), every H.2 module, Phase D–G code, all H.1–H.3 and
D–G artifacts. H-TRANS-002 remains planning-only.

## 19. Reproduction

```bash
git checkout <this commit>
source tools/env.sh
FORCE_COLOR=3 .venv-validation/bin/python -m pytest -q
.venv-validation/bin/python -m pytest -q tests/unit/test_phase_h4_verification.py tests/integration/test_phase_h4_verification.py
.venv-validation/bin/python build-tests/run_phase_h4_validation.py all --write   # ~55 min (synthetic ~5 min)
apkforge verify ORIGINAL.apk TRANSFORMED.apk --plan plan.json --build-control --report h4.md
```
