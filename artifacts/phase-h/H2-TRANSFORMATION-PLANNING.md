# Phase H.2 — Transformation Eligibility & Deterministic Planning

> H.2 determines whether a proposed transformation is supported by the available static
> evidence and produces a deterministic plan. It does not apply the transformation and does
> not establish that the target behavior is malicious.

## 1. Starting point

- Starting commit: `4013e9e` (Phase H.1), working tree clean at start.
- Toolchain: Python 3.14.7, Apktool 3.0.3, OpenJDK 25.0.4.1, Linux 7.2.7 (Fedora 44).
- The validation runs were executed on the uncommitted H.2 tree on top of `4013e9e`
  (`git_head` in the summaries therefore reads `4013e9e`).

## 2. Implementation summary

| Module | Role |
|---|---|
| `apkforge/transformation/models.py` | `EligibilityState`, `DecisionReason` (+ `REASON_STATES`, one state per code), requirement checks, `TargetEvidenceSummary`, `TransformationPlan`, `TransformationDecision`, `PlanningResult` |
| `catalog.py` | `H-TRANS-001` (remove isolated class), `H-TRANS-002` (remove isolated method) — specifications only, no executor |
| `targets.py` | parsing (`com.x.A`, `Lcom/x/A;`, `com.x.A->m(I)V`) and resolution; names are never guessed |
| `selector.py` | `TargetEvidenceSelector` (lookup tables built once per H.1 result) -> `TargetEvidenceSet` |
| `eligibility.py` | `EligibilityEvaluator`: completeness-respecting rules, reflection/native/manifest/resource policies, method-shape and override analysis |
| `conflicts.py` | overlapping requests in one set |
| `planner.py` | `TransformationPlanner`, `TransformationPlanningService.plan / plan_from_result` |
| `report.py` | Markdown report |
| `cli/main.py` | `apkforge transform APK -t ID --target T [--dry-run] [--json] [--report] [--verbose]`; `--apply` exits 2 |

H.1 change (additive, schema 1 -> 2): the smali indexer now records per class the access
flags, interfaces, class annotations, file state, duplicate definitions and method
declarations (name, proto, flags, method annotations, line). Existing evidence records are
unchanged; compact JSON omits the method lists. Two raw index accessors were added
(`ReferenceIndex.evidence_targeting`, `string_values`). Committed H.1 artifacts (schema 1)
were **not** regenerated. Risk/reversibility reuse the Phase D enums; no second
modification engine exists.

## 3. Eligibility model

States: `ELIGIBLE`, `CONDITIONALLY_ELIGIBLE`, `REFUSED`, `UNSUPPORTED`, `UNDETERMINED`.
Every reason code maps to exactly one state; the strongest present state decides
(`REFUSED > UNSUPPORTED > UNDETERMINED > CONDITIONALLY_ELIGIBLE`), and `ELIGIBLE` requires
no reasons and every precondition `SATISFIED`. A precondition relying on absence is
satisfied only by `ABSENCE_ESTABLISHED` (nothing observed + relevant components COMPLETE);
`ABSENCE_NOT_ESTABLISHED` and `ONLY_INDIRECT_EVIDENCE` block. 41 reason codes are
documented in `docs/transformation.md`. The only `CONDITIONALLY_ELIGIBLE` condition is
`KOTLIN_METADATA_UPDATE_REQUIRED` (method removal from a class carrying `kotlin.Metadata`),
emitted as an unsatisfied plan condition — never an approval.

## 4. H-TRANS-001 results (synthetic, real APKs)

| Case | Fixture | Result | Reasons |
|---|---|---|---|
| isolated class | f01 B, f03 C | ELIGIBLE (plan) | — |
| caller | f02 B | REFUSED | CLASS_CALLER_PRESENT, TYPE_REFERENCE_PRESENT |
| multiple callers | f03 B (A and C) | REFUSED | CLASS_CALLER_PRESENT (2 source classes) |
| method / field ref | f04 B / f05 B | REFUSED | METHOD_CALLER_PRESENT / FIELD_REFERENCE_PRESENT |
| constructor | f06 B | REFUSED | CONSTRUCTOR_REFERENCE_PRESENT |
| const-class | f07 B | REFUSED | CONST_CLASS_REFERENCE_PRESENT |
| string naming class | f08 B | UNDETERMINED | STRING_REFERENCE_UNRESOLVED (indirect) |
| reflection resolved | f09 B | REFUSED | REFLECTION_TARGET_PRESENT |
| reflection unresolved | f09 C | UNDETERMINED | REFLECTION_TARGET_UNKNOWN |
| native method | f10 B | UNSUPPORTED | NATIVE_METHOD_DECLARED (+ NATIVE_DEPENDENCY_UNKNOWN) |
| native code present | f11 B | UNDETERMINED | NATIVE_DEPENDENCY_UNKNOWN |
| manifest component | f12 B (service), C (receiver) | REFUSED | MANIFEST_COMPONENT_REFERENCE |
| resource (layout tag) | f13 B | REFUSED | RESOURCE_REFERENCE_PRESENT |
| resource textual | f13 C | UNDETERMINED | RESOURCE_TEXTUAL_MATCH |
| incomplete resources | f14 B | UNDETERMINED | RESOURCE_ANALYSIS_INCOMPLETE |
| incomplete DEX (unit) | f01 + missing classes2 | UNDETERMINED | DEX_ANALYSIS_INCOMPLETE |
| missing target | f01 Missing | REFUSED | TARGET_NOT_FOUND |
| ambiguous target | g03 C (2 DEX files) | REFUSED | TARGET_AMBIGUOUS |

## 5. H-TRANS-002 results

| Case | Target | Result | Reasons |
|---|---|---|---|
| isolated method | g01 D->helper()V, E->own()V (also recursive, private, overload with proto: unit) | ELIGIBLE (plan) | — |
| direct caller | D->used()V | REFUSED | METHOD_CALLER_PRESENT |
| multiple callers | D->shared()V (A and F) | REFUSED | METHOD_CALLER_PRESENT |
| call through subclass owner | D->sutil()V (`invoke-static F->sutil`) | REFUSED | METHOD_CALLER_PRESENT |
| reflection target | g02 D->secret()V | REFUSED | REFLECTION_TARGET_PRESENT |
| unresolved reflection | f09 C->bar()V | UNDETERMINED | REFLECTION_TARGET_UNKNOWN |
| interface method | I->run()V | UNSUPPORTED | INTERFACE_METHOD, ABSTRACT_METHOD |
| override / overridden | E->run()V, F->helper2()V / D->helper2()V | UNSUPPORTED | METHOD_OVERRIDES / METHOD_OVERRIDDEN |
| unresolved supertype | H->handle()V (extends android.app.Activity) | UNDETERMINED | OVERRIDE_RELATIONSHIP_UNRESOLVED |
| native method | f10 B->nativeCall(I)I | UNSUPPORTED | NATIVE_METHOD |
| constructor / clinit (unit) | B-><init>()V / A-><clinit>()V | UNSUPPORTED | CONSTRUCTOR_METHOD / CLASS_INITIALIZER |
| enum values(), readResolve | N, D | UNSUPPORTED | ENUM_IMPLICIT_METHOD, SERIALIZATION_HOOK_METHOD |
| runtime annotation | J->js()V (@JavascriptInterface) | UNDETERMINED | ANNOTATION_DRIVEN_ACCESS_POSSIBLE |
| onClick shape (unit) | D->onClick(View)V | UNDETERMINED | RESOURCE_METHOD_REFERENCE_NOT_ANALYZED |
| Kotlin metadata | K->k()V | CONDITIONALLY_ELIGIBLE (plan + condition) | KOTLIN_METADATA_UPDATE_REQUIRED |
| ambiguous overloads | D->over | REFUSED | TARGET_AMBIGUOUS |
| incomplete analysis (unit) | missing classes2 / PARTIAL defining file | UNDETERMINED | DEX_ANALYSIS_INCOMPLETE, TARGET_DEFINITION_INCOMPLETE |

## 6. Synthetic test results

- `build-tests/run_phase_h2_validation.py synthetic`: **37/37 cases PASS** over 17 real
  APKs (14 H.1 + 3 H.2 fixtures), each planned twice with identical JSON, no APK changed,
  no workspace left behind (`h2-synthetic-summary.json`). Outcomes: 4 ELIGIBLE,
  1 CONDITIONALLY_ELIGIBLE, 17 REFUSED, 7 UNSUPPORTED, 8 UNDETERMINED.
- `tests/unit/test_phase_h2_transformation.py`: 78 passed (incl. conflicts, completeness
  propagation, decode failure -> UNDETERMINED, no filesystem mutation, Markdown report).
- `tests/integration/test_phase_h2_transformation.py`: 9 passed (real APKs, CLI JSON with
  `FORCE_COLOR=3` ANSI-free and byte-identical across runs, `--apply` -> exit 2, usage
  errors, `.md`/`.json` reports, input SHA preserved, decode workspace removed).

## 7. 9-APK planning results (read-only)

Targets per APK (deterministic): up to 5 manifest component classes, classes inside a
Phase F tracker-rule package signature (only Fennec matched: 6), 20 evenly spaced classes
(H-TRANS-001) and the first ordinary method of each (H-TRANS-002); plus one deliberately
conflicting pair. Class and method requests are planned as separate sets so they do not
conflict with each other. Rules were not relaxed.

| APK | SHA-256 (12) | H.1 | Targets | Plans | ELIGIBLE | COND. | REFUSED | UNSUPPORTED | UNDETERMINED |
|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95 | `e03f79082278` | PARTIAL | 41 | 0 | 0 | 0 | 33 | 6 | 2 |
| com.oF2pks.applicationsinfo_19 | `c0188f5f1f56` | PARTIAL | 39 | 0 | 0 | 0 | 31 | 3 | 5 |
| de.audioattack.openlink_28 | `3d28923f08bd` | PARTIAL | 40 | 0 | 0 | 0 | 32 | 2 | 6 |
| de.danoeh.antennapod_3120295 | `3f43a4337a69` | PARTIAL | 43 | 0 | 0 | 0 | 35 | 4 | 4 |
| eu.siacs.conversations_4218104 | `3fae646e33b5` | PARTIAL | 41 | 0 | 0 | 0 | 32 | 8 | 1 |
| godau.fynn.usagedirect_10 | `c55079192a77` | PARTIAL | 43 | 0 | 0 | 0 | 33 | 6 | 4 |
| io.github.muntashirakon.AppManager_451 | `e1f6ba10812c` | PARTIAL | 41 | 0 | 0 | 0 | 30 | 6 | 5 |
| org.mozilla.fennec_fdroid_1560020 | `27f2951376ca` | PARTIAL | 50 | 0 | 0 | 0 | 40 | 10 | 0 |
| org.schabi.newpipe_1015_cb84069 | `18447bfb1e06` | PARTIAL | 40 | 0 | 0 | 0 | 30 | 8 | 2 |

378 targets, **0 plans**. Every REFUSED decision has observed evidence (callers, type
references, manifest components...) and in nearly every case additionally
`REFLECTION_TARGET_UNKNOWN` / `NATIVE_DEPENDENCY_UNKNOWN` / `RESOURCE_ANALYSIS_INCOMPLETE`,
so none of these APKs could yield an absence-based plan with the current H.1 evidence — the
expected outcome given that every corpus app is PARTIAL in H.1. Most frequent reasons
(decisions): REFLECTION_TARGET_UNKNOWN 339, NATIVE_DEPENDENCY_UNKNOWN 256,
TYPE_REFERENCE_PRESENT 215, RESOURCE_ANALYSIS_INCOMPLETE 204, CLASS_CALLER_PRESENT 198,
METHOD_CALLER_PRESENT 170. Every conflicting pair was REFUSED with
CONFLICTING_TRANSFORMATION; no manifest component was ever planned. Full per-decision data:
`h2-corpus-summary.json`.

## 8. Deterministic-plan validation

- Plan/decision ids = SHA-256 over APK SHA-256, transformation id, normalised target,
  parameters, H.1 and H.2 schema versions; no timestamps, UUIDs or paths.
- Unit: identical JSON across independent analyses, request order does not change plan ids
  or content, target spellings normalise to one id, id changes with the APK SHA.
- Synthetic: every case planned twice through H.1 -> H.2 with identical JSON.
- Corpus: re-planning each APK gave identical JSON (9/9); OpenLink full pipeline
  (decode + H.1 + H.2) twice gave identical JSON.

## 9. Performance

- Planning cost after H.1: 0.01–0.42 s per APK for ~40 targets; selector tables
  0–1.3 s (AppManager). Largest decision JSON ≈ 12.6 KB.
- Regression test `test_planning_is_index_based_and_compact`: 420k evidence records,
  20k classes, 400 decisions in ~2.4 s; `ReferenceAnalysisResult.all_evidence` is patched to
  raise (no full traversal per target); traced peak < 200 MB; a hub class referenced by
  ~100k records still yields a decision < 20 KB.
- Runner max RSS 2266 MB, dominated by H.1 on the largest apps (Fennec/AppManager).

## 10. Phase D–G regression results

| Gate | Result |
|---|---|
| Full pytest (`FORCE_COLOR=3`) | **1082 passed, 10 skipped** (baseline at 4013e9e: 995 passed, 10 skipped; +87 H.2 tests) |
| H.1 synthetic runner (no `--write`) | PASS 14/14 with the schema-2 parser |
| Phase D `run_phase_d_validation.py` | A, B, C verified; D, F expected failures; E dry-run — all as expected |
| Phase E `run_phase_e_validation.py baseline` (no `--write`) | 8 VERIFIED, Fennec UNDETERMINED — same as the recorded baseline |
| Phase F `run_phase_f_validation.py --output-dir work/h2-regression/phase-f` | completed; 102 findings vs 105 in committed `artifacts/phase-f/` (see note) |
| Phase G runner redirected to `work/h2-regression/phase-g` | corpus summary identical to committed `artifacts/phase-g` (timing fields excluded) |
| ruff check / format / mypy (repo-wide) | 517 / 56 / 102 — identical to a clean `4013e9e` worktree; mypy error set identical; all touched files clean |

Phase F evidence drift (pre-existing, not attributed to H.2): the current run reports 3
fewer `persistence` findings (AntennaPod 13->12, Fennec 20->19, NewPipe 13->12; 7->4 by
category, all informational). Committed `artifacts/phase-f/` was generated at `e0d8e9b`
before Phase G changed `privacy/behavior.py`; H.1 recorded the same delta on `ded323f`.
H.2 touches no privacy code. The historical evidence was not overwritten; the current
output lives in `work/h2-regression/phase-f/` (git-ignored, provenance: this run on the
H.2 tree over `4013e9e`). Phase D/E/G runners were run without `--write`; no committed
D–G artifact changed.

## 11. Input SHA preservation

`sha256sum tests/corpus/*.apk` was identical before and after the H.2 corpus run, the
Phase D–G regression chain and the final H.2 run. Every synthetic APK and every
`PlanningResult.original_unchanged` was true. Nothing was rebuilt from the corpus,
signed or installed.

## 12. Limitations

See `docs/known-limitations.md` (Phase H.2) and `docs/transformation.md`: most real-app
decisions are UNDETERMINED by design; override resolution needs supertype definitions (no
Android API database); method names in resources are only covered for the onClick shape;
exact string matches on method names block H-TRANS-002; runtime annotations are treated as
possible dispatch; single-target evaluation (no group removal); plans are not proofs of
runtime safety and say nothing about maliciousness.

## 13. Reproduction

```bash
git checkout <this commit>
source tools/env.sh
.venv-validation/bin/python -m pytest -q
FORCE_COLOR=3 .venv-validation/bin/python -m pytest -q tests/unit/test_phase_h2_transformation.py tests/integration/test_phase_h2_transformation.py
.venv-validation/bin/python build-tests/run_phase_h2_validation.py all --write   # ~8 min
.venv-validation/bin/python build-tests/run_phase_d_validation.py
.venv-validation/bin/python build-tests/run_phase_e_validation.py baseline        # ~20 min
.venv-validation/bin/python build-tests/run_phase_f_validation.py --output-dir work/h2-regression/phase-f
.venv-validation/bin/ruff check src/apkforge/transformation && .venv-validation/bin/mypy src/apkforge/transformation
.venv-validation/bin/apkforge transform tests/corpus/de.audioattack.openlink_28.apk \
    -t H-TRANS-001 --target de.audioattack.openlink.ui.IncognitoActivity --dry-run -v
```

## 14–15. Final commit and working tree

H.2 is committed as a single commit on top of `4013e9e` (the commit that adds this file);
the working tree is clean after the commit (`work/` is git-ignored).
