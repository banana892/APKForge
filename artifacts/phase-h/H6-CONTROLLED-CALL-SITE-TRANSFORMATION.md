# Phase H.6 — Controlled Call-Site Transformation (H-TRANS-003)

> **Scope of every claim below.** H.6 performs one static rewrite — the method reference of
> exactly one invocation — and verifies that rewrite with the existing H.1 / Phase E / H.4
> machinery. A VERIFIED result establishes that the defined transformation was performed
> and passed the defined checks. It does **not** establish that behaviour or functionality
> is preserved, that the replacement is semantically equivalent to the original method,
> that privacy improved, or that anything malicious was removed.

Validation run: `20261004T200031Z` (`build-tests/run_phase_h6_validation.py all --write`),
evidence in `h6-synthetic-summary.json`, `h6-corpus-summary.json`,
`h6-validation-summary.md`. Toolchain: Apktool 3.0.3, build-tools 35.0.0 (as H.1–H.5).

## 1. Objective

Establish that APKForge can modify one live invocation in DEX/smali while proving which
invocation changed, why it was eligible, what replaced it, that no other call site,
instruction, method, class or reference changed, and that the result passes the H.4
three-APK verification. H.6 is not a smali patching engine: it has exactly one edit
operation with a fixed contract.

## 2. Architecture (all reused; nothing parallel)

```text
H.1 ReferenceAnalysisService (schema 3: invocation registers + move-result)
  -> H.2 TransformationPlanner: TargetEvidenceSelector.select_call_site
       -> EligibilityEvaluator.evaluate_call_site -> deterministic plan (replace_call_site)
  -> TransformationExecutor (H.3/H.5 executor, dispatch on target kind CALL_SITE)
       plan load / source SHA / plan id / ELIGIBLE / H.1+H.2 re-run = identical plan
       -> consequences declared from the original DEX (call_site_consequences)
       -> ModificationPipeline (Phase D) + ReplaceCallSiteModifier: one-line rewrite,
          exact-mutation proof before build -> BuildService build/align/sign/verify
       -> Phase E expected-vs-actual -> H.1 re-analysis (CallSitePostAnalysis) -> publish
  -> H.4 TransformationVerifier / ControlExperiment (A original, B control, C transformed)
```

No second decode/build/sign pipeline, reference analyser, verifier or mutation
transaction exists. `ReplaceCallSiteModifier` is not in the default modifier catalog
(`apkforge modify` cannot reach it).

### Files changed

| Area | Files |
|---|---|
| H.1 (additive, schema 3) | `reference/models.py`, `reference/smali.py`, `reference/index.py` |
| H.2 | `transformation/models.py`, `targets.py`, `catalog.py`, `selector.py`, `eligibility.py`, `planner.py`, `conflicts.py` |
| Application / H.4 | `transformation/application.py`, `dexstate.py`, `modifier.py`, `executor.py`, `verifier.py`, `verification.py`, `report.py`, `__init__.py` |
| CLI | `cli/main.py` (`--replacement`, help texts) |
| Tests | `tests/fixtures/h6_apks.py` (new), `tests/fixtures/h1_apks.py` (`Fixture.min_sdk`), `tests/unit/test_phase_h6_call_site.py` (new), `tests/integration/test_phase_h6_call_site_transformation.py` (new), two scope assertions in `tests/unit/test_phase_h2_transformation.py` / `test_phase_h3_transformation.py` |
| Runners / docs | `build-tests/run_phase_h6_validation.py` (new), one stale expectation in `build-tests/run_phase_h3_validation.py`, `docs/transformation.md`, this file, `h6-*` |

## 3. Transformation contract (H-TRANS-003)

One `invoke-static` — or one `invoke-direct` of a **private instance** method — is
redirected to a predetermined replacement method that is declared in the same APK with
the **identical descriptor** (for `invoke-direct`: same class, private, non-static).
Opcode, operand registers and the consuming `move-result*` stay as they are. Target
syntax `CALLER@INVOKED[#N]`; replacement in the plan parameter `replacement`.

```text
invoke-static {}, Lcom/example/h1/Source;->getValue()Ljava/lang/String;
  becomes
invoke-static {}, Lcom/example/h1/Replacement;->getValue()Ljava/lang/String;
```

Not implemented (by design): instruction injection, register or control-flow rewriting,
method-body rewriting, hooks, virtual/interface/super/constructor/polymorphic/custom
invocations, framework or library targets, subtype-compatible replacements.

## 4. Eligibility rules

Preconditions: `call_site_exists`, `dex_analysis_complete`, `caller_analysis_complete`,
`caller_modifiable`, `supported_invoke_opcode`, `target_method_resolved`,
`replacement_method_resolved`, `replacement_differs`, `invocation_kind_compatible`,
`argument_types_compatible`, `return_type_compatible`, `register_mapping_consistent`,
`result_mapping_consistent`, `replacement_accessible`, `no_reflection_target`,
`no_dynamic_invocation`, `no_native_boundary`, `no_conflicting_transformation`.
ELIGIBLE requires every one SATISFIED; H.2's existing precedence (REFUSED > UNSUPPORTED >
UNDETERMINED > CONDITIONALLY_ELIGIBLE) decides otherwise. No rule was relaxed for any
corpus APK; there is no force/unsafe/ignore flag.

New reason codes (state): `CALL_SITE_NOT_FOUND`, `CALL_SITE_AMBIGUOUS`,
`CALL_SITE_MULTIPLE_MATCHES`, `CALL_SITE_ALREADY_REPLACED`, `TARGET_METHOD_NOT_FOUND`,
`PARAMETER_INVALID`, `REPLACEMENT_METHOD_NOT_FOUND`, `REPLACEMENT_SIGNATURE_MISMATCH`,
`REPLACEMENT_INACCESSIBLE`, `REGISTER_TYPE_MISMATCH`, `RESULT_TYPE_MISMATCH` (REFUSED);
`UNSUPPORTED_INVOKE_OPCODE`, `CONSTRUCTOR_INVOCATION`, `POLYMORPHIC_INVOCATION`,
`INVOKE_CUSTOM_UNSUPPORTED`, `INVOKE_POLYMORPHIC_UNSUPPORTED` (UNSUPPORTED);
`CALLER_ANALYSIS_INCOMPLETE`, `TARGET_RELATIONSHIP_UNRESOLVED` (UNDETERMINED).
Reused where the concept already existed: `NATIVE_ANALYSIS_INCOMPLETE` →
`NATIVE_DEPENDENCY_UNKNOWN`; `REFLECTION_ANALYSIS_INCOMPLETE`, `ANALYSIS_INCOMPLETE`,
`CONFLICTING_TRANSFORMATION`, `TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS`,
`TARGET_DEFINITION_INCOMPLETE`, `NATIVE_METHOD`, `SYNTHETIC_METHOD`, `ABSTRACT_METHOD`,
`INTERFACE_METHOD`, `REFLECTION_TARGET_*`, `DYNAMIC_CODE_LOADING_PRESENT` keep their H.2
meaning.

## 5. Schema changes

- **H.1 schema 2 → 3** (additive): invocation records gain `registers`,
  `result_register`, `result_instruction`; `invoke-custom` call sites are additionally
  recorded against their bootstrap method (the `UNSUPPORTED_INSTRUCTION` issue stays, the
  file stays PARTIAL — nothing becomes more complete); `ReferenceIndex.invocations_in`.
  Evidence ids are unchanged (the new fields are not identity fields). Old results carry
  `None` and are treated as `CALLER_ANALYSIS_INCOMPLETE`, never as compatible. Historical
  H.1 artifacts keep their recorded schema numbers and are not reinterpreted.
  Consequence: `analysis_schema` is part of every plan id, so plans written against
  schema 2 are refused as `PLAN_INVALID` by the executor and must be re-planned.
- **H.2** (additive): `TargetKind.CALL_SITE`; `TransformationTarget` gains
  `invoked_class/name/descriptor` and `occurrence` (None — and omitted from JSON — for
  class/method targets); planning schema unchanged.
- **Application** (additive): `MutationRecord` gains the `REPLACE_CALL_SITE` fields
  (`call_site`, `source_line`, `original_instruction`, `replacement_instruction`,
  `changed_lines`, `removed_invocations`, `added_invocations`, `other_changes`);
  `CallSitePostAnalysis`; `TransformationApplicationResult.call_site_analysis`;
  `TransformationVerificationResult.call_site_post_analysis`; DEX domain fact
  `methods_code_changed`.

## 6. Plan and mutation model

The plan's single `replace_call_site` change carries `dex`, `caller_class`,
`caller_method`, `source_line`, `evidence_id`, `opcode`, `registers`, `register_count`,
`result_instruction`, `result_register`, `original`, `replacement`, `occurrence`,
`occurrences_in_caller`, `invocations_in_caller`, `expected_mutation_count` = 1. The plan
id hashes APK SHA-256 + transformation id + normalised target + parameters (normalised
replacement) + schemas; both spellings of the replacement give the same id.

Before mutation (apply refuses otherwise): source SHA, plan schema, recomputed plan id,
ELIGIBLE, H.1+H.2 re-run gives an identical plan, the invocation at the planned line
re-parsed with the H.1 parser has the planned opcode/registers/result/occurrence, the
line has the single-reference form, census matches. After the one-line rewrite and
**before any build**: exactly the planned line changed; exactly one invocation record
changed (original → replacement, same opcode, registers, result); no other evidence of the
file and no other smali file changed; census unchanged — otherwise `UNEXPECTED_MUTATION`
(FAILED, nothing built or published).

## 7. Synthetic fixtures (real APKs, published like real apps)

`h6_callsite` (positive + most negatives), `h6_callsite_alt` (distinct SHA),
`h6_reflection`, `h6_native` (bundled .so + native replacement), `h6_dynamic` (minSdk 26:
invoke-polymorphic, invoke-custom). All built with BuildService, round-tripped, signed v2/v3
by a separate publisher key. All input SHA-256 unchanged after the run.

### Positive results (H.6 application + H.4 control experiment)

| Shape | Plan id | Changed line (before → after) | H.6 | H.4 | Completeness |
|---|---|---|---|---|---|
| static, object result | `plan-c570a0cb478b730af56e` | 64: `…Source;->getValue()…` → `…Replacement;->getValue()…` | VERIFIED | VERIFIED | COMPLETE |
| primitive + wide + object args, primitive result | `plan-b617a0c3da083308b172` | 28: `invoke-static {p0, p1, p2, p3}, …Source;->compute(IJLjava/lang/String;)I` → `…Replacement;->compute…` | VERIFIED | VERIFIED | COMPLETE |
| private instance (`invoke-direct`) | `plan-c1f03b22912020c8ba75` | 116: `…A;->secret()…` → `…A;->secretAlt()…` | VERIFIED | VERIFIED | COMPLETE |
| second of two identical calls (`#2`) | `plan-b5e91d2b7d474a20303f` | 94 only (call #1 at line 90 untouched) | VERIFIED | VERIFIED | COMPLETE |

Each: 1 call site changed, 1 changed line, 0 other changes; H.1 re-analysis: invocation
sequence changed only at the planned position (`[0]`, `[0]`, `[0]`, `[1]`), original
calls N → N−1, replacement 0 → 1, no other reference or declaration change. H.4: 0
unexpected, 0 unknown; signal = `dex_class modified A` + `file modified classes.dex` +
the predicted framework-API-reference deltas (e.g. `+ Replacement;->getValue()`, and for
the instance case `− A;->secret()` / `+ A;->secretAlt()`, because Phase E's API-reference
extraction includes in-app references whose output contains a framework type); 7 noise
differences, each reproduced by the control rebuild.

## 8. Negative cases (all refused by H.2 and by the executor; nothing written)

| Case | Decision | Reason |
|---|---|---|
| target missing | REFUSED | CALL_SITE_NOT_FOUND |
| caller missing | REFUSED | TARGET_NOT_FOUND |
| target ambiguous (overloaded caller name) | REFUSED | CALL_SITE_AMBIGUOUS |
| multiple matching call sites (no `#N`) | REFUSED | CALL_SITE_MULTIPLE_MATCHES |
| signature mismatch (instance replacement for invoke-static) | REFUSED | REPLACEMENT_SIGNATURE_MISMATCH |
| argument mismatch | REFUSED | REGISTER_TYPE_MISMATCH |
| return-type mismatch | REFUSED | RESULT_TYPE_MISMATCH |
| inaccessible replacement | REFUSED | REPLACEMENT_INACCESSIBLE |
| replacement missing / parameter missing | REFUSED | REPLACEMENT_METHOD_NOT_FOUND / PARAMETER_INVALID |
| replacement is the invoked method | REFUSED | CALL_SITE_ALREADY_REPLACED |
| already transformed APK (H.6's own verified output) | REFUSED | CALL_SITE_ALREADY_REPLACED |
| conflicting set (+ H-TRANS-002 removing the replacement) | REFUSED ×2 | CONFLICTING_TRANSFORMATION (`call_site_overlap`) |
| constructor call | UNSUPPORTED | CONSTRUCTOR_INVOCATION |
| virtual call | UNSUPPORTED | POLYMORPHIC_INVOCATION |
| invoke-polymorphic | UNSUPPORTED | INVOKE_POLYMORPHIC_UNSUPPORTED |
| invoke-custom | UNSUPPORTED | INVOKE_CUSTOM_UNSUPPORTED (+ CALLER_ANALYSIS_INCOMPLETE) |
| native replacement | UNSUPPORTED | NATIVE_METHOD |
| incomplete reference analysis (DEX PARTIAL) | UNDETERMINED | DEX_ANALYSIS_INCOMPLETE |
| unsupported instruction in the caller (malformed/unsupported) | UNDETERMINED | CALLER_ANALYSIS_INCOMPLETE |
| reflection dependency | UNDETERMINED | REFLECTION_TARGET_UNKNOWN |
| native dependency | UNDETERMINED | NATIVE_DEPENDENCY_UNKNOWN |

Unit tests additionally cover tampered H.1 evidence (wrong register count, broken wide
pair, wrong `move-result` kind, missing registers → schema < 3, super/interface opcodes,
invoke-direct of a static method) and a compiler-generated caller (SYNTHETIC_METHOD).

## 9. Fault injection

Mutation faults (patched rewrite hook; all `FAILED / UNEXPECTED_MUTATION` at the mutation
stage, **nothing built, nothing published**): wrong call site (#1 instead of #2), two call
sites, wrong replacement target, replacement with a wrong descriptor, unrelated method in
the same class, unrelated class (another smali file).

Build-time faults (injected into the transformed build only; H.6 refuses to publish and
H.4 reports FAILED in the named domain; control rebuild EQUIVALENT): second call site
(dex), other method (dex), other class (dex), resource (resources), manifest (manifest),
native library (native), asset (assets).

Integrity (all REFUSED before mutation): source SHA mismatch → `SOURCE_SHA_MISMATCH`;
invalid plan id → `PLAN_ID_MISMATCH`; forged plan with an edited replacement →
`PLAN_MISMATCH`; plan rebound to another APK with a recomputed id → `PLAN_NOT_ELIGIBLE`;
call site gone from the decoded workspace after planning → `TARGET_NOT_FOUND`
(pre-transform).

## 10. Reproducibility

Same plan planned twice: byte-identical planning JSON, identical plan id and eligibility.
Same plan applied twice: identical mutation record, identical `CallSitePostAnalysis`,
identical `comparable()` result and identical **APK entry contents**
(`output_content_sha256`). Outer APK bytes differ (`outer_apk_bytes_identical: false`):
ZIP timestamps and signing differ per build, which the project treats as packaging, not
content.

## 11. Real corpus (read-only; eligibility never relaxed)

20 real call sites per APK, sampled deterministically across opcode families (static 8,
direct 3, constructor 2, virtual 4, interface 2, super 1); replacement = another method
of the invoked (else caller) class with the same descriptor and static-ness when one
exists, else a non-existent placeholder. Nothing was chosen to be eligible.

| APK | Targets | ELIGIBLE | COND. | REFUSED | UNSUPPORTED | UNDETERMINED | Applied | Verification | SHA unchanged |
|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95 | 20 | 0 | 0 | 14 | 2 | 4 | 0 | n/a | yes |
| com.oF2pks.applicationsinfo_19 | 20 | 0 | 0 | 16 | 3 | 1 | 0 | n/a | yes |
| de.audioattack.openlink_28 | 20 | 0 | 0 | 14 | 3 | 3 | 0 | n/a | yes |
| de.danoeh.antennapod_3120295 | 20 | 0 | 0 | 16 | 2 | 2 | 0 | n/a | yes |
| eu.siacs.conversations_4218104 | 20 | 0 | 0 | 12 | 3 | 5 | 0 | n/a | yes |
| godau.fynn.usagedirect_10 | 20 | 0 | 0 | 13 | 1 | 6 | 0 | n/a | yes |
| io.github.muntashirakon.AppManager_451 | 20 | 0 | 0 | 11 | 4 | 5 | 0 | n/a | yes |
| org.mozilla.fennec_fdroid_1560020 | 20 | 0 | 0 | 15 | 1 | 4 | 0 | n/a | yes |
| org.schabi.newpipe_1015_cb84069 | 20 | 0 | 0 | 15 | 3 | 2 | 0 | n/a | yes |
| **total** | **180** | **0** | **0** | **126** | **22** | **32** | **0** | | **all 9** |

Reason codes (decisions carrying each): REFLECTION_TARGET_UNKNOWN 160,
NATIVE_DEPENDENCY_UNKNOWN 120, REPLACEMENT_METHOD_NOT_FOUND 117, POLYMORPHIC_INVOCATION 63,
DYNAMIC_CODE_LOADING_PRESENT 20, REFLECTION_ANALYSIS_INCOMPLETE 20,
CONSTRUCTOR_INVOCATION 18, TARGET_METHOD_NOT_FOUND 18, SYNTHETIC_METHOD 13,
REPLACEMENT_SIGNATURE_MISMATCH 7, ABSTRACT_METHOD 2, INTERFACE_METHOD 2,
REPLACEMENT_INACCESSIBLE 2, REFLECTION_TARGET_PRESENT 1, TARGET_RELATIONSHIP_UNRESOLVED 1.
Every corpus APK has unresolved reflection (reflection component PARTIAL), so no real
call site can reach ELIGIBLE: **0 real transformations** — the expected outcome. Every
input APK SHA-256 is recorded in `h6-corpus-summary.json` and was identical after the run.

## 12. H.4 verification results

All four positive shapes: H.4 **VERIFIED**, completeness **COMPLETE**, every mandatory
domain PASSED; new call-site invariants `caller_class_retained`,
`exactly_one_method_body_changed[original->transformed|control->transformed]`,
`no_other_change[…]`, `h1_call_site_state` all PASSED. All seven build-time faults:
**FAILED** in the injected domain. CLI `apkforge verify ORIG OUT --plan P --build-control`
on an H-TRANS-003 output: VERIFIED / COMPLETE.

## 13. Status vocabulary (kept distinct)

| State | Meaning in H.6 |
|---|---|
| planned | an H.2 decision exists (any eligibility) |
| eligible | H.2 decided ELIGIBLE and emitted a plan (nothing applied) |
| applied | the executor rewrote the line and built (status BUILT reached) |
| verified | H.6 status VERIFIED (every matrix row PASS, output published) and/or H.4 VERIFIED |
| verified with limitations | H.4 VERIFIED_WITH_LIMITATIONS (a mandatory domain PARTIAL) — not observed for H.6 fixtures |
| unverified | H.4 UNVERIFIED (plan/rebuild/noise floor unusable) |
| failed | H.6 FAILED (UNEXPECTED_MUTATION, UNEXPECTED_DIFF, …) or H.4 FAILED |

Synthetic: 4 eligible / 4 applied / 4 verified (H.6 and H.4). Corpus: 180 planned /
0 eligible / 0 applied.

## 14. Limitations

- Type-level compatibility only (identical descriptor and invocation kind); no semantic
  equivalence, behaviour-preservation or safety claim.
- Only `invoke-static` and private `invoke-direct`; both methods declared in the APK.
- Requires COMPLETE DEX analysis, no unresolved reflection, no dynamic code loading and no
  unanalysed native code; real apps typically fail these (corpus: 0 eligible).
- The H.1 post-analysis compares the original's and the output's decoded smali exactly; an
  APK whose decode is not a rebuild fixed point would fail verification (conservative).
- Observed during H.6 and fixed in a follow-up commit: androguard prints method
  descriptors with spaces (`(I J Ljava/lang/String;)I`) and the DEX inspector's
  `_parse_params` turned each space into a parameter, so Phase E keyed multi-parameter
  methods as `f(int, ,long)V` while `dexstate.method_key()` gave `f(int,long)V`. H.5 removal
  of a >=2-parameter method therefore failed safe (declared change not observed). The parser
  now skips whitespace; the H.5 fixture `h5_multiparam` removes
  `combine(ILjava/lang/String;J)` and verifies. H.6 was never affected (it compares
  descriptors with spaces removed and declares only the caller method name).

## 15. Security / safety boundaries

Planning never mutates; application requires an explicit plan and `--apply`; no
implicit plan+apply, no `--force`/`--unsafe`/`--ignore-checks`; the source APK is never
written (SHA compared before/after every run); outputs are published atomically only when
every check passed; the modifier is not reachable through `apkforge modify`.

## 16. Regression results

| Suite | Result |
|---|---|
| full pytest | **1353 passed, 10 skipped** (baseline at 5d9eb9d: 1229 passed / 10 skipped; +124 H.6 tests, see §17) |
| ruff check (touched files) / format check | clean / clean; repo-wide ruff 517 = baseline |
| mypy `src/apkforge` | 102 errors = baseline, no new error |
| Phase D runner | scenarios A–F as expected |
| Phase E baseline / openlink | 8 VERIFIED + Fennec UNDETERMINED (known, resource table not comparable) / PASS (all 15 scenarios as expected) |
| Phase F runner | completed (output redirected to work/) |
| Phase G runner | completed (artifact dirs redirected to work/) |
| H.1 / H.2 / H.5 runners | PASS / PASS / PASS |
| H.3 runner | PASS after one documented expectation update (below) |
| H.4 runner | PASS (synthetic cases + corpus noise-floor experiments as before) |
| H.6 runner | PASS |

Changed expectations (contract changes, documented):

1. `test_phase_h2_transformation.py`: `SCHEMA_VERSION == 2` → `3` (H.1 schema 3) and
   catalog `[001, 002]` → `[001, 002, 003]`.
2. `test_phase_h3_transformation.py`: `SUPPORTED_TRANSFORMATIONS` gains `H-TRANS-003`.
3. `run_phase_h3_validation.py` scenario `H_trans_002` (class plan relabelled H-TRANS-002):
   expected `PLAN_ID_MISMATCH` → `PLAN_INVALID`. This expectation was already stale at
   HEAD 5d9eb9d (verified: the untouched H.5 code returns `PLAN_INVALID` because the
   plan holds no `remove_method` change); the run is still refused before any analysis.

No historical baseline or committed H.1–H.5 artifact was regenerated.

## 17. Test inventory

- `tests/unit/test_phase_h6_call_site.py` — 79 tests (schema 3, parsing, determinism,
  every decision class, tampered evidence, conflicts, rewrite/mutation diff, plan loading,
  integrity, CLI usage, reports).
- `tests/integration/test_phase_h6_call_site_transformation.py` — 45 tests on real APKs
  (positive shapes, H.4, refusals, already transformed, conflicts, 6 mutation faults,
  7 build faults, integrity, reproducibility, CLI incl. ANSI-free `--json`).
