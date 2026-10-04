# Phase H.5 — Controlled Isolated Method Transformation (H-TRANS-002)

## 1. Starting commit

H.5 continues from the verified H.4 checkpoint:

- H.1 `4013e9e` — read-only evidence & reference model
- H.2 `4667dce` — eligibility & deterministic planning
- H.3 `563178d` — controlled class transformation (H-TRANS-001)
- H.4 `6e4ae37` — transformation verification hardening

The working tree was clean at `6e4ae37` before H.5 began.

## 2. H.5 implementation commit

`feat(transformation): implement Phase H.5 controlled isolated method transformation`
(this commit). No H.1–H.4 artifact was rewritten; only new code, tests, a runner and this
document were added, plus the small, justified updates to H.3/H.4 tests and the CLI help
that recording "H-TRANS-002 is now applied" requires.

## 3. H-TRANS-002 semantics

`H-TRANS-002 — Remove Isolated Method` removes **exactly one method from exactly one
class**. The containing class and every other method of it are retained. It is the second
narrowly scoped transformation after H-TRANS-001 (remove isolated class).

It does **not** rewrite instructions, patch bodies, rename, change access levels, rewrite
call sites, modify control flow, replace APIs, remove SDKs, touch native code, or edit
resources/manifest/assets. It removes one `.method … .end method` block.

## 4. H.2 plan consumption

H.5 adds **no** eligibility engine. It consumes the existing H.2 plan:

1. the H.2 planner (unchanged) already produces a `remove_method` plan for an ELIGIBLE
   method target;
2. the executor loads the plan, recomputes the source APK SHA-256, recomputes and compares
   the deterministic plan id, confirms `transformation_id == "H-TRANS-002"` and
   `eligibility == ELIGIBLE` (never `CONDITIONALLY_ELIGIBLE`/`REFUSED`/`UNSUPPORTED`/
   `UNDETERMINED`), confirms the plan's target kind is `method`, then **re-runs H.1 + H.2**
   on the source and requires an identical plan before any mutation.

Only `ELIGIBLE` reaches mutation. There is no `--force`, `--unsafe`,
`--ignore-eligibility` or `--skip-verification`. If H.2 says the target is not eligible,
H.5 stops before mutation (`PLAN_NOT_ELIGIBLE`).

## 5. Method identity

The target carries class, method name, parameter types and return type — the project's
existing `TransformationTarget` (`com.example.Target->foo(I)V`). A method without a
descriptor that matches more than one overload is `TARGET_AMBIGUOUS` (H.2). The Phase E
DEX differ identifies a method by `name(param,param)ret` (primitives spelled out in
parameters, e.g. `foo(int)V`; return type left as a descriptor-to-Java value); H.5 derives
that key from the smali descriptor with `dexstate.method_key`, so

```
com.example.Target->foo()V          → foo()V
com.example.Target->foo(I)V         → foo(int)V
com.example.Target->foo(Ljava/lang/String;)V → foo(java.lang.String)V
```

are distinct, and the key H.5 predicts matches the key the differ reports.

## 6. Constructor / initializer restrictions

`<init>` and `<clinit>` are rejected by the existing H.2 rule (`CONSTRUCTOR_METHOD`,
`CLASS_INITIALIZER` → `UNSUPPORTED`), together with abstract, interface, native,
bridge/synthetic, enum `values()`/`valueOf()` and the Java serialization hooks. H.5 adds
no path around this; such targets never produce a plan and never reach mutation.

## 7. Overload handling

An ambiguous method name (no descriptor, several overloads) is `TARGET_AMBIGUOUS`
(`h5_overloads`, target `com.example.h1.B->foo`). Given a descriptor, only that overload is
removed: `h5_overloads` targets `foo(I)V`; after the transformation `foo()V` and
`foo(Ljava/lang/String;)V` remain in the class, and only the `foo(int)V` method key and the
string used exclusively by `foo(I)V` disappear. The surviving overloads keep the shared
method-name string, so it is correctly *not* predicted to be removed.

## 8. Caller / reference requirements

H.2's `no_call_sites` and reflection/annotation/resource rules are authoritative. After the
transformation H.5 re-analyses the output with H.1 and requires **no remaining call site or
resolved reflection** reaching the removed method (`definitive_references == 0`) and no
indirect hint (`indirect_references == 0`), the containing class still defined, and the DEX
and reflection components COMPLETE. H.5 **does not remove callers or repair references**: if
the target is not genuinely isolated, H.2 refuses the transformation.

## 9. Mutation behaviour

`RemoveIsolatedMethodModifier` (never in the default modifier catalog, so unreachable
through `apkforge modify`) runs inside the existing Phase D `ModificationPipeline`:

- **plan** — re-checks the decoded workspace: the class is defined exactly once in the
  planned file, the census matches the analysed APK, the `.method` block exists exactly
  once and is delimited, the class keeps at least one other method, and the predicted
  string-pool removals are Phase-E-enumerable;
- **apply** — removes exactly that one block (the file is **modified**, not deleted), then
  proves, before anything is built, that exactly the target method disappeared, no other
  method was added/removed, no class changed, and the method count went `N → N−1`;
- **verify** — on the rebuilt APK's DEX diff: the target class is modified with
  `methods_removed == [key]`, `methods_added == []`, `methods_modified == []`, and no other
  class or DEX file changed.

The mutation record is `{transformation_id: H-TRANS-002, operation: REMOVE_METHOD, class,
method, descriptor, method_key, count: 1, methods N→N-1, classes unchanged}`.

## 10. H.4 integration

H.5 reuses the H.4 infrastructure (`TransformationVerifier`, `ControlExperiment`) with a
method-removal branch — no second verifier. The expected semantic delta for a method
removal is declared from the original APK and the plan (`method_removal_expectations`):
one `dex_class modified` observation (class retained, `methods_removed == [key]`), plus the
string-pool entries and framework API references used **only** by that method. The verifier
distinguishes:

- expected method removal (the declared `dex_class modified` delta, attributable on the
  control→transformed signal) from
- unexpected class removal, unexpected other-method removal/addition/modification,
  unexpected DEX change, and unexpected resource / manifest / asset / native changes —
  each of which fails verification.

Method-specific invariants: `target_class_retained`, `target_method_absent_after`,
`exactly_one_method_removed[leg]`, `no_other_change[leg]`, `method_count` (N→N−1),
`h1_reference_state` (method absent, no reference, DEX+reflection COMPLETE).

## 11. Noise-floor behaviour

H.4's control-rebuild methodology is retained unchanged: for every positive fixture the
original (A), an unmodified control rebuild (B) and the method-removal rebuild (C) are
produced; the control rebuild measures the toolchain noise floor. A difference is accepted
as NOISE only when the unmodified control reproduces it with the same content (the existing
H.4 rules); nothing is assumed.

## 12. Positive synthetic result

`h5_isolated` — `com.example.h1.B->isolatedStamp()Ljava/lang/String;` (isolated `static`
method using one unique string and one unique framework API). H.2 **independently**
decides `ELIGIBLE`; H.3-style application reaches **VERIFIED** (14/14 matrix rows PASS);
H.4 reaches **VERIFIED / COMPLETE**. Expected delta observed, nothing else:

```
dex_class     modified  com.example.h1.B  (methods_removed = [isolatedStamp()java.lang.String])
dex_string    removed   isolatedStamp, h5-only-in-this-method, getMainLooper,
                        Landroid/os/Looper;, Ljava/lang/String;
dex_api_ref   removed   android.os.Looper;->getMainLooper()Landroid.os.Looper
```

method count `3 → 2`; class count unchanged (`2 → 2`); `bar()V` and `<init>()V` remain.

`h5_overloads` — target `foo(I)V`: **VERIFIED / COMPLETE**; only `foo(int)V` and the
string `h5-only-in-foo-int` are removed; `foo()V` and `foo(java.lang.String)V` remain.

## 13. Negative / fault-injection results

Negative fixtures (H.2 refuses; H.5 respects the decision, no mutation):

| Fixture / target | H.2 decision | reason |
|---|---|---|
| `h5_caller B->callee()V` | REFUSED | METHOD_CALLER_PRESENT |
| `h5_reflection B->isolatedStamp()…` | UNDETERMINED | REFLECTION_TARGET_UNKNOWN |
| `h5_native B->isolatedStamp()…` | UNDETERMINED | NATIVE_DEPENDENCY_UNKNOWN |
| `h5_override B->run()V` | UNSUPPORTED | METHOD_OVERRIDES |
| `h5_override A->run()V` | UNSUPPORTED | METHOD_OVERRIDDEN |
| `h5_interface B->handle()V` | UNSUPPORTED | METHOD_OVERRIDES |
| `h5_interface Iface->handle()V` | UNSUPPORTED | ABSTRACT_METHOD, INTERFACE_METHOD |
| `h5_isolated B-><init>()V` | UNSUPPORTED | CONSTRUCTOR_METHOD |
| `h5_isolated B->doesNotExist()V` | REFUSED | TARGET_NOT_FOUND |
| `h5_overloads B->foo` | REFUSED | TARGET_AMBIGUOUS |

Fault injection (the spec's conceptual label → the concrete code/status H.5 produces):

| Spec fault | Concrete outcome |
|---|---|
| A. Remove wrong method | H.5 `FAILED` `UNEXPECTED_MUTATION` (MUTATION stage, no build) |
| B. Remove two methods | H.5 `FAILED` `UNEXPECTED_MUTATION`, count = 2 |
| C. Remove method and class | H.5 `FAILED` `UNEXPECTED_MUTATION`, removed_classes = [B] |
| D. Modify another method/class | build injected → H.4 `FAILED`, DEX domain FAILED |
| E. Modify resource | build injected → H.4 `FAILED`, resources domain FAILED |
| F. Modify manifest | build injected → H.4 `FAILED`, manifest domain FAILED |
| G. Add native library | build injected → H.4 `FAILED`, native domain FAILED |
| (add asset) | build injected → H.4 `FAILED`, assets domain FAILED |
| H. Leave caller / reference | build injected → H.4 `FAILED`, DEX domain FAILED, method
  post-analysis `definitive_references ≥ 1` |
| I. Target disappears before mutation | H.5 `REFUSED` `TARGET_NOT_FOUND` (PRE_TRANSFORM) |
| J. Source SHA mismatch | H.5 `REFUSED` `SOURCE_SHA_MISMATCH` |
| K. Forged / modified plan | H.5 `REFUSED` `PLAN_ID_MISMATCH` / `PLAN_MISMATCH` |

All faults are rejected; no faulty output is ever published.

## 14. Real corpus result

H.5 was run against the existing 9-APK corpus (`build-tests/run_phase_h5_validation.py
corpus`): H.1 analysis, then H-TRANS-002 planning over the sampled ordinary-method targets
of each APK. Eligibility was **not** relaxed.

- Method targets attempted: **152 (16+17+17+18+16+18+16+19+15 across the 9 APKs)**
- ELIGIBLE: **0**; transformations applied: **0**
- Every input APK byte-identical before and after (SHA-256 recorded per APK)

No real corpus method qualifies as removable under the strict H.2 rules, which is the
expected and acceptable outcome; the synthetic fixtures exercise the positive path.

## 15. SHA preservation

The source APK is never modified in place; `SHA256(source_before) == SHA256(source_after)`
is asserted on every synthetic and corpus run, and the transformed APK is always written to
a separate output path (the executor refuses an output equal to the source).

## 16. D–G regressions

Unchanged. Phase D (A–F behaviour), Phase E (8 VERIFIED, Fennec UNDETERMINED), Phase F
(known drift 102 current / 105 historical; persistence 7 → 4) and Phase G (committed summary
identical apart from timing fields) were not touched by H.5. See §28 of the full suite run.

## 17. H.1–H.4 regressions

- H.1 evidence/analysis behaviour unchanged.
- H.2 corpus decisions unchanged (the planner is unchanged).
- H.3 class-removal positive and negative cases unchanged (one negative tamper case now
  reports `PLAN_INVALID` instead of `PLAN_ID_MISMATCH` because relabelling a `remove_class`
  plan as H-TRANS-002 is now caught by the plan-shape check first — a stricter, correct
  refusal; the class transformation itself is byte-for-byte unchanged).
- H.4 class-removal verification cases unchanged (one obsolete unit test that asserted
  "H-TRANS-002 is planning-only" was repurposed to an unsupported-transformation id, since
  H-TRANS-002 is now verifiable).

## 18. Known limitations

- Static scope only: VERIFIED means the requested isolated method removal was statically
  established together with the defined verification invariants. It does **not** mean the
  resulting APK is safe, malware-free, spyware-free, or guaranteed to function correctly
  when executed.
- H.5 does not remove callers or repair references. If the target is not genuinely
  isolated, H.2 must refuse the transformation.
- Overrides of framework/library methods cannot be resolved without the supertype
  definitions; such virtual methods stay UNDETERMINED (H.2).
- Method names referenced from resources (`android:onClick`) are not indexed by H.1;
  matching public `(Landroid/view/View;)V` handlers stay UNDETERMINED (H.2).
- The output is re-signed with the development key and cannot update an install signed with
  the original key.
- res/ binary XML and resources.arsc are compared by content hash, not decoded; byte
  identity with the control rebuild is established, not semantic identity with the original
  when the toolchain re-encodes them (inherited H.4 limitation).

## 19. Toolchain versions

- Apktool 3.0.3 (`tools/apktool_3.0.3.jar`), APKForge-managed framework android-35
- Android build-tools 35.0.0 (aapt2, zipalign, apksigner)
- JDK: OpenJDK 25
- androguard 4.1.4 (DEX inventory / API-reference attribution)

## 20. Schema versions

- Planning (H.2) schema: 1
- Application (H.3/H.5) result schema: 1 (`MutationRecord` gains the optional
  `REMOVE_METHOD` fields; `MethodPostAnalysis` added — additive, no version bump)
- Verification (H.4) result schema: 1 (`method_post_analysis` field added — additive)
- Reference analysis (H.1) schema: 2

## 21. Files changed

New:

- `src/apkforge/transformation/` — method-removal additions to `dexstate.py` (method
  identity, per-method API/string attribution, `.method` block split/census), `modifier.py`
  (`RemoveIsolatedMethodModifier`, `method_removal_expectations`), `executor.py` (method
  dispatch, `method_removal_consequences`, `assess_post_analysis_method`, method matrix),
  `application.py` (`MethodPostAnalysis`, `MutationRecord` method fields,
  `SUPPORTED_TRANSFORMATIONS`), `verification.py` (`method_post_analysis`), `verifier.py`
  (method `_derive_expected`, `_method_invariants`, DEX state/facts).
- `tests/fixtures/h5_apks.py` — positive/overload/negative fixtures + fault injection.
- `tests/integration/test_phase_h5_method_transformation.py` — 34 integration tests.
- `build-tests/run_phase_h5_validation.py` — synthetic + corpus validation runner.
- `artifacts/phase-h/H5-METHOD-TRANSFORMATION.md`, `h5-*-summary.json`,
  `h5-validation-summary.md`.

Modified (small, justified): `src/apkforge/cli/main.py` (help text only),
`tests/unit/test_phase_h3_transformation.py`, `tests/unit/test_phase_h4_verification.py`,
`tests/integration/test_phase_h3_transformation.py` (the three obsolete
"H-TRANS-002 is not applied" assertions).

---

> **VERIFIED** means the requested isolated method removal was statically established
> together with the defined verification invariants. It does **not** mean the resulting APK
> is safe, malware-free, spyware-free, or guaranteed to function correctly when executed.

> H.5 does not remove callers or repair references. If the target is not genuinely isolated,
> H.2 must refuse the transformation.
