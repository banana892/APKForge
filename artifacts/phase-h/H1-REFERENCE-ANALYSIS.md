# Phase H.1 — Evidence & Reference Analysis

> H.1 does not perform APK transformations. It only produces evidence that future
> transformation stages may consume. No APK was modified, rebuilt from the corpus, signed,
> installed or executed during H.1 validation.

Starting point: `ded323f` (clean tree). Design: [`docs/transformation.md`](../../docs/transformation.md).

## Implementation summary

New read-only package `src/apkforge/reference/`:

| Module | Role |
|---|---|
| `models.py` | `AnalysisState` + `combine_states`, `Evidence` (slotted dataclass, stable `evidence_id`), `ComponentAnalysis`, `QueryResult`, `AbsenceAssessment`, `ReferenceAnalysisResult` |
| `smali.py` | decoded-smali indexer: class/method/field/type/string/constructor/const-class references, reflection and native indicators, per-method register tracking |
| `manifest.py` | manifest class/authority references, built on the Phase E `diff.manifest_tree.parse_manifest_xml` |
| `resources.py` | `res/`, `assets/`, Apktool `unknown/` structural + textual references (expat, line numbers, DTD refused) |
| `index.py` | `ReferenceIndex`: `find_class/method/field/type/const_class/string_references`, `find_reflection_evidence`, `find_native_dependencies`, `find_manifest/resource_references`, `callers_of`, `assess_absence` |
| `service.py` | `ReferenceAnalysisService.analyze(apk)` (decode via existing `BuildService.decode` into a throwaway workspace, SHA-256 before/after) and `analyze_decoded(project)` |
| `report.py` | Markdown report |

CLI: `apkforge references APK [--json] [--report PATH] [--verbose] [--class C ...] [--all-evidence] [--skip-resources]`.
No second APK pipeline: decoding is the BuildService stage, manifest flattening is the Phase E tree.

## Reference types supported

`CLASS_REFERENCE` (invoke/field owner, new-instance, check-cast, instance-of, const-class,
arrays, .catch, .super, .implements) · `METHOD_REFERENCE` (static/direct/virtual/super/interface/polymorphic, /range)
· `CONSTRUCTOR_REFERENCE` (`<init>`) · `FIELD_REFERENCE` (iget/iput/sget/sput and variants)
· `TYPE_REFERENCE` (signatures, field types, member descriptors, operands, casts, arrays, const-class, annotations, catch, debug locals)
· `STRING_REFERENCE` (`STRING_LITERAL` / `POSSIBLE_CLASS_NAME` / `POSSIBLE_METHOD_NAME` / `POSSIBLE_REFLECTION_TARGET` / `UNKNOWN_STRING_USE`)
· `CONST_CLASS_REFERENCE` · `REFLECTION_INDICATOR` · `NATIVE_METHOD` · `NATIVE_LIBRARY_LOAD` · `MANIFEST_REFERENCE` · `RESOURCE_REFERENCE`.

## Reflection handling

Class.forName, ClassLoader.loadClass, Class.get(Declared)Method/Field/Constructor(s), Class.newInstance,
Method.invoke, Constructor.newInstance, Field.get*/set*, Proxy.newProxyInstance, MethodHandles.Lookup.find*,
and Dex/Path/InMemoryDex/BaseDex/DelegateLast/URL class-loader construction. Resolution:
`TARGET_IDENTIFIED` (constant traced within the same straight-line block), `TARGET_UNKNOWN`,
`NO_TARGET_IDENTIFIED`. Any non-identified indicator makes the `reflection` component PARTIAL;
an indicator is never treated as proof that a class is dynamically referenced.

## Native handling

`NATIVE_METHOD` for `native` methods (expected JNI symbol recorded, library `UNKNOWN`);
`NATIVE_LIBRARY_LOAD` for System/Runtime `load`/`loadLibrary` (`IDENTIFIED` + bundled-`.so` check, or `UNKNOWN`).
Native binaries are not analysed: whenever native code exists, `native_code` is `NOT_ANALYZED`.

## Resource / manifest handling

Manifest: component `android:name`, activity-alias `targetActivity`, `parentActivityName`, application
`name`/`backupAgent`/`appComponentFactory`/`manageSpaceActivity` (structural), provider authorities,
other attributes equal to an app class (textual). Resources/assets: custom view tags, class-valued
attributes, `META-INF/services` entries (structural); exact/embedded text matches (indirect only).

## Completeness model

States `COMPLETE` / `PARTIAL` / `UNKNOWN` / `NOT_ANALYZED` for components `dex` (+ per-DEX),
`reflection`, `native_indicators`, `native_code`, `manifest`, `resources`, `assets`.
`combine_states` never reports more completeness than the weakest input. `QueryResult.absence_established`
is true only for an empty COMPLETE query; `assess_absence` returns `REFERENCES_OBSERVED`,
`ONLY_INDIRECT_EVIDENCE`, `ABSENCE_NOT_ESTABLISHED` or `NO_REFERENCES_WITHIN_SCOPE`.

## Synthetic fixture results (real APKs, Apktool 3.0.3)

Each fixture is a hand-written Apktool project built into an APK with `BuildService.build`,
then decoded and analysed twice. Full per-fixture JSON: `fixtures/`.

| Fixture | Scenario | Overall state | Deterministic | APK unchanged | Result |
|---|---|---|---|---|---|
| `f01_isolated` | A and B; B has no references | COMPLETE | True | True | **PASS** |
| `f02_class_ref` | A -> B (instance-of) | COMPLETE | True | True | **PASS** |
| `f03_multiple_callers` | A -> B and C -> B (check-cast) | COMPLETE | True | True | **PASS** |
| `f04_method_ref` | A.foo() -> B.bar() | COMPLETE | True | True | **PASS** |
| `f05_field_ref` | A -> B.counter (sget/sput) | COMPLETE | True | True | **PASS** |
| `f06_constructor` | new-instance B; invoke-direct B.<init> | COMPLETE | True | True | **PASS** |
| `f07_const_class` | const-class B | COMPLETE | True | True | **PASS** |
| `f08_string` | a string naming B (not a structural reference) | COMPLETE | True | True | **PASS** |
| `f09_reflection` | Class.forName("com.example.h1.B") plus an unresolved Class.forName(p1); C isolated | PARTIAL | True | True | **PASS** |
| `f10_native_method` | B declares a native method | PARTIAL | True | True | **PASS** |
| `f11_load_library` | System.loadLibrary("h1native") with a bundled lib/arm64-v8a/libh1native.so | PARTIAL | True | True | **PASS** |
| `f12_manifest` | manifest service .B, receiver C, activity-alias -> A | COMPLETE | True | True | **PASS** |
| `f13_resource` | layout inflates <com.example.h1.B>; assets text mentions C | COMPLETE | True | True | **PASS** |
| `f14_incomplete` | multidex (C in classes2.dex) + malformed assets/broken.xml; B unreferenced | PARTIAL | True | True | **PASS** |

Key outcomes: f01 B has no callers, class-reference query COMPLETE, `NO_REFERENCES_WITHIN_SCOPE`;
f08 the class-name string is `POSSIBLE_CLASS_NAME` and not a class reference (`ONLY_INDIRECT_EVIDENCE`);
f09 dex COMPLETE but reflection PARTIAL -> class C `ABSENCE_NOT_ESTABLISHED` (spec §17);
f14 malformed asset -> assets PARTIAL -> no absence claim; simulated loss of `classes2.dex`
-> `dex:classes2.dex` UNKNOWN, dex PARTIAL (pytest `test_f14_missing_decoded_dex`).

## Read-only corpus run (9 APKs)

| APK | Overall | dex | reflection | native_code | assets | Classes | Evidence | Absence proven (sample) | APK unchanged | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 2845 | 458489 | 0/26 | True | 16.3 |
| com.oF2pks.applicationsinfo_19.apk | PARTIAL | COMPLETE | PARTIAL | COMPLETE | COMPLETE | 63 | 10094 | 0/32 | True | 1.1 |
| de.audioattack.openlink_28.apk | PARTIAL | COMPLETE | PARTIAL | COMPLETE | PARTIAL | 108 | 8898 | 0/27 | True | 1.2 |
| de.danoeh.antennapod_3120295.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 12065 | 1231196 | 0/26 | True | 35.8 |
| eu.siacs.conversations_4218104.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 7686 | 1048744 | 0/26 | True | 35.3 |
| godau.fynn.usagedirect_10.apk | PARTIAL | COMPLETE | PARTIAL | COMPLETE | PARTIAL | 5902 | 751418 | 0/26 | True | 23.6 |
| io.github.muntashirakon.AppManager_451.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 30717 | 3970739 | 0/26 | True | 107.7 |
| org.mozilla.fennec_fdroid_1560020.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 37886 | 3448661 | 0/26 | True | 112.0 |
| org.schabi.newpipe_1015_cb84069.apk | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | PARTIAL | 10671 | 1504221 | 0/26 | True | 50.2 |

Every corpus smali line was interpreted (`dex` COMPLETE for all 9). Every APK ends PARTIAL because of
unresolved reflection, native code and/or uninspectable binary assets, so no class absence is ever
established on real apps — the intended conservative outcome. Each declared activity was found
`REFERENCES_OBSERVED`; OpenLink JSON was identical across two runs.

## Regression results

| Gate | Command | Result |
|---|---|---|
| Full pytest | `.venv-validation/bin/python -m pytest -q` | 995 passed, 10 skipped (includes the 86 H.1 tests) |
| H.1 tests, `FORCE_COLOR=3` | `pytest tests/unit/test_phase_h1_reference.py tests/integration/test_phase_h1_references.py` | 86 passed |
| Phase D | `build-tests/run_phase_d_validation.py` | A–F all as expected |
| Phase E | `build-tests/run_phase_e_validation.py baseline` | 8 VERIFIED, Fennec UNDETERMINED (same as Phase G record) |
| Phase F | `build-tests/run_phase_f_validation.py --output-dir work/...` | completed; findings identical to `ded323f` (see note) |
| Phase G | runner with output redirected to `work/` | corpus summary identical to committed `artifacts/phase-g` (timing excluded) |
| H.1 | `build-tests/run_phase_h1_validation.py all --write` | PASS (14/14 fixtures, 9/9 corpus) |
| ruff | `ruff check` / `ruff format --check` on all touched files | touched files clean; repo-wide counts identical to `ded323f` (pre-existing: 517 lint errors, 56 unformatted files) |
| mypy | `mypy src/apkforge` | 102 errors before and after (all pre-existing; `src/apkforge/reference` clean) |

Note (Phase F): committed `artifacts/phase-f/` was generated at `e0d8e9b`, before Phase G changed
`privacy/behavior.py`; the current run reports 3 fewer persistence findings. The identical result was
reproduced on a clean `ded323f` worktree, so the delta predates H.1. Phase F/G evidence was not rewritten.

## Known limitations

See `docs/known-limitations.md` (Phase H.1 section) and `docs/transformation.md`: static scope only;
same-block constant tracking; native binaries not analysed; uninterpreted smali (invoke-custom,
method handles, odex quick ops) -> PARTIAL; resources matched only against app classes/authorities;
manifest location is a tree key, not a line; very large evidence volumes (CLI JSON omits per-instruction
code references unless `--all-evidence`).

## Reproduction

```bash
git checkout <H.1 commit>
source tools/env.sh
.venv-validation/bin/python -m pytest -q
.venv-validation/bin/python -m pytest -q tests/unit/test_phase_h1_reference.py tests/integration/test_phase_h1_references.py
.venv-validation/bin/python build-tests/run_phase_h1_validation.py all --write   # ~8 min
.venv-validation/bin/python build-tests/run_phase_d_validation.py
.venv-validation/bin/python build-tests/run_phase_e_validation.py baseline        # ~20 min
.venv-validation/bin/ruff check src/apkforge/reference && .venv-validation/bin/mypy src/apkforge/reference
.venv-validation/bin/python -m apkforge references tests/corpus/de.audioattack.openlink_28.apk --class de.audioattack.openlink.ui.IncognitoActivity -v
```
