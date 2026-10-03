# Phase H.2 validation summary (planning only)

- Overall: **PASS**
- Run: `20261003T134947Z`

## Toolchain

- python: `3.14.7`
- platform: `Linux-7.2.7-200.fc44.x86_64-x86_64-with-glibc2.43`
- apktool: `3.0.3`
- java: `openjdk version "25.0.4.1" 2026-08-18`
- git_head: `4013e9e`

## Synthetic decisions (PASS)

| Fixture | Transformation | Target | Expected | Got | Reasons | Result |
|---|---|---|---|---|---|---|
| f01_isolated | H-TRANS-001 | `B` | ELIGIBLE | ELIGIBLE | - | PASS |
| f01_isolated | H-TRANS-001 | `Missing` | REFUSED | REFUSED | TARGET_NOT_FOUND | PASS |
| f02_class_ref | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f03_multiple_callers | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f03_multiple_callers | H-TRANS-001 | `C` | ELIGIBLE | ELIGIBLE | - | PASS |
| f04_method_ref | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, METHOD_CALLER_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f05_field_ref | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, FIELD_REFERENCE_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f06_constructor | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, CONSTRUCTOR_REFERENCE_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f07_const_class | H-TRANS-001 | `B` | REFUSED | REFUSED | CLASS_CALLER_PRESENT, CONST_CLASS_REFERENCE_PRESENT, TYPE_REFERENCE_PRESENT | PASS |
| f08_string | H-TRANS-001 | `B` | UNDETERMINED | UNDETERMINED | STRING_REFERENCE_UNRESOLVED | PASS |
| f09_reflection | H-TRANS-001 | `B` | REFUSED | REFUSED | REFLECTION_TARGET_PRESENT, REFLECTION_TARGET_UNKNOWN, STRING_REFERENCE_UNRESOLVED | PASS |
| f09_reflection | H-TRANS-001 | `C` | UNDETERMINED | UNDETERMINED | REFLECTION_TARGET_UNKNOWN | PASS |
| f09_reflection | H-TRANS-002 | `C->bar()V` | UNDETERMINED | UNDETERMINED | REFLECTION_TARGET_UNKNOWN | PASS |
| f10_native_method | H-TRANS-001 | `B` | UNSUPPORTED | UNSUPPORTED | NATIVE_DEPENDENCY_UNKNOWN, NATIVE_METHOD_DECLARED | PASS |
| f10_native_method | H-TRANS-002 | `B->nativeCall(I)I` | UNSUPPORTED | UNSUPPORTED | NATIVE_DEPENDENCY_UNKNOWN, NATIVE_METHOD | PASS |
| f11_load_library | H-TRANS-001 | `B` | UNDETERMINED | UNDETERMINED | NATIVE_DEPENDENCY_UNKNOWN | PASS |
| f12_manifest | H-TRANS-001 | `B` | REFUSED | REFUSED | MANIFEST_COMPONENT_REFERENCE | PASS |
| f12_manifest | H-TRANS-001 | `C` | REFUSED | REFUSED | MANIFEST_COMPONENT_REFERENCE | PASS |
| f13_resource | H-TRANS-001 | `B` | REFUSED | REFUSED | RESOURCE_REFERENCE_PRESENT | PASS |
| f13_resource | H-TRANS-001 | `C` | UNDETERMINED | UNDETERMINED | RESOURCE_TEXTUAL_MATCH | PASS |
| f14_incomplete | H-TRANS-001 | `B` | UNDETERMINED | UNDETERMINED | RESOURCE_ANALYSIS_INCOMPLETE | PASS |
| g01_methods | H-TRANS-002 | `D->helper()V` | ELIGIBLE | ELIGIBLE | - | PASS |
| g01_methods | H-TRANS-002 | `E->own()V` | ELIGIBLE | ELIGIBLE | - | PASS |
| g01_methods | H-TRANS-002 | `D->used()V` | REFUSED | REFUSED | METHOD_CALLER_PRESENT | PASS |
| g01_methods | H-TRANS-002 | `D->shared()V` | REFUSED | REFUSED | METHOD_CALLER_PRESENT | PASS |
| g01_methods | H-TRANS-002 | `D->sutil()V` | REFUSED | REFUSED | METHOD_CALLER_PRESENT | PASS |
| g01_methods | H-TRANS-002 | `I->run()V` | UNSUPPORTED | UNSUPPORTED | ABSTRACT_METHOD, INTERFACE_METHOD, METHOD_OVERRIDDEN | PASS |
| g01_methods | H-TRANS-002 | `E->run()V` | UNSUPPORTED | UNSUPPORTED | METHOD_OVERRIDES | PASS |
| g01_methods | H-TRANS-002 | `D->helper2()V` | UNSUPPORTED | UNSUPPORTED | METHOD_OVERRIDDEN | PASS |
| g01_methods | H-TRANS-002 | `N->values()[Lcom/example/h1/N;` | UNSUPPORTED | UNSUPPORTED | ENUM_IMPLICIT_METHOD | PASS |
| g01_methods | H-TRANS-002 | `D->readResolve()Ljava/lang/Object;` | UNSUPPORTED | UNSUPPORTED | SERIALIZATION_HOOK_METHOD | PASS |
| g01_methods | H-TRANS-002 | `H->handle()V` | UNDETERMINED | UNDETERMINED | OVERRIDE_RELATIONSHIP_UNRESOLVED | PASS |
| g01_methods | H-TRANS-002 | `J->js()V` | UNDETERMINED | UNDETERMINED | ANNOTATION_DRIVEN_ACCESS_POSSIBLE | PASS |
| g01_methods | H-TRANS-002 | `K->k()V` | CONDITIONALLY_ELIGIBLE | CONDITIONALLY_ELIGIBLE | KOTLIN_METADATA_UPDATE_REQUIRED | PASS |
| g01_methods | H-TRANS-002 | `D->over` | REFUSED | REFUSED | TARGET_AMBIGUOUS | PASS |
| g02_method_reflection | H-TRANS-002 | `D->secret()V` | REFUSED | REFUSED | REFLECTION_TARGET_PRESENT, STRING_REFERENCE_UNRESOLVED | PASS |
| g03_duplicate_class | H-TRANS-001 | `C` | REFUSED | REFUSED | TARGET_AMBIGUOUS | PASS |

## Corpus planning, read-only (PASS)

| APK | SHA-256 (12) | H.1 state | Targets | Plans | ELIGIBLE | COND. | REFUSED | UNSUPPORTED | UNDETERMINED | Unchanged | Plan s | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | `e03f79082278` | PARTIAL | 41 | 0 | 0 | 0 | 33 | 6 | 2 | True | 0.09 | PASS |
| com.oF2pks.applicationsinfo_19.apk | `c0188f5f1f56` | PARTIAL | 39 | 0 | 0 | 0 | 31 | 3 | 5 | True | 0.01 | PASS |
| de.audioattack.openlink_28.apk | `3d28923f08bd` | PARTIAL | 40 | 0 | 0 | 0 | 32 | 2 | 6 | True | 0.01 | PASS |
| de.danoeh.antennapod_3120295.apk | `3f43a4337a69` | PARTIAL | 43 | 0 | 0 | 0 | 35 | 4 | 4 | True | 0.09 | PASS |
| eu.siacs.conversations_4218104.apk | `3fae646e33b5` | PARTIAL | 41 | 0 | 0 | 0 | 32 | 8 | 1 | True | 0.11 | PASS |
| godau.fynn.usagedirect_10.apk | `c55079192a77` | PARTIAL | 43 | 0 | 0 | 0 | 33 | 6 | 4 | True | 0.11 | PASS |
| io.github.muntashirakon.AppManager_451.apk | `e1f6ba10812c` | PARTIAL | 41 | 0 | 0 | 0 | 30 | 6 | 5 | True | 0.42 | PASS |
| org.mozilla.fennec_fdroid_1560020.apk | `27f2951376ca` | PARTIAL | 50 | 0 | 0 | 0 | 40 | 10 | 0 | True | 0.22 | PASS |
| org.schabi.newpipe_1015_cb84069.apk | `18447bfb1e06` | PARTIAL | 40 | 0 | 0 | 0 | 30 | 8 | 2 | True | 0.12 | PASS |

Max RSS: 2266 MB

