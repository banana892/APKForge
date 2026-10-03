# Phase H.1 validation summary

- Overall: **PASS**
- Run: `20261003T095415Z`

## Toolchain

- python: `3.14.7`
- platform: `Linux-7.2.7-200.fc44.x86_64-x86_64-with-glibc2.43`
- apktool: `3.0.3`
- java: `openjdk version "25.0.4.1" 2026-08-18`
- git_head: `ded323f`

## Synthetic fixtures (PASS)

| Fixture | Result | State | Deterministic | APK unchanged | Notes |
|---|---|---|---|---|---|
| f01_isolated | PASS | COMPLETE | True | True | A and B; B has no references |
| f02_class_ref | PASS | COMPLETE | True | True | A -> B (instance-of) |
| f03_multiple_callers | PASS | COMPLETE | True | True | A -> B and C -> B (check-cast) |
| f04_method_ref | PASS | COMPLETE | True | True | A.foo() -> B.bar() |
| f05_field_ref | PASS | COMPLETE | True | True | A -> B.counter (sget/sput) |
| f06_constructor | PASS | COMPLETE | True | True | new-instance B; invoke-direct B.<init> |
| f07_const_class | PASS | COMPLETE | True | True | const-class B |
| f08_string | PASS | COMPLETE | True | True | a string naming B (not a structural reference) |
| f09_reflection | PASS | PARTIAL | True | True | Class.forName("com.example.h1.B") plus an unresolved Class.forName(p1); C isolated |
| f10_native_method | PASS | PARTIAL | True | True | B declares a native method |
| f11_load_library | PASS | PARTIAL | True | True | System.loadLibrary("h1native") with a bundled lib/arm64-v8a/libh1native.so |
| f12_manifest | PASS | COMPLETE | True | True | manifest service .B, receiver C, activity-alias -> A |
| f13_resource | PASS | COMPLETE | True | True | layout inflates <com.example.h1.B>; assets text mentions C |
| f14_incomplete | PASS | PARTIAL | True | True | multidex (C in classes2.dex) + malformed assets/broken.xml; B unreferenced |

## Corpus, read-only (PASS)

| APK | Result | Overall | dex | reflection | native_code | manifest | resources | assets | Classes | Unresolved reflection | Absence proven (sample) | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | COMPLETE | PARTIAL | 2845 | 244 | 0/26 | 16.3 |
| com.oF2pks.applicationsinfo_19.apk | PASS | PARTIAL | COMPLETE | PARTIAL | COMPLETE | COMPLETE | COMPLETE | COMPLETE | 63 | 2 | 0/32 | 1.1 |
| de.audioattack.openlink_28.apk | PASS | PARTIAL | COMPLETE | PARTIAL | COMPLETE | COMPLETE | COMPLETE | PARTIAL | 108 | 10 | 0/27 | 1.2 |
| de.danoeh.antennapod_3120295.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | COMPLETE | PARTIAL | 12065 | 336 | 0/26 | 35.8 |
| eu.siacs.conversations_4218104.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | PARTIAL | PARTIAL | 7686 | 356 | 0/26 | 35.3 |
| godau.fynn.usagedirect_10.apk | PASS | PARTIAL | COMPLETE | PARTIAL | COMPLETE | COMPLETE | COMPLETE | PARTIAL | 5902 | 286 | 0/26 | 23.6 |
| io.github.muntashirakon.AppManager_451.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | COMPLETE | PARTIAL | 30717 | 1032 | 0/26 | 107.7 |
| org.mozilla.fennec_fdroid_1560020.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | COMPLETE | PARTIAL | 37886 | 516 | 0/26 | 112.0 |
| org.schabi.newpipe_1015_cb84069.apk | PASS | PARTIAL | COMPLETE | PARTIAL | NOT_ANALYZED | COMPLETE | COMPLETE | PARTIAL | 10671 | 575 | 0/26 | 50.2 |
