# Phase H.4 validation summary (transformation verification hardening)

- Overall: **PASS**
- Run: `20261003T173957Z`

## Toolchain

- python: `3.14.7`
- platform: `Linux-7.2.7-200.fc44.x86_64-x86_64-with-glibc2.43`
- apktool: `3.0.3`
- java: `openjdk version "25.0.4.1" 2026-08-18`
- git_head: `563178d`

## Synthetic cases (PASS)

| Case | H.2 | H.3 | Expected H.4 | H.4 | Completeness | Unexpected | Unknown | Seconds | Result |
|---|---|---|---|---|---|---|---|---|---|
| 1_clean | ELIGIBLE | VERIFIED | VERIFIED | VERIFIED | COMPLETE | 0 | 0 | 9.975 | PASS |
| 2_repeat | ELIGIBLE | VERIFIED | VERIFIED | VERIFIED | COMPLETE | 0 | 0 | 9.876 | PASS |
| 3_noise | - | - | VERIFIED | VERIFIED | COMPLETE | 0 | 0 | 5.2 | PASS |
| 4a_h3_faulty_mutation | - | FAILED/UNEXPECTED_MUTATION | UNVERIFIED | UNVERIFIED | NOT_ANALYZED | 0 | 0 | 5.504 | PASS |
| fault_asset_added | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 1 | 0 | 9.002 | PASS |
| fault_manifest_modified | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 2 | 0 | 8.735 | PASS |
| fault_native_added | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | UNKNOWN | 3 | 0 | 8.813 | PASS |
| fault_other_class_modified | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 1 | 0 | 8.913 | PASS |
| fault_other_class_removed | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | COMPLETE | 4 | 0 | 9.634 | PASS |
| fault_resource_modified | - | FAILED/UNEXPECTED_DIFF | FAILED | FAILED | PARTIAL | 1 | 0 | 9.79 | PASS |
| 7b_native_modified | UNSUPPORTED | - | FAILED | FAILED | COMPLETE | 2 | 0 | 0.6 | PASS |
| 8a_strings_truncated | - | - | UNKNOWN | UNKNOWN | PARTIAL | 0 | 2 | 0.0 | PASS |
| 8b_native_comparator_failed | - | - | UNKNOWN | UNKNOWN | UNKNOWN | 0 | 0 | 0.0 | PASS |
| 8c_h1_insufficient | - | - | UNKNOWN | UNKNOWN | UNKNOWN | 0 | 0 | 0.0 | PASS |
| negative_target_not_removed | - | - | FAILED | FAILED | COMPLETE | 0 | 0 | 0.0 | PASS |
| limitations_resource_table | ELIGIBLE | VERIFIED | VERIFIED_WITH_LIMITATIONS | VERIFIED_WITH_LIMITATIONS | PARTIAL | 0 | 0 | 10.114 | PASS |
| negative_h_trans_002 | - | - | UNVERIFIED | UNVERIFIED | NOT_ANALYZED | 0 | 0 | 0.0 | PASS |

- fault_asset_added: UNEXPECTED_CHANGE [assets] file added assets/injected.txt (control: absent)
- fault_manifest_modified: UNEXPECTED_CHANGE [manifest] uses_permission added android.permission.INTERNET (control: absent)
- fault_manifest_modified: UNEXPECTED_CHANGE [manifest] file modified AndroidManifest.xml (control: absent)
- fault_native_added: UNEXPECTED_CHANGE [native] native_library added lib/arm64-v8a/libinjected.so (control: absent)
- fault_native_added: UNEXPECTED_CHANGE [native] native_abi added arm64-v8a (control: absent)
- fault_native_added: UNEXPECTED_CHANGE [native] file added lib/arm64-v8a/libinjected.so (control: absent)
- fault_other_class_modified: UNEXPECTED_CHANGE [dex] dex_class modified com.example.h1.C (control: absent)
- fault_other_class_removed: UNEXPECTED_CHANGE [dex] dex_class removed com.example.h1.C (control: absent)
- fault_other_class_removed: UNEXPECTED_CHANGE [dex] dex_string removed C.java (control: absent)
- fault_other_class_removed: UNEXPECTED_CHANGE [dex] dex_string removed Lcom/example/h1/C; (control: absent)
- fault_other_class_removed: UNEXPECTED_CHANGE [dex] dex_string removed ping (control: absent)
- fault_resource_modified: UNEXPECTED_CHANGE [resources] file modified resources.arsc (control: absent)
- fault_resource_modified: limitation [resources] PARTIAL: original->transformed: resource_table not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established)); control->transformed:
- 7b_native_modified: UNEXPECTED_CHANGE [native] native_library modified lib/arm64-v8a/libh3native.so (control: absent)
- 7b_native_modified: UNEXPECTED_CHANGE [native] file modified lib/arm64-v8a/libh3native.so (control: absent)
- 8a_strings_truncated: UNKNOWN [dex] dex_string incomplete removed: DiffEngine output was truncated; not every change could be classified
- 8a_strings_truncated: UNKNOWN [dex] file modified classes.dex: planned entry, but its semantic comparison is incomplete (strings)
- 8a_strings_truncated: limitation [dex] PARTIAL: original->transformed: strings partial (string enumeration truncated (0/0 added, 2/7 removed listed)); control->transformed: strings partial (string enumeration truncated (0/0 added, 2/
- limitations_resource_table: limitation [resources] PARTIAL: original->control: resource_table not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established)); original->transformed: re

## Corpus (PASS)

- Targets planned: 226; ELIGIBLE: 0; transformations: 0; noise-floor H.4 results: {'UNKNOWN': 1, 'VERIFIED_WITH_LIMITATIONS': 8}
- Corpus SHA-256 unchanged: True; max RSS 2247 MB

| APK | SHA-256 (12) | Targets | ELIGIBLE | Control no-op | Bytes equal | Content equal | H.4 (B2 vs B1) | Completeness | Non-complete domains | H.1 s | H.4 s | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | `e03f79082278` | 25 | 0 | EQUIVALENT_WITH_RESIDUE/EQUIVALENT_WITH_RESIDUE | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 18.7 | 157.3 | PASS |
| com.oF2pks.applicationsinfo_19.apk | `c0188f5f1f56` | 22 | 0 | EQUIVALENT_WITH_RESIDUE/EQUIVALENT_WITH_RESIDUE | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 1.1 | 7.5 | PASS |
| de.audioattack.openlink_28.apk | `3d28923f08bd` | 23 | 0 | EQUIVALENT/EQUIVALENT | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 1.3 | 8.9 | PASS |
| de.danoeh.antennapod_3120295.apk | `3f43a4337a69` | 25 | 0 | EQUIVALENT_WITH_RESIDUE/EQUIVALENT_WITH_RESIDUE | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 39.0 | 262.6 | PASS |
| eu.siacs.conversations_4218104.apk | `3fae646e33b5` | 25 | 0 | EQUIVALENT/EQUIVALENT | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 34.9 | 238.9 | PASS |
| godau.fynn.usagedirect_10.apk | `c55079192a77` | 25 | 0 | EQUIVALENT/EQUIVALENT | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 24.7 | 132.3 | PASS |
| io.github.muntashirakon.AppManager_451.apk | `e1f6ba10812c` | 25 | 0 | EQUIVALENT_WITH_RESIDUE/EQUIVALENT_WITH_RESIDUE | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 125.0 | 712.6 | PASS |
| org.mozilla.fennec_fdroid_1560020.apk | `27f2951376ca` | 31 | 0 | UNDETERMINED/UNDETERMINED | False | True | UNKNOWN | PARTIAL | resources PARTIAL/partial, archive PARTIAL/partial | 120.0 | 906.8 | PASS |
| org.schabi.newpipe_1015_cb84069.apk | `18447bfb1e06` | 25 | 0 | EQUIVALENT/EQUIVALENT | False | True | VERIFIED_WITH_LIMITATIONS | PARTIAL | resources PARTIAL/partial | 41.8 | 252.6 | PASS |
