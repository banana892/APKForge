# Phase H.5 validation (H-TRANS-002 remove isolated method)

- Run: `20261004T084741Z`
- Overall: **PASS**

## Synthetic

- Status: **PASS**
- Inputs unchanged: True

| Fixture | Target | H.3 | H.4 | Completeness |
|---|---|---|---|---|
| h5_isolated | `com.example.h1.B->isolatedStamp()Ljava/lang/String;` | VERIFIED | VERIFIED | COMPLETE |
| h5_overloads | `com.example.h1.B->foo(I)V` | VERIFIED | VERIFIED | COMPLETE |

| Negative | Target | Expected | Decision |
|---|---|---|---|
| h5_caller | `com.example.h1.B->callee()V` | REFUSED | REFUSED |
| h5_reflection | `com.example.h1.B->isolatedStamp()Ljava/lang/String;` | UNDETERMINED | UNDETERMINED |
| h5_native | `com.example.h1.B->isolatedStamp()Ljava/lang/String;` | UNDETERMINED | UNDETERMINED |
| h5_override | `com.example.h1.B->run()V` | UNSUPPORTED | UNSUPPORTED |
| h5_override | `com.example.h1.A->run()V` | UNSUPPORTED | UNSUPPORTED |
| h5_interface | `com.example.h1.B->handle()V` | UNSUPPORTED | UNSUPPORTED |
| h5_interface | `com.example.h1.Iface->handle()V` | UNSUPPORTED | UNSUPPORTED |
| h5_isolated | `com.example.h1.B-><init>()V` | UNSUPPORTED | UNSUPPORTED |
| h5_isolated | `com.example.h1.B->doesNotExist()V` | REFUSED | REFUSED |
| h5_overloads | `com.example.h1.B->foo` | REFUSED | REFUSED |

| Fault | Domain | H.3 | H.4 |
|---|---|---|---|
| asset_added | assets | FAILED | FAILED |
| manifest_modified | manifest | FAILED | FAILED |
| native_added | native | FAILED | FAILED |
| other_method_modified | dex | FAILED | FAILED |
| reference_left | dex | FAILED | FAILED |
| resource_modified | resources | FAILED | FAILED |

## Corpus (read-only; eligibility never relaxed)

- Status: **PASS**; SHA-256 unchanged: True
- 152 method targets, 0 ELIGIBLE, 0 applied

| APK | Method targets | ELIGIBLE | Unchanged |
|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | 16 | 0 | True |
| com.oF2pks.applicationsinfo_19.apk | 17 | 0 | True |
| de.audioattack.openlink_28.apk | 17 | 0 | True |
| de.danoeh.antennapod_3120295.apk | 18 | 0 | True |
| eu.siacs.conversations_4218104.apk | 16 | 0 | True |
| godau.fynn.usagedirect_10.apk | 18 | 0 | True |
| io.github.muntashirakon.AppManager_451.apk | 16 | 0 | True |
| org.mozilla.fennec_fdroid_1560020.apk | 19 | 0 | True |
| org.schabi.newpipe_1015_cb84069.apk | 15 | 0 | True |

