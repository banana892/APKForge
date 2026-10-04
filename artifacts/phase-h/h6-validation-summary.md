# Phase H.6 validation (H-TRANS-003 controlled call-site replacement)

- Run: `20261004T200031Z`
- Overall: **PASS**

## Synthetic

- Status: **PASS**
- Inputs unchanged: True

| Shape | Target | H.6 | H.4 | Completeness | Changed line |
|---|---|---|---|---|---|
| static | `com.example.h1.A->run()Ljava/lang/String;@com.example.h1.Source->getValue()Ljava/lang/String;` | VERIFIED | VERIFIED | COMPLETE | [64] |
| args_and_result | `com.example.h1.A->calc(IJLjava/lang/String;)I@com.example.h1.Source->compute(IJLjava/lang/String;)I` | VERIFIED | VERIFIED | COMPLETE | [28] |
| private_instance | `com.example.h1.A->instanceCall()Ljava/lang/String;@com.example.h1.A->secret()Ljava/lang/String;` | VERIFIED | VERIFIED | COMPLETE | [116] |
| repeated_second_call | `com.example.h1.A->twice()Ljava/lang/String;@com.example.h1.Source->getValue()Ljava/lang/String;#2` | VERIFIED | VERIFIED | COMPLETE | [94] |

| Negative | Expected | Decision | Reasons | Executor |
|---|---|---|---|---|
| target missing | REFUSED (CALL_SITE_NOT_FOUND) | REFUSED | CALL_SITE_NOT_FOUND | REFUSED |
| caller missing | REFUSED (TARGET_NOT_FOUND) | REFUSED | TARGET_NOT_FOUND | REFUSED |
| target ambiguous | REFUSED (CALL_SITE_AMBIGUOUS) | REFUSED | CALL_SITE_AMBIGUOUS | REFUSED |
| multiple matching call sites | REFUSED (CALL_SITE_MULTIPLE_MATCHES) | REFUSED | CALL_SITE_MULTIPLE_MATCHES | REFUSED |
| signature mismatch | REFUSED (REPLACEMENT_SIGNATURE_MISMATCH) | REFUSED | REPLACEMENT_SIGNATURE_MISMATCH | REFUSED |
| argument mismatch | REFUSED (REGISTER_TYPE_MISMATCH) | REFUSED | REGISTER_TYPE_MISMATCH | REFUSED |
| return-type mismatch | REFUSED (RESULT_TYPE_MISMATCH) | REFUSED | RESULT_TYPE_MISMATCH | REFUSED |
| inaccessible replacement | REFUSED (REPLACEMENT_INACCESSIBLE) | REFUSED | REPLACEMENT_INACCESSIBLE | REFUSED |
| replacement missing | REFUSED (REPLACEMENT_METHOD_NOT_FOUND) | REFUSED | REPLACEMENT_METHOD_NOT_FOUND | REFUSED |
| replacement parameter missing | REFUSED (PARAMETER_INVALID) | REFUSED | PARAMETER_INVALID | REFUSED |
| constructor call | UNSUPPORTED (CONSTRUCTOR_INVOCATION) | UNSUPPORTED | CONSTRUCTOR_INVOCATION | REFUSED |
| polymorphic (virtual) call | UNSUPPORTED (POLYMORPHIC_INVOCATION) | UNSUPPORTED | POLYMORPHIC_INVOCATION | REFUSED |
| invoke-polymorphic | UNSUPPORTED (INVOKE_POLYMORPHIC_UNSUPPORTED) | UNSUPPORTED | DEX_ANALYSIS_INCOMPLETE, INVOKE_POLYMORPHIC_UNSUPPORTED, NATIVE_DEPENDENCY_UNKNOWN, REFLECTION_ANALYSIS_INCOMPLETE | REFUSED |
| invoke-custom | UNSUPPORTED (INVOKE_CUSTOM_UNSUPPORTED) | UNSUPPORTED | CALLER_ANALYSIS_INCOMPLETE, DEX_ANALYSIS_INCOMPLETE, INVOKE_CUSTOM_UNSUPPORTED, NATIVE_DEPENDENCY_UNKNOWN, REFLECTION_ANALYSIS_INCOMPLETE | REFUSED |
| incomplete reference analysis | UNDETERMINED (DEX_ANALYSIS_INCOMPLETE) | UNDETERMINED | DEX_ANALYSIS_INCOMPLETE, NATIVE_DEPENDENCY_UNKNOWN, REFLECTION_ANALYSIS_INCOMPLETE | REFUSED |
| unsupported instruction in the caller | UNDETERMINED (CALLER_ANALYSIS_INCOMPLETE) | UNDETERMINED | CALLER_ANALYSIS_INCOMPLETE, DEX_ANALYSIS_INCOMPLETE, NATIVE_DEPENDENCY_UNKNOWN, REFLECTION_ANALYSIS_INCOMPLETE | REFUSED |
| reflection dependency | UNDETERMINED (REFLECTION_TARGET_UNKNOWN) | UNDETERMINED | REFLECTION_TARGET_UNKNOWN | REFUSED |
| native dependency | UNDETERMINED (NATIVE_DEPENDENCY_UNKNOWN) | UNDETERMINED | NATIVE_DEPENDENCY_UNKNOWN | REFUSED |
| native replacement | UNSUPPORTED (NATIVE_METHOD) | UNSUPPORTED | NATIVE_DEPENDENCY_UNKNOWN, NATIVE_METHOD | REFUSED |
| replacement is the invoked method | REFUSED (CALL_SITE_ALREADY_REPLACED) | REFUSED | CALL_SITE_ALREADY_REPLACED | REFUSED |

- Already transformed APK: REFUSED ['CALL_SITE_ALREADY_REPLACED']
- Conflicting request set: ['REFUSED', 'REFUSED'] ['call_site_overlap']

| Mutation fault | Status | Failure | Built | Published |
|---|---|---|---|---|
| wrong_call_site | FAILED | UNEXPECTED_MUTATION | False | False |
| two_call_sites | FAILED | UNEXPECTED_MUTATION | False | False |
| wrong_replacement | FAILED | UNEXPECTED_MUTATION | False | False |
| wrong_descriptor | FAILED | UNEXPECTED_MUTATION | False | False |
| unrelated_method | FAILED | UNEXPECTED_MUTATION | False | False |
| unrelated_class | FAILED | UNEXPECTED_MUTATION | False | False |

| Build fault | Domain | H.6 | H.4 |
|---|---|---|---|
| asset_added | assets | FAILED | FAILED |
| manifest_modified | manifest | FAILED | FAILED |
| native_added | native | FAILED | FAILED |
| other_class_modified | dex | FAILED | FAILED |
| other_method_modified | dex | FAILED | FAILED |
| resource_modified | resources | FAILED | FAILED |
| second_call_site | dex | FAILED | FAILED |

| Integrity case | Expected | Status | Failure |
|---|---|---|---|
| source SHA mismatch | SOURCE_SHA_MISMATCH | REFUSED | SOURCE_SHA_MISMATCH |
| invalid plan id | PLAN_ID_MISMATCH | REFUSED | PLAN_ID_MISMATCH |
| forged plan (edited replacement) | PLAN_MISMATCH | REFUSED | PLAN_MISMATCH |
| forged plan (rebound, id recomputed) | PLAN_NOT_ELIGIBLE | REFUSED | PLAN_NOT_ELIGIBLE |
| target disappearing after planning | TARGET_NOT_FOUND | REFUSED | TARGET_NOT_FOUND |

Reproducibility:

- plan_json_identical: True
- plan_id: plan-b5e91d2b7d474a20303f
- eligibility_identical: True
- status: ['VERIFIED', 'VERIFIED']
- mutation_record_identical: True
- post_analysis_identical: True
- result_comparable_identical: True
- entry_contents_identical: True
- outer_apk_bytes_identical: False

## Corpus (read-only; eligibility never relaxed)

- Status: **PASS**; SHA-256 unchanged: True
- 180 call-site targets: 0 ELIGIBLE, 0 CONDITIONALLY_ELIGIBLE, 126 REFUSED, 22 UNSUPPORTED, 32 UNDETERMINED; 0 applied

| APK | Targets | ELIGIBLE | COND. | REFUSED | UNSUPPORTED | UNDETERMINED | Applied | Verification | Unchanged |
|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | 20 | 0 | 0 | 14 | 2 | 4 | 0 | not applicable (no ELIGIBLE plan) | True |
| com.oF2pks.applicationsinfo_19.apk | 20 | 0 | 0 | 16 | 3 | 1 | 0 | not applicable (no ELIGIBLE plan) | True |
| de.audioattack.openlink_28.apk | 20 | 0 | 0 | 14 | 3 | 3 | 0 | not applicable (no ELIGIBLE plan) | True |
| de.danoeh.antennapod_3120295.apk | 20 | 0 | 0 | 16 | 2 | 2 | 0 | not applicable (no ELIGIBLE plan) | True |
| eu.siacs.conversations_4218104.apk | 20 | 0 | 0 | 12 | 3 | 5 | 0 | not applicable (no ELIGIBLE plan) | True |
| godau.fynn.usagedirect_10.apk | 20 | 0 | 0 | 13 | 1 | 6 | 0 | not applicable (no ELIGIBLE plan) | True |
| io.github.muntashirakon.AppManager_451.apk | 20 | 0 | 0 | 11 | 4 | 5 | 0 | not applicable (no ELIGIBLE plan) | True |
| org.mozilla.fennec_fdroid_1560020.apk | 20 | 0 | 0 | 15 | 1 | 4 | 0 | not applicable (no ELIGIBLE plan) | True |
| org.schabi.newpipe_1015_cb84069.apk | 20 | 0 | 0 | 15 | 3 | 2 | 0 | not applicable (no ELIGIBLE plan) | True |

Reason codes (decisions carrying each):

- `ABSTRACT_METHOD`: 2
- `CONSTRUCTOR_INVOCATION`: 18
- `DYNAMIC_CODE_LOADING_PRESENT`: 20
- `INTERFACE_METHOD`: 2
- `NATIVE_DEPENDENCY_UNKNOWN`: 120
- `POLYMORPHIC_INVOCATION`: 63
- `REFLECTION_ANALYSIS_INCOMPLETE`: 20
- `REFLECTION_TARGET_PRESENT`: 1
- `REFLECTION_TARGET_UNKNOWN`: 160
- `REPLACEMENT_INACCESSIBLE`: 2
- `REPLACEMENT_METHOD_NOT_FOUND`: 117
- `REPLACEMENT_SIGNATURE_MISMATCH`: 7
- `SYNTHETIC_METHOD`: 13
- `TARGET_METHOD_NOT_FOUND`: 18
- `TARGET_RELATIONSHIP_UNRESOLVED`: 1

