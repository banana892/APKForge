# Phase H.7 validation summary (20261006T185420Z)

Overall: **PASS**

## Framework (reference test-modkit, synthetic APK)

- Status: **PASS**

| Scenario | Status | Failure | Expected | Published | Original unchanged |
|---|---|---|---|---|---|
| success | SUCCESS | - | SUCCESS | True | True |
| noop | NO_OP | - | NO_OP | False | True |
| noop-undeclared | OUTPUT_INVALID | OUTPUT_UNCHANGED | OUTPUT_INVALID / OUTPUT_UNCHANGED | False | True |
| noop-empty | NO_OP | - | NO_OP | False | True |
| missing-output | OUTPUT_MISSING | OUTPUT_MISSING | OUTPUT_MISSING / OUTPUT_MISSING | False | True |
| no-declaration | OUTPUT_INVALID | UNEXPECTED_ARTIFACT | OUTPUT_INVALID / UNEXPECTED_ARTIFACT | False | True |
| invalid-apk | OUTPUT_INVALID | OUTPUT_MALFORMED | OUTPUT_INVALID / OUTPUT_MALFORMED | False | True |
| truncated-apk | OUTPUT_INVALID | OUTPUT_MALFORMED | OUTPUT_INVALID / OUTPUT_MALFORMED | False | True |
| nonzero-exit | EXECUTION_FAILED | NON_ZERO_EXIT | EXECUTION_FAILED / NON_ZERO_EXIT | False | True |
| timeout | TIMEOUT | TIMEOUT | TIMEOUT / TIMEOUT | False | True |
| crash | EXECUTION_FAILED | PROCESS_CRASH | EXECUTION_FAILED / PROCESS_CRASH | False | True |
| multiple-outputs | OUTPUT_INVALID | OUTPUT_AMBIGUOUS | OUTPUT_INVALID / OUTPUT_AMBIGUOUS | False | True |
| extra-artifact | OUTPUT_INVALID | UNEXPECTED_ARTIFACT | OUTPUT_INVALID / UNEXPECTED_ARTIFACT | False | True |
| outside-workspace | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE | OUTPUT_INVALID / OUTPUT_OUTSIDE_WORKSPACE | False | True |
| outside-undeclared | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE | OUTPUT_INVALID / OUTPUT_OUTSIDE_WORKSPACE | False | True |
| symlink-escape | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE | OUTPUT_INVALID / OUTPUT_OUTSIDE_WORKSPACE | False | True |
| malicious-filename | OUTPUT_INVALID | UNSAFE_FILENAME | OUTPUT_INVALID / UNSAFE_FILENAME | False | True |
| traversal-entry | OUTPUT_INVALID | OUTPUT_MALFORMED | OUTPUT_INVALID / OUTPUT_MALFORMED | False | True |
| directory-output | OUTPUT_INVALID | OUTPUT_NOT_REGULAR_FILE | OUTPUT_INVALID / OUTPUT_NOT_REGULAR_FILE | False | True |
| mutate-input | EXECUTION_FAILED | INPUT_MUTATED | EXECUTION_FAILED / INPUT_MUTATED | False | True |
| noisy | SUCCESS | - | SUCCESS | True | True |
| echo-env | SUCCESS | - | SUCCESS | True | True |
| echo-args | SUCCESS | - | SUCCESS | True | True |
| replace-output-dir | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE | OUTPUT_INVALID / OUTPUT_OUTSIDE_WORKSPACE | False | True |

- Parent environment leaked: False (child env keys: HOME, LANG, PATH, TMPDIR)
- Secret occurrences in logs/metadata/result: 0
- Shell metacharacters interpreted: False
- Reproducible output bytes: True; provenance identical modulo ids/timestamps/paths: True
- Availability states: {'default': 'AVAILABLE', 'not_installed': 'NOT_INSTALLED', 'dependency_missing': 'DEPENDENCY_MISSING', 'version_unsupported': 'VERSION_UNSUPPORTED', 'disabled': 'EXECUTION_UNAVAILABLE'}

## Pipeline (published fixture, BuildService, H.4)

- Status: **PASS**
- Diff files added: 1
- Privacy delta: +0 -0 =0
- Security delta: +0 -0 =0
- BuildService rebuilds: {'control': True, 'modkit_output': True}
- H.4 undeclared: FAILED (unexpected: ['assets/test-modkit/marker.txt'])
- H.4 declared: VERIFIED (expected: ['assets/test-modkit/marker.txt'], noise: 7)
- Original unchanged: True

## Corpus (test-modkit success)

- Status: **PASS**; SHA-256 unchanged: True

| APK | Status | Marker | Seconds |
|---|---|---|---|
| com.emanuelef.remote_capture_95.apk | SUCCESS | True | 1.6 |
| com.oF2pks.applicationsinfo_19.apk | SUCCESS | True | 0.1 |
| de.audioattack.openlink_28.apk | SUCCESS | True | 0.1 |
| de.danoeh.antennapod_3120295.apk | SUCCESS | True | 1.0 |
| eu.siacs.conversations_4218104.apk | SUCCESS | True | 1.4 |
| godau.fynn.usagedirect_10.apk | SUCCESS | True | 0.4 |
| io.github.muntashirakon.AppManager_451.apk | SUCCESS | True | 2.3 |
| org.mozilla.fennec_fdroid_1560020.apk | SUCCESS | True | 8.0 |
| org.schabi.newpipe_1015_cb84069.apk | SUCCESS | True | 0.8 |
