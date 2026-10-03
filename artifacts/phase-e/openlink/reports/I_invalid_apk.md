# APKForge verification: FAILED

- original: `de.audioattack.openlink_28.apk` sha256 `None`
- modified: `truncated.apk` sha256 `None`
- toolchain: apktool 3.0.3, build-tools 35.0.0, java 25.0.4.1
- overall: **FAILED** (failed: structural)

## RAW DIFF

Not available: no diff

## NORMALIZED DIFF

Not classified.

## SEMANTIC DIFF

| comparator | status | changes | level | note |
|---|---|---:|---|---|

## SECURITY-RELEVANT DIFF

Not computed.

## REQUESTED

- (none: pair verification)

## EXPECTED CHANGES

- none declared

## ACTUAL CHANGES

- none (beyond rebuild noise)

## UNEXPECTED CHANGES

- none

## UNKNOWN / UNDETERMINED

- none

## VERIFICATION

| check | status | summary |
|---|---|---|
| structural | failed | not a ZIP archive |
| signature | undetermined | APK to verify is not a ZIP/APK archive: truncated.apk |
| noise_baseline | undetermined | no no-op baseline: rebuild noise cannot be separated from changes |
| modification | not_applicable | no modifier was run (pair verification) |
| expected_changes | not_applicable | no expected changes declared |
| unexpected_changes | undetermined | the diff was not classified |
| semantic_diff | undetermined | no diff available |
| security_diff | undetermined | not computed |

Overall: **FAILED** — failed: structural

## LIMITATIONS

- signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

## EVIDENCE DISCIPLINE

**Observed fact**

- structural: failed — not a ZIP archive
- signature: undetermined — APK to verify is not a ZIP/APK archive: truncated.apk
- noise_baseline: undetermined — no no-op baseline: rebuild noise cannot be separated from changes
- modification: not_applicable — no modifier was run (pair verification)
- expected_changes: not_applicable — no expected changes declared
- unexpected_changes: undetermined — the diff was not classified
- semantic_diff: undetermined — no diff available
- security_diff: undetermined — not computed

**Inference**

- Differences classified as rebuild noise are inferred to be caused by the rebuild because they are identical to this APK's measured no-op rebuild (content assurance) or match a documented path rule (path_rule assurance).

**Risk assessment**

- None. This report describes changes; it does not assess whether a change is malicious. A clean diff does not prove an APK is malware-free, and a verified signature proves structural/signing validity, not safety.

**Unknown**

- limitation: signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

_Verification establishes structural/signing validity and that observed differences match the plan and the measured rebuild noise, within the stated comparator coverage. It does not establish that the application is safe._
