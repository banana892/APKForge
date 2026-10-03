# APKForge verification: FAILED

- original: `de.audioattack.openlink_28.apk` sha256 `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`
- modified: `signed.apk` sha256 `5a8a55330dbfd20527f1d86e38918f1ee9422638635e79774a244855ebfba180`
- package: de.audioattack.openlink 1.5.11
- overall: **FAILED** (failed: unexpected_changes)

## RAW DIFF

Entries: {'added': 66, 'removed': 82, 'modified': 4, 'unchanged': 10}; metadata-only differences: 10

- dex: {'modified': 1}
- manifest: {'modified': 1}
- meta_inf: {'removed': 16}
- resource: {'added': 64, 'removed': 64}
- resource_table: {'modified': 1}
- signature: {'added': 2, 'modified': 1, 'removed': 2}

## NORMALIZED DIFF

Mode: content_fingerprint; classification: {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 65, 'unexpected': 16, 'unknown': 9}
Noise by rule: {'dex_compiler_marker_removed': 1, 'signature_replaced': 3, 'dex_reencoded': 1, 'resource_path_canonicalized': 60}
Noise by assurance: {'content': 62, 'path_only': 3}

## SEMANTIC DIFF

| comparator | status | changes | level | note |
|---|---|---:|---|---|
| identity | unchanged | 0 | semantic: package, version, SDK levels |  |
| manifest | unchanged | 0 | semantic: selected <application> attributes, SDK levels |  |
| manifest_tree | unchanged | 0 | structural: every manifest element and attribute (decoded XML) |  |
| permissions | unchanged | 0 | semantic: uses-permission and declared permissions |  |
| components | unchanged | 0 | semantic: activities, services, receivers, providers (activity-alias: tree only) |  |
| intent_filters | unchanged | 0 | semantic: actions, categories, data per component |  |
| certificate | modified | 2 | signing certificate fingerprints (SHA-256) |  |
| dex | unchanged | 0 | semantic: DEX files, classes, methods (code hash), fields |  |
| strings | modified | 1 | semantic: DEX string pool values |  |
| network | unchanged | 0 | extracted URLs, domains, IPs |  |
| native | unchanged | 0 | content-hash and ELF metadata per lib/<abi>/<name>.so |  |
| resources | modified | 64 | content-hash per res/ entry (binary XML is not decoded) |  |
| resource_table | not_comparable | 1 | content-hash of resources.arsc; entries are not compared | resources.arsc differs; its entries are not compared semantically (only byte identity is established) |
| assets | unchanged | 0 | content-hash per assets/ entry |  |
| embedded | unchanged | 0 | embedded APK/DEX/executable presence |  |
| files | modified | 88 | content-hash per archive entry, with rename pairing |  |

## SECURITY-RELEVANT DIFF

_Observed changes only. A change in a security-relevant area is not evidence of malicious behaviour, and an empty section is not evidence of safety._

### Permissions (complete)

- no change observed

### Components (complete)

- no change observed

### Intent filters (complete)

- no change observed

### Certificate (complete)

- modified signing certificate [unknown] — evidence: APK signature block / META-INF

### Network domains and IPs (complete)

- no change observed

### URLs (complete)

- no change observed

### Native libraries (complete)

- no change observed

### DEX classes (complete)

- no change observed

### Embedded executables/archives (complete)

- no change observed

### Sensitive manifest changes (complete)

- no change observed

### Other manifest elements (complete)

- no change observed

## REQUESTED

- (none: pair verification)

## EXPECTED CHANGES

- none declared

## ACTUAL CHANGES

- none (beyond rebuild noise)

## UNEXPECTED CHANGES

- file removed `META-INF/androidx.annotation_annotation-experimental.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.arch.core_core-runtime.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.core_core-viewtree.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.core_core.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.interpolator_interpolator.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.lifecycle_lifecycle-runtime.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.profileinstaller_profileinstaller.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.startup_startup-runtime.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.tracing_tracing.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx.versionedparcelable_versionedparcelable.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/androidx/annotation/annotation/LICENSE.txt` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/com/android/build/gradle/app-metadata.properties` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/kotlinx_coroutines_android.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/kotlinx_coroutines_core.version` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/version-control-info.textproto` — not declared by the modification and not in this APK's no-op baseline
- file removed `META-INF/versions/9/OSGI-INF/MANIFEST.MF` — not declared by the modification and not in this APK's no-op baseline

## UNKNOWN / UNDETERMINED

- certificate modified `signing_certificate` [certificate_replaced] — new certificate ca8cf670324cd90bd0c512e7a1c8d1925eaa67863d151345fe386dae42ac0f13 is not the signing certificate f769555534625181026172519a074c1c4eefc5f5318aa6913ebb80ca466e972b (rule 'certificate_replaced')
- file modified `AndroidManifest.xml` [manifest_reencoded] — content differs from the no-op rebuild of this APK (rule 'manifest_reencoded')
- file added `META-INF/C5.RSA` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file added `META-INF/C5.SF` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-anydpi-v26/ic_incognito_foreground.xml` [resource_path_canonicalized] — content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')
- file renamed `res/drawable-anydpi-v26/ic_launcher_foreground.xml` [resource_path_canonicalized] — content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')
- file renamed `res/drawable-anydpi-v26/ic_launcher_monochrome.xml` [resource_path_canonicalized] — content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')
- file renamed `res/drawable/notification_action_background.xml` [resource_path_canonicalized] — content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')
- file modified `resources.arsc` [resource_table_reencoded] — content differs from the no-op rebuild of this APK (rule 'resource_table_reencoded')

## VERIFICATION

| check | status | summary |
|---|---|---|
| structural | passed | archive and container structure valid |
| signature | passed | signature verifies |
| noise_baseline | passed | content-aware baseline; build toolchain not declared, so only exact content identity is accepted as noise |
| modification | not_applicable | no modifier was run (pair verification) |
| expected_changes | not_applicable | no expected changes declared |
| unexpected_changes | failed | 16 unexpected change(s) detected |
| semantic_diff | partial | partial: resource_table: not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established)) |
| security_diff | undetermined | 1 security-relevant change(s) could not be classified |

Overall: **FAILED** — failed: unexpected_changes

## LIMITATIONS

- components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- native: native code is not analysed; hash and ELF metadata only
- resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- noise baseline: the toolchain that built the APK under test is not identified; noise is accepted only on exact content identity, other rebuild differences are UNKNOWN
- signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

## EVIDENCE DISCIPLINE

**Observed fact**

- structural: passed — archive and container structure valid
- signature: passed — signature verifies
- noise_baseline: passed — content-aware baseline; build toolchain not declared, so only exact content identity is accepted as noise
- modification: not_applicable — no modifier was run (pair verification)
- expected_changes: not_applicable — no expected changes declared
- unexpected_changes: failed — 16 unexpected change(s) detected
- semantic_diff: partial — partial: resource_table: not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established))
- security_diff: undetermined — 1 security-relevant change(s) could not be classified

**Inference**

- Differences classified as rebuild noise are inferred to be caused by the rebuild because they are identical to this APK's measured no-op rebuild (content assurance) or match a documented path rule (path_rule assurance).

**Risk assessment**

- None. This report describes changes; it does not assess whether a change is malicious. A clean diff does not prove an APK is malware-free, and a verified signature proves structural/signing validity, not safety.

**Unknown**

- certificate modified signing_certificate
- file modified AndroidManifest.xml
- file added META-INF/C5.RSA
- file added META-INF/C5.SF
- file renamed res/drawable-anydpi-v26/ic_incognito_foreground.xml
- file renamed res/drawable-anydpi-v26/ic_launcher_foreground.xml
- file renamed res/drawable-anydpi-v26/ic_launcher_monochrome.xml
- file renamed res/drawable/notification_action_background.xml
- file modified resources.arsc
- limitation: components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- limitation: native: native code is not analysed; hash and ELF metadata only
- limitation: resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- limitation: resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- limitation: noise baseline: the toolchain that built the APK under test is not identified; noise is accepted only on exact content identity, other rebuild differences are UNKNOWN
- limitation: signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

_Verification establishes structural/signing validity and that observed differences match the plan and the measured rebuild noise, within the stated comparator coverage. It does not establish that the application is safe._
