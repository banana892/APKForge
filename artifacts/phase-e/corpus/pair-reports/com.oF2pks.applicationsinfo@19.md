# APKForge verification: VERIFIED

- original: `com.oF2pks.applicationsinfo_19.apk` sha256 `c0188f5f1f566e12324bd6bf4bf4f1b9408d852c6cc6b113706503031f13eebd`
- modified: `com.oF2pks.applicationsinfo_19.noop2.apk` sha256 `a8b23f7171ae8a4e9ae6d3011b7d237bdcaf381a78a9f690af6ff1ee121754d8`
- package: com.oF2pks.applicationsinfo 1.7-19
- toolchain: apktool 3.0.3, build-tools 35.0.0, java 25.0.4.1
- overall: **VERIFIED** (every applicable check passed)

## RAW DIFF

Entries: {'added': 32, 'removed': 32, 'modified': 4, 'unchanged': 1}; metadata-only differences: 1

- dex: {'modified': 1}
- manifest: {'modified': 1}
- resource: {'added': 30, 'removed': 30}
- resource_table: {'modified': 1}
- signature: {'added': 2, 'modified': 1, 'removed': 2}

## NORMALIZED DIFF

Mode: content_fingerprint; classification: {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 42, 'unexpected': 0, 'unknown': 0}
Noise by rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'manifest_reencoded': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'baseline_residue': 4, 'resource_path_canonicalized': 28, 'resource_table_reencoded': 1}
Noise by assurance: {'content': 36, 'path_only': 5, 'signer': 1}

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
| resources | modified | 32 | content-hash per res/ entry (binary XML is not decoded) |  |
| resource_table | not_comparable | 1 | content-hash of resources.arsc; entries are not compared | resources.arsc differs; its entries are not compared semantically (only byte identity is established) |
| assets | unchanged | 0 | content-hash per assets/ entry |  |
| embedded | unchanged | 0 | embedded APK/DEX/executable presence |  |
| files | modified | 40 | content-hash per archive entry, with rename pairing |  |

## SECURITY-RELEVANT DIFF

_Observed changes only. A change in a security-relevant area is not evidence of malicious behaviour, and an empty section is not evidence of safety._

### Permissions (complete)

- no change observed

### Components (complete)

- no change observed

### Intent filters (complete)

- no change observed

### Certificate (complete)

- modified signing certificate [rebuild_noise] — evidence: APK signature block / META-INF

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

- none

## UNKNOWN / UNDETERMINED

- none

## VERIFICATION

| check | status | summary |
|---|---|---|
| structural | passed | archive and container structure valid |
| signature | passed | signature verifies with the expected signer |
| noise_baseline | passed | content-aware baseline for this APK and toolchain |
| modification | not_applicable | no modifier was run (pair verification) |
| expected_changes | not_applicable | no expected changes declared |
| unexpected_changes | passed | no unexpected or unclassified change |
| semantic_diff | passed | every comparator completed |
| security_diff | passed | 1 security-relevant change(s), none unexpected |

Overall: **VERIFIED** — every applicable check passed

## LIMITATIONS

- components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- native: native code is not analysed; hash and ELF metadata only
- resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

## EVIDENCE DISCIPLINE

**Observed fact**

- structural: passed — archive and container structure valid
- signature: passed — signature verifies with the expected signer
- noise_baseline: passed — content-aware baseline for this APK and toolchain
- modification: not_applicable — no modifier was run (pair verification)
- expected_changes: not_applicable — no expected changes declared
- unexpected_changes: passed — no unexpected or unclassified change
- semantic_diff: passed — every comparator completed
- security_diff: passed — 1 security-relevant change(s), none unexpected

**Inference**

- Differences classified as rebuild noise are inferred to be caused by the rebuild because they are identical to this APK's measured no-op rebuild (content assurance) or match a documented path rule (path_rule assurance).

**Risk assessment**

- None. This report describes changes; it does not assess whether a change is malicious. A clean diff does not prove an APK is malware-free, and a verified signature proves structural/signing validity, not safety.

**Unknown**

- limitation: components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- limitation: native: native code is not analysed; hash and ELF metadata only
- limitation: resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- limitation: resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- limitation: signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

_Verification establishes structural/signing validity and that observed differences match the plan and the measured rebuild noise, within the stated comparator coverage. It does not establish that the application is safe._
