# APKForge verification: UNDETERMINED

- original: `de.audioattack.openlink_28.apk` sha256 `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`
- modified: `openlink.noop.apk` sha256 `d3a47093bf069f96035939681607fdfb694152e2bb3f1241d79059df5bbbf504`
- package: de.audioattack.openlink 1.5.11
- toolchain: apktool 2.10.0, build-tools 34.0.0, java 17
- overall: **UNDETERMINED** (not established: noise_baseline, unexpected_changes, semantic_diff, security_diff)

## RAW DIFF

Entries: {'added': 66, 'removed': 66, 'modified': 4, 'unchanged': 26}; metadata-only differences: 26

- dex: {'modified': 1}
- manifest: {'modified': 1}
- resource: {'added': 64, 'removed': 64}
- resource_table: {'modified': 1}
- signature: {'added': 2, 'modified': 1, 'removed': 2}

## NORMALIZED DIFF

Mode: content_fingerprint; classification: {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 0, 'unexpected': 0, 'unknown': 74}
Noise by rule: {}
Noise by assurance: {}

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
| files | modified | 72 | content-hash per archive entry, with rename pairing |  |

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

- none

## UNKNOWN / UNDETERMINED

- dex_string removed `~~R8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":21,"pg-map-id":"5d00a76","r8-mode":"full","version":"8.11.18"}` [dex_compiler_marker_removed] — matches path rule 'dex_compiler_marker_removed' but this difference does not occur in the no-op rebuild of this APK
- certificate modified `signing_certificate` [certificate_replaced] — matches path rule 'certificate_replaced' but this difference does not occur in the no-op rebuild of this APK
- file modified `AndroidManifest.xml` [manifest_reencoded] — matches path rule 'manifest_reencoded' but this difference does not occur in the no-op rebuild of this APK
- file added `META-INF/APKFORGE.RSA` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file added `META-INF/APKFORGE.SF` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file removed `META-INF/C4961B96.RSA` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file removed `META-INF/C4961B96.SF` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file modified `META-INF/MANIFEST.MF` [signature_replaced] — matches path rule 'signature_replaced' but this difference does not occur in the no-op rebuild of this APK
- file modified `classes.dex` [dex_reencoded] — matches path rule 'dex_reencoded' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-anydpi-v26/ic_incognito_foreground.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-anydpi-v26/ic_launcher_foreground.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-anydpi-v26/ic_launcher_monochrome.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notification_bg_low_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notification_bg_low_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notification_bg_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notification_bg_normal_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notification_oversize_large_icon_bg.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-hdpi/notify_panel_notification_icon_bg.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-mdpi/notification_bg_low_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-mdpi/notification_bg_low_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-mdpi/notification_bg_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-mdpi/notification_bg_normal_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-mdpi/notify_panel_notification_icon_bg.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-xhdpi/notification_bg_low_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-xhdpi/notification_bg_low_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-xhdpi/notification_bg_normal.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-xhdpi/notification_bg_normal_pressed.9.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable-xhdpi/notify_panel_notification_icon_bg.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_answer.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_answer_low.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_answer_video.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_answer_video_low.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_decline.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/ic_call_decline_low.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/notification_action_background.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/notification_bg.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/notification_bg_low.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/notification_icon_background.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/drawable/notification_tile_bg.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/activity_main.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/custom_dialog.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/ime_base_split_test_activity.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/ime_secondary_split_test_activity.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_action.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_action_tombstone.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_template_custom_big.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_template_icon_group.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_template_part_chronometer.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/layout/notification_template_part_time.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-anydpi-v26/ic_incognito.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-anydpi-v26/ic_incognito_round.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-anydpi-v26/ic_launcher.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-anydpi-v26/ic_launcher_round.xml` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-hdpi/ic_incognito.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-hdpi/ic_incognito_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-hdpi/ic_launcher.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-hdpi/ic_launcher_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-mdpi/ic_incognito.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-mdpi/ic_incognito_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-mdpi/ic_launcher.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-mdpi/ic_launcher_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xhdpi/ic_incognito.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xhdpi/ic_incognito_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xhdpi/ic_launcher.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xhdpi/ic_launcher_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxhdpi/ic_incognito.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxhdpi/ic_incognito_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxhdpi/ic_launcher.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxhdpi/ic_launcher_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxxhdpi/ic_incognito.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxxhdpi/ic_incognito_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxxhdpi/ic_launcher.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file renamed `res/mipmap-xxxhdpi/ic_launcher_round.png` [resource_path_canonicalized] — matches path rule 'resource_path_canonicalized' but this difference does not occur in the no-op rebuild of this APK
- file modified `resources.arsc` [resource_table_reencoded] — matches path rule 'resource_table_reencoded' but this difference does not occur in the no-op rebuild of this APK

## VERIFICATION

| check | status | summary |
|---|---|---|
| structural | passed | archive and container structure valid |
| signature | passed | signature verifies |
| noise_baseline | undetermined | BASELINE_INCOMPATIBLE: java: baseline 25.0.4.1 vs current 17; apktool: baseline 3.0.3 vs current 2.10.0; zipalign: baseline 35.0.0 vs current 34.0.0; apksigner: baseline 0.9 vs current 34.0.0; build_tools: baseline 35.0.0 vs current 34.0.0; android_platform: baseline android-35 vs current android-34 |
| modification | not_applicable | no modifier was run (pair verification) |
| expected_changes | not_applicable | no expected changes declared |
| unexpected_changes | undetermined | 74 change(s) could not be classified |
| semantic_diff | partial | partial: resource_table: not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established)) |
| security_diff | undetermined | 1 security-relevant change(s) could not be classified |

Overall: **UNDETERMINED** — not established: noise_baseline, unexpected_changes, semantic_diff, security_diff

## LIMITATIONS

- components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- native: native code is not analysed; hash and ELF metadata only
- resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- noise baseline: java: baseline 25.0.4.1 vs current 17
- noise baseline: apktool: baseline 3.0.3 vs current 2.10.0
- noise baseline: zipalign: baseline 35.0.0 vs current 34.0.0
- noise baseline: apksigner: baseline 0.9 vs current 34.0.0
- noise baseline: build_tools: baseline 35.0.0 vs current 34.0.0
- noise baseline: android_platform: baseline android-35 vs current android-34
- signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

## EVIDENCE DISCIPLINE

**Observed fact**

- structural: passed — archive and container structure valid
- signature: passed — signature verifies
- noise_baseline: undetermined — BASELINE_INCOMPATIBLE: java: baseline 25.0.4.1 vs current 17; apktool: baseline 3.0.3 vs current 2.10.0; zipalign: baseline 35.0.0 vs current 34.0.0; apksigner: baseline 0.9 vs current 34.0.0; build_tools: baseline 35.0.0 vs current 34.0.0; android_platform: baseline android-35 vs current android-34
- modification: not_applicable — no modifier was run (pair verification)
- expected_changes: not_applicable — no expected changes declared
- unexpected_changes: undetermined — 74 change(s) could not be classified
- semantic_diff: partial — partial: resource_table: not_comparable (resources.arsc differs; its entries are not compared semantically (only byte identity is established))
- security_diff: undetermined — 1 security-relevant change(s) could not be classified

**Inference**

- Differences classified as rebuild noise are inferred to be caused by the rebuild because they are identical to this APK's measured no-op rebuild (content assurance) or match a documented path rule (path_rule assurance).

**Risk assessment**

- None. This report describes changes; it does not assess whether a change is malicious. A clean diff does not prove an APK is malware-free, and a verified signature proves structural/signing validity, not safety.

**Unknown**

- dex_string removed ~~R8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":21,"pg-map-id":"5d00a76","r8-mode":"full","version":"8.11.18"}
- certificate modified signing_certificate
- file modified AndroidManifest.xml
- file added META-INF/APKFORGE.RSA
- file added META-INF/APKFORGE.SF
- file removed META-INF/C4961B96.RSA
- file removed META-INF/C4961B96.SF
- file modified META-INF/MANIFEST.MF
- file modified classes.dex
- file renamed res/drawable-anydpi-v26/ic_incognito_foreground.xml
- file renamed res/drawable-anydpi-v26/ic_launcher_foreground.xml
- file renamed res/drawable-anydpi-v26/ic_launcher_monochrome.xml
- file renamed res/drawable-hdpi/notification_bg_low_normal.9.png
- file renamed res/drawable-hdpi/notification_bg_low_pressed.9.png
- file renamed res/drawable-hdpi/notification_bg_normal.9.png
- file renamed res/drawable-hdpi/notification_bg_normal_pressed.9.png
- file renamed res/drawable-hdpi/notification_oversize_large_icon_bg.png
- file renamed res/drawable-hdpi/notify_panel_notification_icon_bg.png
- file renamed res/drawable-mdpi/notification_bg_low_normal.9.png
- file renamed res/drawable-mdpi/notification_bg_low_pressed.9.png
- file renamed res/drawable-mdpi/notification_bg_normal.9.png
- file renamed res/drawable-mdpi/notification_bg_normal_pressed.9.png
- file renamed res/drawable-mdpi/notify_panel_notification_icon_bg.png
- file renamed res/drawable-xhdpi/notification_bg_low_normal.9.png
- file renamed res/drawable-xhdpi/notification_bg_low_pressed.9.png
- file renamed res/drawable-xhdpi/notification_bg_normal.9.png
- file renamed res/drawable-xhdpi/notification_bg_normal_pressed.9.png
- file renamed res/drawable-xhdpi/notify_panel_notification_icon_bg.png
- file renamed res/drawable/ic_call_answer.xml
- file renamed res/drawable/ic_call_answer_low.xml
- file renamed res/drawable/ic_call_answer_video.xml
- file renamed res/drawable/ic_call_answer_video_low.xml
- file renamed res/drawable/ic_call_decline.xml
- file renamed res/drawable/ic_call_decline_low.xml
- file renamed res/drawable/notification_action_background.xml
- file renamed res/drawable/notification_bg.xml
- file renamed res/drawable/notification_bg_low.xml
- file renamed res/drawable/notification_icon_background.xml
- file renamed res/drawable/notification_tile_bg.xml
- file renamed res/layout/activity_main.xml
- file renamed res/layout/custom_dialog.xml
- file renamed res/layout/ime_base_split_test_activity.xml
- file renamed res/layout/ime_secondary_split_test_activity.xml
- file renamed res/layout/notification_action.xml
- file renamed res/layout/notification_action_tombstone.xml
- file renamed res/layout/notification_template_custom_big.xml
- file renamed res/layout/notification_template_icon_group.xml
- file renamed res/layout/notification_template_part_chronometer.xml
- file renamed res/layout/notification_template_part_time.xml
- file renamed res/mipmap-anydpi-v26/ic_incognito.xml
- file renamed res/mipmap-anydpi-v26/ic_incognito_round.xml
- file renamed res/mipmap-anydpi-v26/ic_launcher.xml
- file renamed res/mipmap-anydpi-v26/ic_launcher_round.xml
- file renamed res/mipmap-hdpi/ic_incognito.png
- file renamed res/mipmap-hdpi/ic_incognito_round.png
- file renamed res/mipmap-hdpi/ic_launcher.png
- file renamed res/mipmap-hdpi/ic_launcher_round.png
- file renamed res/mipmap-mdpi/ic_incognito.png
- file renamed res/mipmap-mdpi/ic_incognito_round.png
- file renamed res/mipmap-mdpi/ic_launcher.png
- file renamed res/mipmap-mdpi/ic_launcher_round.png
- file renamed res/mipmap-xhdpi/ic_incognito.png
- file renamed res/mipmap-xhdpi/ic_incognito_round.png
- file renamed res/mipmap-xhdpi/ic_launcher.png
- file renamed res/mipmap-xhdpi/ic_launcher_round.png
- file renamed res/mipmap-xxhdpi/ic_incognito.png
- file renamed res/mipmap-xxhdpi/ic_incognito_round.png
- file renamed res/mipmap-xxhdpi/ic_launcher.png
- file renamed res/mipmap-xxhdpi/ic_launcher_round.png
- file renamed res/mipmap-xxxhdpi/ic_incognito.png
- file renamed res/mipmap-xxxhdpi/ic_incognito_round.png
- file renamed res/mipmap-xxxhdpi/ic_launcher.png
- file renamed res/mipmap-xxxhdpi/ic_launcher_round.png
- file modified resources.arsc
- limitation: components: <activity-alias> is not modelled as a component; alias changes are reported by manifest_tree only
- limitation: native: native code is not analysed; hash and ELF metadata only
- limitation: resources: res/ binary XML and images are compared by content hash, not decoded; a same-path content change cannot be interpreted semantically
- limitation: resource_table: not_comparable: resources.arsc differs; its entries are not compared semantically (only byte identity is established)
- limitation: signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their validity is established by apksigner, not by the diff

_Verification establishes structural/signing validity and that observed differences match the plan and the measured rebuild noise, within the stated comparator coverage. It does not establish that the application is safe._
