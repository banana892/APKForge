# Phase E: OpenLink verification scenarios — PASS

Generated 2026-10-03T03:50:11.707246+00:00. APK `de.audioattack.openlink_28.apk` sha256 `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed` (unchanged after the run: True). Baseline `tests/corpus/results/phase-e-noise-baseline.json`. APKForge fda21291a158a23d95d79c85dc5bf0ab94a131e1 (dirty: True).

| scenario | expected | result | matrix overall | classification | problems |
|---|---|---|---|---|---|
| A_noop | VERIFIED | VERIFIED | VERIFIED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0} | none |
| B_c5 | verified | verified | VERIFIED | {'expected_modification': 2, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 0, 'unknown': 0} | none |
| C_undeclared_manifest | failed | failed | FAILED | {'expected_modification': 0, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 1, 'unknown': 0} | none |
| C2_declared_manifest | unverified | unverified | UNDETERMINED | {'expected_modification': 1, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 0, 'unknown': 0} | none |
| D_marker | verified | verified | VERIFIED | {'expected_modification': 1, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0} | none |
| E_combined | verified | verified | VERIFIED | {'expected_modification': 3, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 0, 'unknown': 0} | none |
| F_undeclared_file | failed | failed | FAILED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 1, 'unknown': 0} | none |
| G_missing_expectation | failed | failed | FAILED | {'expected_modification': 1, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0} | none |
| H_content_hash_v2 | FAILED | FAILED | FAILED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 73, 'unexpected': 1, 'unknown': 0} | none |
| H_content_hash_legacy | UNDETERMINED | UNDETERMINED | UNDETERMINED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0} | none |
| I_invalid_apk | FAILED | FAILED | FAILED | None | none |
| J_invalid_signature | FAILED | FAILED | FAILED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 73, 'unexpected': 1, 'unknown': 0} | none |
| K1_declared_other_toolchain | UNDETERMINED | UNDETERMINED | UNDETERMINED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 0, 'unexpected': 0, 'unknown': 74} | none |
| K2_real_old_toolchain_undeclared | FAILED|UNDETERMINED | FAILED | FAILED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 65, 'unexpected': 16, 'unknown': 9} | none |
| K3_real_old_toolchain_declared | FAILED|UNDETERMINED | FAILED | FAILED | {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 0, 'unexpected': 16, 'unknown': 74} | none |

## Details

### A_noop

- overall_reason: every applicable check passed
- baseline_status: COMPATIBLE
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- signature: signature verifies
- structural: archive and container structure valid

### B_c5

- overall_reason: every applicable check passed
- baseline_status: COMPATIBLE
- derived: {'declared_expected': 2, 'baseline_fingerprint_entries': 74, 'planned_entries': ['AndroidManifest.xml'], 'derived_noise': 73}
- expected_observed: ['uses_permission removed android.permission.RECEIVE_BOOT_COMPLETED', 'component modified de.audioattack.openlink.conf.PackageChangeBroadcastReceiver']
- planned_entries: ['AndroidManifest.xml']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'passed', 'expected_changes': 'passed', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'permissions': ['removed android.permission.RECEIVE_BOOT_COMPLETED [expected_modification]'], 'components': ['modified receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver [expected_modification]'], 'certificate': ['modified signing certificate [rebuild_noise]']}

### C_undeclared_manifest

- overall_reason: failed: unexpected_changes, security_diff
- baseline_status: COMPATIBLE
- planned_entries: ['AndroidManifest.xml']
- unexpected: ["manifest_element added application#0/meta-data[name=apkforge.test.phase_e]: not declared by the modification and not in this APK's no-op baseline"]
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'undetermined', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'passed', 'security_diff': 'failed'}
- security: {'certificate': ['modified signing certificate [rebuild_noise]'], 'manifest_other': ['added application#0/meta-data[name=apkforge.test.phase_e] [unexpected]']}

### C2_declared_manifest

- overall_reason: not established: modification
- baseline_status: COMPATIBLE
- expected_observed: ['manifest_element added application#0/meta-data[name=apkforge.test.phase_e]']
- planned_entries: ['AndroidManifest.xml']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'undetermined', 'expected_changes': 'passed', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'certificate': ['modified signing certificate [rebuild_noise]'], 'manifest_other': ['added application#0/meta-data[name=apkforge.test.phase_e] [expected_modification]']}

### D_marker

- overall_reason: every applicable check passed
- baseline_status: COMPATIBLE
- expected_observed: ['file added assets/apkforge-test/marker.txt']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'passed', 'expected_changes': 'passed', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'certificate': ['modified signing certificate [rebuild_noise]']}

### E_combined

- overall_reason: every applicable check passed
- baseline_status: COMPATIBLE
- expected_observed: ['uses_permission removed android.permission.RECEIVE_BOOT_COMPLETED', 'component modified de.audioattack.openlink.conf.PackageChangeBroadcastReceiver', 'file added assets/apkforge-test/marker.txt']
- planned_entries: ['AndroidManifest.xml']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'passed', 'expected_changes': 'passed', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'permissions': ['removed android.permission.RECEIVE_BOOT_COMPLETED [expected_modification]'], 'components': ['modified receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver [expected_modification]'], 'certificate': ['modified signing certificate [rebuild_noise]']}

### F_undeclared_file

- overall_reason: failed: unexpected_changes
- baseline_status: COMPATIBLE
- unexpected: ["file added assets/apkforge-test/undeclared.txt: not declared by the modification and not in this APK's no-op baseline"]
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'undetermined', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'certificate': ['modified signing certificate [rebuild_noise]']}

### G_missing_expectation

- overall_reason: failed: modification, expected_changes
- baseline_status: COMPATIBLE
- expected_observed: ['file added assets/apkforge-test/missing-expectation.txt']
- expected_missing: ['uses_permission removed android.permission.INTERNET']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'failed', 'expected_changes': 'failed', 'unexpected_changes': 'passed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- security: {'certificate': ['modified signing certificate [rebuild_noise]']}

### H_content_hash_v2

- overall_reason: failed: unexpected_changes
- baseline_status: COMPATIBLE
- unexpected: ["file renamed res/drawable-anydpi-v26/ic_incognito_foreground.xml: content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')"]
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- tampered_entry: res/drawable-anydpi-v26/ic_incognito_foreground.xml
- signature: signature verifies
- structural: archive and container structure valid

### H_content_hash_legacy

- overall_reason: not established: noise_baseline, unexpected_changes, semantic_diff
- baseline_status: LEGACY_PATH_RULES
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'partial', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'partial', 'semantic_diff': 'partial', 'security_diff': 'passed'}
- tampered_entry: res/drawable-anydpi-v26/ic_incognito_foreground.xml
- note: schema-1 path rules accept the tampered entry as resource_path_canonicalized noise (the blind spot Phase E closes); the matrix is UNDETERMINED only because legacy noise is path-rule assured
- signature: signature verifies
- structural: archive and container structure valid

### I_invalid_apk

- overall_reason: failed: structural
- matrix: {'structural': 'failed', 'signature': 'undetermined', 'noise_baseline': 'undetermined', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'undetermined', 'semantic_diff': 'undetermined', 'security_diff': 'undetermined'}
- signature: APK to verify is not a ZIP/APK archive: truncated.apk
- structural: not a ZIP archive

### J_invalid_signature

- overall_reason: failed: signature, unexpected_changes
- baseline_status: COMPATIBLE
- unexpected: ["file renamed res/drawable-anydpi-v26/ic_incognito_foreground.xml: content differs from the no-op rebuild of this APK (rule 'resource_path_canonicalized')"]
- matrix: {'structural': 'passed', 'signature': 'failed', 'noise_baseline': 'passed', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'passed', 'security_diff': 'passed'}
- signature: zipalign -c: final APK is not 4-byte aligned (with page-aligned .so).; apksigner verify did not verify the APK (exit 1).
- structural: archive and container structure valid

### K1_declared_other_toolchain

- overall_reason: not established: noise_baseline, unexpected_changes, semantic_diff, security_diff
- baseline_status: BASELINE_INCOMPATIBLE
- unknown_sample: ['dex_string removed ~~R8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":21,"pg-map-id":"5d00a76","r8-mode":"full","version":"8.11.18"}', 'certificate modified signing_certificate', 'file modified AndroidManifest.xml', 'file added META-INF/APKFORGE.RSA', 'file added META-INF/APKFORGE.SF']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'undetermined', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'undetermined', 'semantic_diff': 'partial', 'security_diff': 'undetermined'}
- signature: signature verifies
- structural: archive and container structure valid

### K2_real_old_toolchain_undeclared

- overall_reason: failed: unexpected_changes
- baseline_status: TOOLCHAIN_UNKNOWN
- unexpected: ["file removed META-INF/androidx.annotation_annotation-experimental.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.arch.core_core-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.core_core-viewtree.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.core_core.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.interpolator_interpolator.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.lifecycle_lifecycle-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.profileinstaller_profileinstaller.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.startup_startup-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.tracing_tracing.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.versionedparcelable_versionedparcelable.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx/annotation/annotation/LICENSE.txt: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/com/android/build/gradle/app-metadata.properties: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/kotlinx_coroutines_android.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/kotlinx_coroutines_core.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/version-control-info.textproto: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/versions/9/OSGI-INF/MANIFEST.MF: not declared by the modification and not in this APK's no-op baseline"]
- unknown_sample: ['certificate modified signing_certificate', 'file modified AndroidManifest.xml', 'file added META-INF/C5.RSA', 'file added META-INF/C5.SF', 'file renamed res/drawable-anydpi-v26/ic_incognito_foreground.xml']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'passed', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'partial', 'security_diff': 'undetermined'}
- signature: signature verifies
- structural: archive and container structure valid

### K3_real_old_toolchain_declared

- overall_reason: failed: unexpected_changes
- baseline_status: BASELINE_INCOMPATIBLE
- unexpected: ["file removed META-INF/androidx.annotation_annotation-experimental.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.arch.core_core-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.core_core-viewtree.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.core_core.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.interpolator_interpolator.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.lifecycle_lifecycle-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.profileinstaller_profileinstaller.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.startup_startup-runtime.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.tracing_tracing.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx.versionedparcelable_versionedparcelable.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/androidx/annotation/annotation/LICENSE.txt: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/com/android/build/gradle/app-metadata.properties: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/kotlinx_coroutines_android.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/kotlinx_coroutines_core.version: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/version-control-info.textproto: not declared by the modification and not in this APK's no-op baseline", "file removed META-INF/versions/9/OSGI-INF/MANIFEST.MF: not declared by the modification and not in this APK's no-op baseline"]
- unknown_sample: ['dex_string removed ~~R8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":21,"pg-map-id":"5d00a76","r8-mode":"full","version":"8.11.18"}', 'certificate modified signing_certificate', 'file modified AndroidManifest.xml', 'file removed META-INF/C4961B96.RSA', 'file removed META-INF/C4961B96.SF']
- matrix: {'structural': 'passed', 'signature': 'passed', 'noise_baseline': 'undetermined', 'modification': 'not_applicable', 'expected_changes': 'not_applicable', 'unexpected_changes': 'failed', 'semantic_diff': 'partial', 'security_diff': 'undetermined'}
- signature: signature verifies
- structural: archive and container structure valid

Modified APKs are not installed or run. VERIFIED means structurally valid, correctly signed and changed only as planned within the comparator coverage; it does not mean the APK is safe.
