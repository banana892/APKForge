# Phase D validation: PASS

Generated 2026-10-03T03:50:27.171977+00:00. APK `de.audioattack.openlink_28.apk`, original SHA-256 `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`.
APKForge commit `fda21291a158a23d95d79c85dc5bf0ab94a131e1` (dirty: True).
Toolchain: java 25.0.4.1, apktool 3.0.3, zipalign 35.0.0, apksigner 0.9, build_tools 35.0.0, android_platform android-35.

| scenario | modifiers | expected | status | executed / verified / not attempted / rolled back | expected obs. | unexpected | stages | original |
|---|---|---|---|---|---|---|---|---|
| A | c5.disable_boot_receiver | verified | **verified** | 1 / 1 / 0 / 0 | 2 | 0 | prepare, decode, build, align, sign, verify | unchanged |
| B | test.marker_asset | verified | **verified** | 1 / 1 / 0 / 0 | 1 | 0 | prepare, decode, build, align, sign, verify | unchanged |
| C | c5.disable_boot_receiver → test.marker_asset | verified | **verified** | 2 / 2 / 0 / 0 | 3 | 0 | prepare, decode, build, align, sign, verify | unchanged |
| D | test.marker_asset → test.failing → c5.disable_boot_receiver | failed | **failed** | 1 / 0 / 1 / 1 | 0 | 0 | prepare, decode | unchanged |
| E | c5.disable_boot_receiver → test.marker_asset | dry_run | **dry_run** | 0 / 0 / 0 / 0 | 0 | 0 | prepare, decode | unchanged |
| F | test.undeclared | failed | **failed** | 1 / 0 / 0 / 0 | 0 | 1 | prepare, decode, build, align, sign, verify | unchanged |

## Details

### A: verified -> verified

- `c5.disable_boot_receiver`: success, verified — remove <uses-permission android:name=android.permission.RECEIVE_BOOT_COMPLETED>; set android:enabled="false" on <receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver>
- expected modifications: ['component modified de.audioattack.openlink.conf.PackageChangeBroadcastReceiver', 'uses_permission removed android.permission.RECEIVE_BOOT_COMPLETED']
- classification: {'expected_modification': 2, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 0, 'unknown': 0}
- noise per rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1}
- original checkpoints: ['planning', 'apply c5.disable_boot_receiver', 'build pipeline', 'diff']

### B: verified -> verified

- `test.marker_asset`: success, verified — added assets/apkforge-test/marker.txt
- expected modifications: ['file added assets/apkforge-test/marker.txt']
- classification: {'expected_modification': 1, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0}
- noise per rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'manifest_reencoded': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1}
- original checkpoints: ['planning', 'apply test.marker_asset', 'build pipeline', 'diff']

### C: verified -> verified

- `c5.disable_boot_receiver`: success, verified — remove <uses-permission android:name=android.permission.RECEIVE_BOOT_COMPLETED>; set android:enabled="false" on <receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver>
- `test.marker_asset`: success, verified — added assets/apkforge-test/marker.txt
- expected modifications: ['component modified de.audioattack.openlink.conf.PackageChangeBroadcastReceiver', 'file added assets/apkforge-test/marker.txt', 'uses_permission removed android.permission.RECEIVE_BOOT_COMPLETED']
- classification: {'expected_modification': 3, 'planned_entry': 1, 'rebuild_noise': 73, 'unexpected': 0, 'unknown': 0}
- noise per rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1}
- original checkpoints: ['planning', 'apply c5.disable_boot_receiver', 'apply test.marker_asset', 'build pipeline', 'diff']

### D: failed -> failed

- `test.marker_asset`: success, not_verified, rolled back — added assets/apkforge-test/marker.txt
- `test.failing`: failed, not_executed — Apply exception: RuntimeError: simulated modifier failure
- `c5.disable_boot_receiver`: pending, not_executed — Not attempted: execution stopped at test.failing
- rollback: {'attempted': True, 'restored': True, 'modifiers': ['test.marker_asset'], 'errors': [], 'scope': 'decoded project in the BuildService workspace'}
- original checkpoints: ['planning', 'apply test.marker_asset', 'apply test.failing']
- failure: apply: test.failing: Apply exception: RuntimeError: simulated modifier failure

### E: dry_run -> dry_run

- `c5.disable_boot_receiver`: dry_run, not_executed — Would apply: remove <uses-permission android:name=android.permission.RECEIVE_BOOT_COMPLETED>; set android:enabled="false" on <receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver>
- `test.marker_asset`: dry_run, not_executed — Would apply: add assets/apkforge-test/marker.txt (125 bytes, fixed text)
- original checkpoints: ['planning']

### F: failed -> failed

- `test.undeclared`: success, not_verified — add assets/apkforge-test/undeclared.txt
- classification: {'expected_modification': 0, 'planned_entry': 0, 'rebuild_noise': 74, 'unexpected': 1, 'unknown': 0}
- noise per rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'manifest_reencoded': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1}
- unexpected: ['file added assets/apkforge-test/undeclared.txt']
- original checkpoints: ['planning', 'apply test.undeclared', 'build pipeline', 'diff']
- failure: semantic: 1 unexpected change(s)

Modified APKs are not installed or run; VERIFIED does not mean the APK is safe.
