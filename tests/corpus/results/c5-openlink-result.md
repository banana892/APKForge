# C.5 result: VERIFIED

Generated 2026-10-02T18:48:01.680699+00:00. Corpus entry `de.audioattack.openlink@28`.

## Identity and toolchain (observed)

- APK: `de.audioattack.openlink_28.apk`, package `de.audioattack.openlink` 1.5.11 (28)
- original SHA-256: `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`
- toolchain: java 25.0.4.1, apktool 3.0.3, zipalign 35.0.0, apksigner 0.9, build_tools 35.0.0, android_platform android-35, platform /home/naishring/Android/Sdk/platforms/android-35/android.jar; signing: development
- APKForge commit: `f9b6cdcd98db4506ee99cf1c3fcb609f4f7b34cf` (dirty: True)

## Modification plan (declared before applying)

- operation: Remove the RECEIVE_BOOT_COMPLETED uses-permission and disable the receiver that handles the boot broadcast (android:enabled=false).
- status: ready
- permission: `android.permission.RECEIVE_BOOT_COMPLETED`
- target receiver (derived from the decoded manifest): `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver`
- preconditions:
  - [x] permission_declared_once: android.permission.RECEIVE_BOOT_COMPLETED declarations: ['uses-permission']
  - [x] boot_receiver_identified: boot receivers: ['de.audioattack.openlink.conf.PackageChangeBroadcastReceiver']; receivers in manifest: 2; requested: (derive)
  - [x] receiver_currently_enabled: android:enabled='true'
- planned source edits:
  - remove_element `manifest/uses-permission[name=android.permission.RECEIVE_BOOT_COMPLETED]`
  - set_attribute `manifest/application[0]/receiver[name=de.audioattack.openlink.conf.PackageChangeBroadcastReceiver]` android:enabled: 'true' -> 'false'
- expected semantic changes (DiffEngine terms):
  - uses_permission removed `android.permission.RECEIVE_BOOT_COMPLETED` 
  - component modified `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver` {'component_type': 'receiver', 'enabled': [True, False]}
- declared consequences:
  - de.audioattack.openlink.conf.PackageChangeBroadcastReceiver also handles android.intent.action.MY_PACKAGE_REPLACED; disabling the component stops those broadcasts too.


## Changes actually applied (observed, decoded manifest)

- applied: True; observed edits == planned edits: True
  - remove_element `manifest/uses-permission[name=android.permission.RECEIVE_BOOT_COMPLETED]`
  - set_attribute `manifest/application[0]/receiver[name=de.audioattack.openlink.conf.PackageChangeBroadcastReceiver]` android:enabled: 'true' -> 'false'

## Pipeline stages (BuildService)

| stage | status | failure |
|---|---|---|
| prepare | PASS |   |
| decode | PASS |   |
| build | PASS |   |
| align | PASS |   |
| sign | PASS |   |
| verify | PASS |   |

- verification: valid=True, zipalign=True, signature=True, expected signer=True, zip integrity=True
- signer: `CN=APKForge Development Key - NOT FOR RELEASE, O=APKForge` sha256 `f769555534625181026172519a074c1c4eefc5f5318aa6913ebb80ca466e972b`; schemes v1=True v2=True v3=True
- modified APK SHA-256: `00d7a6f4691ec3bbd534a1640f47a4250a70971dc7455216e0457fd43e97d8a3`

## Expected vs actual (DiffEngine, original vs modified)

- noise floor: semantic no-op baseline; allowed rules ['certificate_replaced', 'dex_compiler_marker_removed', 'dex_reencoded', 'manifest_reencoded', 'resource_path_canonicalized', 'resource_table_reencoded', 'signature_replaced']; residue []
- classification counts: {'expected_modification': 2, 'rebuild_noise': 74, 'unexpected': 0, 'unknown': 0}
- noise per rule: {'dex_compiler_marker_removed': 1, 'certificate_replaced': 1, 'manifest_reencoded': 1, 'signature_replaced': 5, 'dex_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1}
- expected changes observed: 2/2

Expected modifications observed:

- uses_permission removed `android.permission.RECEIVE_BOOT_COMPLETED` {}
- component modified `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver` {'component_type': 'receiver', 'enabled': [True, False]}

Unexpected / unknown:

- none

- verdict: PASS 

## Original preservation (observed)

- before `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`
- after  `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed`
- preserved: **True**

## Failures

- none

## Limitations (what this does NOT show)

- Manifest-level change only: no DEX/smali code is changed. Code that handles BOOT_COMPLETED is still present in the APK.
- The receiver is disabled for every action it handles, not only for the boot action.
- Code can re-enable components at runtime (PackageManager.setComponentEnabledSetting); static analysis cannot rule that out.
- Other components or mechanisms (alarms, WorkManager, other receivers) that start work at or after boot are not addressed.
- Does not establish runtime behaviour: the modified APK is not installed or run.
- The modified APK is not shown to be behaviourally equivalent apart from the intended change, malware-free, spyware-free, safe to install, or runnable on a device.
- DiffEngine compares a subset of the manifest (5 application attributes, SDK levels, permissions, component exported/permission/enabled/process); other manifest content is covered only by the source-level edit check above, and intent filters of real APKs are not extracted by the inspector (see docs/known-limitations.md).
- resources.arsc and recompiled res/ files are accepted as rebuild noise without semantic comparison.
