# Phase B Step 2 — AntennaPod Toolchain Validation

APK: tests/corpus/de.danoeh.antennapod_3120295.apk
SHA-256: 3f43a4337a693cdb49141afe06cb596e88c796009ed77bff51e9444ce2d1ebfc
Original size: 17,749,828 bytes (16.93 MB)

## Toolchain

JDK: OpenJDK 17.0.20.1 (Temurin-17.0.20.1+1)
Apktool: 2.10.0
Android Build Tools: 34.0.0 (zipalign, apksigner 0.9, aapt, aapt2)
Docker image/environment: apkforge-toolchain:pinned (Ubuntu 22.04.5 LTS / eclipse-temurin:17-jdk-jammy)

## Original APK

APKForge intake: complete (1,516 files, 1 signer)
DEX count: 3 (classes.dex, classes2.dex, classes3.dex; 12,065 classes; 70,360 methods)
Native libraries: 4 (libconscrypt_jni.so across arm64-v8a, armeabi-v7a, x86, x86_64)
Permissions: 11 (including INTERNET, FOREGROUND_SERVICE_MEDIA_PLAYBACK, POST_NOTIFICATIONS)
Components: 38 (12 activities, 7 services, 16 receivers, 3 providers)
Network endpoints: 47 URLs, 47 domains, 10 IPs

# Test A — No-op Round Trip

apktool decode: PASS
apktool build: PASS
zipalign: PASS
apksigner sign: PASS
apksigner verify: PASS
APKForge intake: PASS
APKForge analysis: PASS
APKForge diff: PASS

## No-op semantic comparison

Permissions: 11 / 11 identical (0 added, 0 removed, 0 modified)
Components: 38 / 38 identical (12 activities, 7 services, 16 receivers, 3 providers; 0 added, 0 removed). Provider authority changed representation in binary manifest from resource ID reference `@7F130332` to literal string `"de.danoeh.antennapod.provider"` due to aapt2 resource inlining; semantic authority string is identical.
Manifest attributes: 0 attribute changes, 0 sdk changes
Network endpoints: 47 URLs, 47 domains, 10 IPs identical (0 added, 0 removed, 0 modified)

## No-op noise floor

### Expected rebuild noise

1. **DEX binary re-encoding**:
   - `classes.dex`, `classes2.dex`, `classes3.dex` differ in binary SHA-256 and byte size due to smali disassembly and reassembly.
   - All 12,065 classes, 70,360 methods, and API references remain semantically identical (0 classes added, 0 classes removed, 0 classes modified).
2. **Resource path de-obfuscation / canonicalization**:
   - The original release APK was packaged using resource obfuscation/collapsing (`res/-1.xml`, `res/-B.png`, `res/-5.xml`, etc.).
   - Apktool deobfuscates collapsed paths using the ARSC table into canonical paths (`res/anim/abc_popup_enter.xml`, etc.), which `aapt2` re-emits during rebuild (1,216 collapsed paths replaced by canonical paths).
3. **Signature and META-INF replacement**:
   - Original release key (`179430565a4a04bfe7827483243099bd10870410800cd7c4c7b48d8d3226df55`) replaced by test debug key (`297513e83e552dbbaf9ca171ef6c4efd9eebac93f3edf10c3d7361f745ec19d9`).
   - Old signature blocks (`META-INF/697C4250.RSA`, `META-INF/697C4250.SF`) and 75 `META-INF/*.version` markers dropped/replaced with `ANDROIDD.RSA` / `ANDROIDD.SF`.
4. **Resource reference inlining in binary manifest**:
   - In the original APK's binary `AndroidManifest.xml`, `FileProvider` `android:authorities` was stored as a resource reference `@7F130332` (pointing to `@string/provider_authority`).
   - During `apktool b`, `aapt2` inlines the resolved string literal `"de.danoeh.antennapod.provider"` into the binary manifest attribute.
5. **Archive ordering and alignment**:
   - `zipalign -p -f -v 4` realigns all uncompressed assets and shared native libraries to 4096-byte page boundaries for mmap efficiency.

### Unexpected semantic differences

- None. (Zero unexpected additions, deletions, or mutations across permissions, components, manifest configuration, or network endpoints).

## Test A Result

PASS/PARTIAL/FAIL: PASS

Reason: The untouched complex APK successfully completed decode, smali compilation, aapt2 resource recompilation, 4-byte page-alignment, v1+v2+v3 apksigner signing, and cryptographic verification. APKForge intake, inspection, and differential analysis validated complete semantic stability across all 3 DEX files, 4 native libraries, 11 permissions, 38 components, and 47 network endpoints.

# Test B — Harmless Modification

Modification: Application display label changed
Original value: AntennaPod
New value: AntennaPod (APKForge Test)
Resource/file: res/values/strings.xml (<string name="app_name">)

apktool build: PASS
zipalign: PASS
apksigner sign: PASS
apksigner verify: PASS
APKForge intake: PASS
APKForge analysis: PASS
APKForge diff: PASS

## Intended change

The intended change was detected with 100% precision by APKForge's DiffEngine:
- Manifest change: `category="manifest.application"`, `identifier="label"`, `before="AntennaPod"`, `after="AntennaPod (APKForge Test)"`, `change_type="modified"`.

## Unexpected semantic changes

None.
- Permissions: 11 unchanged (0 added, 0 removed)
- Components: 38 unchanged (0 added, 0 removed, 0 modified)
- DEX classes: 12,065 unchanged (0 added, 0 removed, 0 modified)
- Native libraries: 4 unchanged (0 added, 0 removed)
- Network endpoints: 47 URLs, 47 domains, 10 IPs unchanged (0 added, 0 removed)

## Test B Result

PASS/PARTIAL/FAIL: PASS

Reason: The single string modification was successfully compiled by aapt2, rebuilt into a multi-DEX APK, aligned, signed, verified, and correctly identified by APKForge's differential analysis engine while remaining cleanly isolated from the established no-op noise floor.

# Overall Result

PASS/PARTIAL/FAIL: PASS

## Blocking issue

None.

## Diagnostic conclusion

The pinned external Docker toolchain (`openjdk-17`, `apktool 2.10.0`, `android-sdk-build-tools 34.0.0`) is fully compatible with realistic, complex, multi-DEX, native-library Android APKs.

Key diagnostic findings:
1. **Multi-DEX support**: Apktool 2.10.0 cleanly disassembled and reassembled all 3 DEX files (`classes.dex`, `classes2.dex`, `classes3.dex`) with 12,065 classes and 70,360 methods without class index overflow or multidex smaling errors.
2. **Native libraries**: All 4 native `.so` binaries (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) were copied verbatim and preserved uncompressed with 4096-byte alignment.
3. **Resource noise floor**: In complex production APKs, resource shrinking/name-collapsing (`res/-1.xml`) is canonically restored by Apktool during decode and re-emitted in standard folder structures by aapt2. APKForge diff cleanly distinguishes this structural noise floor from intentional semantic modifications.
4. **Verification**: Cryptographic verification via `apksigner verify` confirms valid v1 (JAR), v2 (APK Signature Scheme v2), and v3 (APK Signature Scheme v3) signatures on both rebuilt artifacts.

## Next Step

The external toolchain is now fully validated on both small (Step 1) and complex multi-DEX/native (Step 2) APKs. Proceed to **Phase B Step 3**: Architecture design and specification for the internal tool runner service (`ToolRunner` / `ApktoolService` / build-tools orchestration) to bring these validated capabilities safely into APKForge.
