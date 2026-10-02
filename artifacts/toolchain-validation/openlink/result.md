# Phase B Step 3 — Open Link With Validation

## Toolchain

JDK: OpenJDK 17.0.20.1 (Temurin-17.0.20.1+1)
Apktool: 2.10.0
Build Tools: 34.0.0 (zipalign, apksigner 0.9, aapt, aapt2)

## Test A — No-op

Decode: PASS
Build: PASS
Zipalign: PASS
Sign: PASS
Verify: PASS (Verifies, v1=true, v2=true, v3=true)
APKForge intake: PASS (complete, 96 files)
APKForge inspection: PASS (complete, 1 DEX, 108 classes, 2 permissions, 6 components, 1 URL/domain, 0 native libs)
APKForge diff: PASS (complete, 0 permissions changed, 0 components changed, 0 manifest attributes changed, 0 network changes, 0 DEX classes changed)

No-op semantic differences: None. All permissions (2), components (6: 3 activities, 0 services, 2 receivers, 1 provider), manifest attributes, and network endpoints (1) remained identical.

No-op noise floor:
- DEX binary re-encoding: `classes.dex` binary hash and size changed due to smali disassembly/reassembly, while all 108 classes, methods, and API references remained semantically identical.
- Resource canonicalization / de-obfuscation: The original APK contained collapsed resource filenames (`res/-U.xml`, `res/0K.xml`, `res/2H.xml`, etc.). Apktool deobfuscated them into canonical paths (`res/drawable/...`, `res/layout/...`, `res/mipmap/...`), which aapt2 re-emitted on rebuild (66 canonical paths added, 82 collapsed paths and old signatures removed).
- Signature and META-INF replacement: Original release signature (`C4961B96.RSA/.SF`) and 16 `META-INF/*.version` markers replaced by the debug key (`ANDROIDD.RSA/.SF`).
- Archive ordering, alignment, and timestamps: Reset to build-time timestamps and aligned to 4-byte boundaries.

## Test B — Manifest Modification

Permission selected: android.permission.RECEIVE_BOOT_COMPLETED
Expected permission change: removed
Actual permission change: removed (DiffEngine reported `permissions.removed: ["android.permission.RECEIVE_BOOT_COMPLETED"]`)

Component selected: de.audioattack.openlink.conf.PackageChangeBroadcastReceiver
Expected component change: enabled → disabled
Actual component change: detected (ComponentDiffer reported `total_modified: 1`, `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver` with `enabled_before=True`, `enabled_after=False`)

Unexpected semantic differences: None. All other permissions, components, DEX classes (108), network endpoints (1), and files remained identical between no-op and modified (only `AndroidManifest.xml` was modified).

## DEX Diff Capability

What APKForge currently compares:
- DEX files: SHA-256 and file size (detects file-level binary modification).
- Classes: Class names (detects additions and removals). For common classes, compares superclass, method signatures (`name(parameters)return_type`), and field signatures (`name`, `type`, `access_flags`).
- Methods: For common method signatures, compares access flags only (`public`, `private`, `static`, etc.).
- Framework API references: Set differences of referenced framework APIs.

Does it establish method-body equality?
No.

If not, limitation:
APKForge does not inspect or compare method bytecode, Dalvik opcodes/instructions, register allocations, or method body hashes. If a method's implementation or bytecode is modified (e.g., via smali patching or hooking) but its name, parameters, return type, and access flags remain unchanged, `DEXDiffer` reports the class and method as completely unchanged.

## Manifest Reference Handling

Observed behavior:
APKForge extracts raw string attribute values directly from the binary manifest without resolving resource ID references (`@7F...`) against the `resources.arsc` table. In Step 2 (AntennaPod), when `aapt2` inlined `@string/provider_authority` (`@7F130332`) into literal string `de.danoeh.antennapod.provider`, APKForge's `DiffEngine` saw a diff (`authorities_before="@7F130332"`, `authorities_after="de.danoeh.antennapod.provider"`), whereas in reality they refer to the exact same string value.

## Noise-Floor Rules Draft

Documented rule for future verifier:
- A file removed from one path (e.g. `res/-1.xml` or `res/-U.xml`) and added at another path (e.g. `res/anim/abc_popup_enter.xml` or `res/drawable/...`) should be considered a possible rename/canonicalization rather than automatically being treated as two independent semantic changes.

Documented noise categories:
1. DEX binary re-encoding (byte-level smali reassembly drift)
2. Resource canonicalization / path renaming (deobfuscation of collapsed names by Apktool)
3. META-INF/signature changes (re-signing with new keystore, removal of build metadata markers)
4. Manifest resource-reference normalization/inlining (`@7F...` resolved/inlined to literal string)
5. Archive ordering (re-ordering of zip entries by aapt/apktool)
6. Timestamps (zip entry modification dates reset)
7. Alignment changes (4096-byte page alignment for uncompressed native libraries and assets)

## Docker Reproducibility

Build-tools source: Pinned download in Dockerfile from `https://dl.google.com/android/repository/build-tools_r34-linux.zip` with SHA-256 `e858c4b60069d0431051b225d384413b1643e1289b00a4825aed347f25bd510f`.
UID/GID handling: Ran container with `--user $(id -u):$(id -g)` and `JAVA_TOOL_OPTIONS="-Duser.home=/tmp"`, ensuring all generated artifacts are owned by the host user (1000:1000) without using `chmod -R 777`.
Remaining reproducibility gap: None. Host Android SDK volume mount eliminated; toolchain is fully self-contained.

## Git Safety

Keystore tracked: No
Keystore ignored: Yes (`.gitignore` line 62 has `*.keystore`)

## Overall Result

PASS

## Findings

1. **ComponentDiffer Blind Spot (`enabled` attribute omitted)**:
   - While `InspectionEngine` successfully parsed `android:enabled="false"` and stored `enabled: False` on `BroadcastReceiverInfo`, `ComponentDiffer` (`src/apkforge/diff/components.py`) does not check `a.enabled != b.enabled` (it only checks `exported`, `permission`, and `intent_filters`).
   - Consequently, setting `android:enabled="false"` in the manifest was omitted from `ComponentDiff` and marked `unchanged`.
2. **Apktool Framework Directory under Non-Root User**:
   - Running as non-root `--user 1000:1000` causes Java to resolve `user.home` to `?` unless configured. Setting `JAVA_TOOL_OPTIONS="-Duser.home=/tmp"` and passing `-p /tmp/framework` completely resolves framework cache creation in unprivileged containers.
3. **Open Link With Component Composition**:
   - Open Link With contains 0 `<service>` components; the controlled component modification was applied to `de.audioattack.openlink.conf.PackageChangeBroadcastReceiver`.

## Next Step

Proceed to **Phase B Step 4**: Design and implement the APKForge internal tool runner / service encapsulation (`ToolRunner`, `ApktoolService`, build-tools orchestration) and address the identified `ComponentDiffer` blind spot (adding `enabled` attribute comparison) within APKForge.
