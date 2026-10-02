# Phase C.1 Toolchain Report

## Environment

- **OS**: Fedora Linux 44 (Workstation Edition), kernel `7.2.7-200.fc44.x86_64`
- **Architecture**: `x86_64`
- **Python**: `Python 3.14.7` (`/usr/bin/python3`)
- **Java**: `OpenJDK 25.0.4.1 (build 25.0.4.1+1-2)` (`/usr/bin/java`, `JAVA_HOME=/usr/lib/jvm/java-25-openjdk`)
- **Android SDK**: `/home/naishring/Android/Sdk`
  - Platforms: `android-35` (`/home/naishring/Android/Sdk/platforms/android-35/android.jar`)
  - Platform-tools: `adb` version `37.0.1-13768407` (`/home/naishring/Android/Sdk/platform-tools/adb`)
  - Build-tools versions: `35.0.0` (primary), `34.0.0`

---

## Required Tools

| Tool | Path | Version | Status | Notes |
|------|------|---------|--------|-------|
| **Java** | `/usr/bin/java` (`/usr/lib/jvm/java-25-openjdk/bin/java`) | `25.0.4.1` (build 25.0.4.1+1-2) | `FOUND` (PREVIOUSLY PRESENT) | OpenJDK 64-bit Server VM. `JAVA_HOME` set to `/usr/lib/jvm/java-25-openjdk`. |
| **Apktool** | `/home/naishring/APKForge/tools/apktool` | `2.10.0` | `CONFIGURED` (PREVIOUSLY PRESENT) | Jar jar was present at `artifacts/toolchain-validation/apktool.jar`. Controlled wrapper script created in `tools/apktool` and linked to `~/.local/bin/apktool`. Android 35 framework installed via `apktool if`. |
| **Android SDK** | `/home/naishring/Android/Sdk` | API 35 (`android-35`) | `FOUND` (PREVIOUSLY PRESENT) | Validated `platforms/android-35/android.jar`, platform-tools `adb` 37.0.1, build-tools 35.0.0 and 34.0.0, SDK licenses accepted. |
| **Build Tools** | `/home/naishring/Android/Sdk/build-tools/35.0.0` | `35.0.0` | `FOUND` (PREVIOUSLY PRESENT) | Build-tools versions 35.0.0 and 34.0.0 installed. Version 35.0.0 selected for toolchain pipeline. |
| **zipalign** | `/home/naishring/Android/Sdk/build-tools/35.0.0/zipalign` | `35.0.0` | `CONFIGURED` (PREVIOUSLY PRESENT) | Binary present in SDK build-tools 35.0.0. Wrapper created in `tools/zipalign` and linked to `~/.local/bin/zipalign`. Executed `-h` and `-c` to verify. |
| **apksigner** | `/home/naishring/Android/Sdk/build-tools/35.0.0/apksigner` | `0.9` (Build-Tools 35.0.0) | `CONFIGURED` (PREVIOUSLY PRESENT) | CLI present in build-tools 35.0.0. Wrapper created in `tools/apksigner` and linked to `~/.local/bin/apksigner`. Executed `--version` to verify (returned 0.9). |
| **Python** | `/usr/bin/python3` | `3.14.7` | `FOUND` (PREVIOUSLY PRESENT) | Python 3.14.7 runtime with standard library and required modules (`androguard`, `yaml`). |

---

## APK Corpus

The test corpus consists of 9 legitimate, structurally diverse open-source Android applications symlinked into `samples/` from `tests/corpus/` (originals preserved untouched):

| Filename | Package | Version | SDK (Min / Target) | Size (Bytes) | SHA-256 | Structural Characteristics |
|----------|---------|---------|---------------------|--------------|---------|-----------------------------|
| `com.emanuelef.remote_capture_95.apk` | `com.emanuelef.remote_capture` (PCAPdroid) | `2.0.2` (code 95) | 23 / 37 | 17,560,048 | `e03f79082278b3754b4954c7537e7c9f7681e5995a44e70aa1589eca10190066` | 2 DEX, 20 native libraries (`lib/`), resources.arsc, VPN service, network capture |
| `com.oF2pks.applicationsinfo_19.apk` | `com.oF2pks.applicationsinfo` | `1.7-19` (code 19) | 16 / 32 | 120,970 | `c0188f5f1f566e12324bd6bf4bf4f1b9408d852c6cc6b113706503031f13eebd` | Minimal app: 1 DEX, 0 native libs, low min-SDK (16), 37 total files |
| `de.audioattack.openlink_28.apk` | `de.audioattack.openlink` | `1.5.11` (code 28) | 21 / 36 | 235,707 | `3d28923f08bd7173880a71ed2c995055349eaa43be4fac29b53a0068035eceed` | Kotlin standard library, 1 DEX, 0 native libs, modern target SDK 36 |
| `de.danoeh.antennapod_3120295.apk` | `de.danoeh.antennapod` | `3.2.0` (code 3120295) | 21 / 34 | 17,749,828 | `3f43a4337a693cdb49141afe06cb596e88c796009ed77bff51e9444ce2d1ebfc` | 3 DEX, 4 native libs, rich media player, complex services and receivers |
| `eu.siacs.conversations_4218104.apk` | `eu.siacs.conversations` | `2.20.4+free` (code 4218104) | 23 / 37 | 30,749,589 | `3fae646e33b59b95f049ce9bd828022e2edbb374fa82e517bd782aced71ba980` | 2 DEX, 2 native libs, XMPP client, Android 15/37 features, Material 3 components |
| `godau.fynn.usagedirect_10.apk` | `godau.fynn.usagedirect` | `0.8.1` (code 10) | 22 / 34 | 3,469,642 | `c55079192a77fc6696a80c6d337c3f0c64fe4ebc27e5970aaf4baac0a60a3b31` | 2 DEX, 0 native libs, Kotlin coroutines, usage stats permissions |
| `io.github.muntashirakon.AppManager_451.apk` | `io.github.muntashirakon.AppManager` | `v4.0.0-alpha01` (code 451) | 21 / 35 | 28,145,654 | `e1f6ba10812c74016ad626e11e27a1ae450aec2c0964a11466abb9e7a9c8ef84` | Complex multidex: 6 DEX files, 16 native libs, root/shell services, 2,310 files |
| `org.mozilla.fennec_fdroid_1560020.apk` | `org.mozilla.fennec_fdroid` | `141.0.0` (code 1560020) | 21 / 34 | 127,634,542 | `27f2951376ca1085e0933066c902fdfe4d260916d381e233475c5fd6964f5745` | Very large APK (127 MB): 3 DEX, 15 native libs (Gecko engine), 3,257 files |
| `org.schabi.newpipe_1015_cb84069.apk` | `org.schabi.newpipe` | `0.29.1` (code 1015) | 23 / 35 | 11,507,122 | `18447bfb1e06d113edc88df93f471827280de06f6f3d4dc42f56f28b9c1bab79` | 3 DEX, 4 native libs, custom extractors, Material Design Components |

---

## Controlled Harmless Test Modification

To ensure the rebuild and signing stages reflect a genuine round-trip modification without altering application logic or security posture, exactly one harmless change was inserted into each APK:

- **Original State**: Clean decoded `AndroidManifest.xml` with no test meta-data.
- **Requested Change**: Insert the following meta-data element immediately inside `<application>`:
  ```xml
  <meta-data android:name="apkforge.toolchain.proof" android:value="verified"/>
  ```
- **Actual Change**: Successfully inserted the element into `AndroidManifest.xml` inside `<application>`.
- **Post-Build Verification**: After rebuild, zipalign, and signing, the binary XML (`AndroidManifest.xml`) inside the signed APK was parsed using `androguard.core.axml.AXMLPrinter` to confirm the presence of `apkforge.toolchain.proof` with value `verified`.

---

## Test Signing Key

A dedicated test keystore was created specifically for APKForge toolchain validation:

- **Location**: `tools/test-signing-key.jks` (excluded from git via `.gitignore`)
- **Key Alias**: `apkforge-test-key`
- **Key Password**: `apkforge-test-pass`
- **Algorithm**: RSA 2048-bit (`SHA256withRSA`)
- **Validity**: 10,000 days
- **Certificate DN**: `CN=APKForge Test Signer, OU=Phase C.1 Toolchain Validation, O=APKForge Project, C=US`
- **SHA-256 Fingerprint**: `C9:AC:63:76:3D:45:DA:0B:C3:ED:74:CB:15:7A:EC:BE:0C:0D:00:FC:16:C9:4A:EA:C1:46:55:2B:83:C7:2E:F0`
- **Purpose**: Generated strictly for APKForge testing and independent toolchain proof. Private signing material remains outside version control.

---

## Independent Pipeline Results

Each stage was executed independently in an isolated workspace per APK:
`original.apk` → `apktool d` → `harmless manifest edit` → `apktool b` → `zipalign` → `apksigner sign` → `verification`

| APK | Decode | Modify | Build | Align | Sign | Verify | Overall Status |
|-----|--------|--------|-------|-------|------|--------|----------------|
| `com.emanuelef.remote_capture_95.apk` | PASS (3.4s) | PASS (<1ms) | PASS (8.3s) | PASS (35ms) | PASS (1.0s) | PASS (1.1s) | **PASS** |
| `com.oF2pks.applicationsinfo_19.apk` | PASS (1.0s) | PASS (<1ms) | PASS (0.7s) | PASS (2ms) | PASS (0.4s) | PASS (0.2s) | **PASS** |
| `de.audioattack.openlink_28.apk` | PASS (1.1s) | PASS (<1ms) | PASS (0.6s) | PASS (2ms) | PASS (0.4s) | PASS (0.2s) | **PASS** |
| `de.danoeh.antennapod_3120295.apk` | PASS (3.5s) | PASS (<1ms) | PASS (10.4s) | PASS (29ms) | PASS (0.7s) | PASS (0.9s) | **PASS** |
| `eu.siacs.conversations_4218104.apk` | PASS (3.6s) | PASS (<1ms) | **FAIL** (3.1s) | SKIPPED | SKIPPED | SKIPPED | **FAIL** |
| `godau.fynn.usagedirect_10.apk` | PASS (2.5s) | PASS (<1ms) | PASS (6.2s) | PASS (8ms) | PASS (0.5s) | PASS (0.4s) | **PASS** |
| `io.github.muntashirakon.AppManager_451.apk` | PASS (7.5s) | PASS (<1ms) | PASS (16.1s) | PASS (56ms) | PASS (1.1s) | PASS (2.7s) | **PASS** |
| `org.mozilla.fennec_fdroid_1560020.apk` | PASS (9.6s) | PASS (<1ms) | PASS (28.5s) | PASS (142ms) | PASS (2.6s) | PASS (3.6s) | **PASS** |
| `org.schabi.newpipe_1015_cb84069.apk` | PASS (4.4s) | PASS (<1ms) | **FAIL** (3.0s) | SKIPPED | SKIPPED | SKIPPED | **FAIL** |

**Summary**:
- Total APKs Tested: **9**
- Full Pipeline Success (**PASS**): **7** (77.8%)
- Failures: **2** (22.2%)

---

## Post-Build Verification Details (Passing Samples)

All 7 passing samples underwent multi-point independent verification:

1. **Alignment Verification**:
   - `zipalign -c -v 4 <apk>` exited with code 0 (`Verification succesful`).
   - Confirmed 4-byte alignment across all uncompressed assets, shared objects (`.so`), and resources.
2. **Signature Verification**:
   - `apksigner verify --verbose --print-certs <apk>` exited with code 0 (`Verifies`).
   - Confirmed signatures: v1 (JAR), v2 (APK Signature Scheme v2), and v3 (APK Signature Scheme v3).
   - Validated certificate DN: `CN=APKForge Test Signer, OU=Phase C.1 Toolchain Validation, O=APKForge Project, C=US`.
   - Validated certificate SHA-256 digest: `c9ac63763d45da0bc3ed74cb157aecbe0c0d00fc16c94aeac146552b83c72ef0`.
3. **ZIP Archive Integrity**:
   - `zipfile.ZipFile.testzip()` verified clean with 0 corrupted CRC or compressed entries.
4. **Harmless Modification Verification**:
   - Parsed compiled binary `AndroidManifest.xml` from inside the final signed APK using Androguard AXML parser.
   - Confirmed presence of `<meta-data android:name="apkforge.toolchain.proof" android:value="verified"/>`.

---

## Failures

### 1. `eu.siacs.conversations_4218104.apk`
- **APK**: `eu.siacs.conversations_4218104.apk` (Conversations 2.20.4+free)
- **Stage**: `rebuild` (`apktool b`)
- **Failure Category**: `RESOURCE_FAILURE`
- **Command / Tool**:
  ```bash
  /home/naishring/APKForge/tools/apktool b -o work/eu.siacs.conversations_4218104/unaligned.apk work/eu.siacs.conversations_4218104/decoded
  ```
- **Relevant Error**:
  ```
  W: /home/naishring/APKForge/work/eu.siacs.conversations_4218104/decoded/res/color/m3_list_item_background_color_selector.xml:5: error: attribute state_swiped (aka eu.siacs.conversations:state_swiped) not found.
  W: /home/naishring/APKForge/work/eu.siacs.conversations_4218104/decoded/res/color/m3_segmented_list_item_background_color_selector.xml:5: error: attribute state_swiped (aka eu.siacs.conversations:state_swiped) not found.
  W: error: failed linking file resources.
  brut.androlib.exceptions.AndrolibException: brut.common.BrutException: could not exec (exit code = 1): [aapt2 link ...]
  ```
- **Likely Cause**:
  Conversations utilizes Material 3 components (`com.google.android.material`) that reference synthetic state selectors (`state_swiped`). During upstream Gradle R8 resource shrinking, synthetic attributes were stripped from `res/values/attrs.xml` while remaining referenced in precompiled color selectors. When Apktool decodes the resources and invokes AAPT2 to re-link, AAPT2 rejects the missing attribute definition in the app's private resource table.
- **Toolchain vs APK-Specific Issue**:
  **APK-Specific Issue**. The build toolchain (Java, Apktool, AAPT2, zipalign, apksigner) is functioning properly as proven by the 7 successful rebuilds (including multidex and large native apps). The failure is an APK-specific decompile/re-link resource resolution limitation inherent to modern AAPT2/M3 resource stripping.

### 2. `org.schabi.newpipe_1015_cb84069.apk`
- **APK**: `org.schabi.newpipe_1015_cb84069.apk` (NewPipe 0.29.1)
- **Stage**: `rebuild` (`apktool b`)
- **Failure Category**: `RESOURCE_FAILURE`
- **Command / Tool**:
  ```bash
  /home/naishring/APKForge/tools/apktool b -o work/org.schabi.newpipe_1015_cb84069/unaligned.apk work/org.schabi.newpipe_1015_cb84069/decoded
  ```
- **Relevant Error**:
  ```
  W: /home/naishring/APKForge/work/org.schabi.newpipe_1015_cb84069/decoded/res/animator/mtrl_card_state_list_anim.xml:4: error: attribute state_dragged (aka org.schabi.newpipe:state_dragged) not found.
  W: /home/naishring/APKForge/work/org.schabi.newpipe_1015_cb84069/decoded/res/color/mtrl_card_view_foreground.xml:5: error: attribute state_dragged (aka org.schabi.newpipe:state_dragged) not found.
  W: /home/naishring/APKForge/work/org.schabi.newpipe_1015_cb84069/decoded/res/color/mtrl_card_view_foreground.xml:6: error: attribute state_dragged (aka org.schabi.newpipe:state_dragged) not found.
  W: /home/naishring/APKForge/work/org.schabi.newpipe_1015_cb84069/decoded/res/color/mtrl_card_view_ripple.xml:5: error: attribute state_dragged (aka org.schabi.newpipe:state_dragged) not found.
  W: error: failed linking file resources.
  brut.androlib.exceptions.AndrolibException: brut.common.BrutException: could not exec (exit code = 1): [aapt2 link ...]
  ```
- **Likely Cause**:
  NewPipe relies on Google Material Design Components (`mtrl_card_state_list_anim`, `mtrl_card_view_foreground`). Upstream build optimization stripped the custom attribute `state_dragged` from the public/attrs definitions. When Apktool reconstructs XMLs from the compiled binary ARSC, AAPT2 fails to re-link without an explicit attribute definition in `res/values/attrs.xml`.
- **Toolchain vs APK-Specific Issue**:
  **APK-Specific Issue**. The toolchain binaries are operational; this failure is due to upstream resource table compression/stripping that Apktool cannot re-link with standard AAPT2 without manual attribute stubs or Apktool `--no-res` flag.

---

## Toolchain Conclusion

**PARTIALLY_READY**

### Justification:
1. **Toolchain Baseline Proven**: The required build toolchain (Java 25, Apktool 2.10.0, Android SDK 35, Build Tools 35.0.0, zipalign 35.0.0, and apksigner 0.9) is correctly installed, configured, and capable of executing the complete round-trip pipeline (`decode → modify → rebuild → zipalign → sign → verify`).
2. **Diverse Success Across Architectures**: The pipeline succeeded end-to-end on 7 of 9 diverse APKs (77.8%), including:
   - Small lightweight apps (`applicationsinfo`, `openlink`)
   - Complex native apps with 20 shared libraries (`PCAPdroid`)
   - Complex multidex apps with 6 DEX files and root components (`AppManager`)
   - Very large media apps (`AntennaPod`) and heavy browser engines (Fennec, 127 MB, 3,257 files)
3. **Reproducible Baseline**: Alignment verification, v1/v2/v3 cryptographic signatures, and binary XML modifications were proven independently across all passing samples.
4. **Distinction from Implementation**: The 2 failures (`Conversations`, `NewPipe`) are strictly resource re-linking incompatibilities (`RESOURCE_FAILURE`) caused by stripped Material Components attributes in modern Gradle/R8 builds, not toolchain installation or configuration failures.

---

## Known Limitations

1. **AAPT2 Material Design Custom Attributes**:
   APKs built with modern Android Gradle Plugin (AGP) and R8 resource shrinking where library attributes (e.g., `state_dragged`, `state_swiped`) are inlined or omitted from `res/values/attrs.xml` will fail during `apktool b` resource re-linking with `attribute <attr> not found`.
   - *Mitigation for Future Phases*: If resource modification is not required for a given patch, Apktool can be invoked with `-r` / `--no-res` (do not decode resources), or smali-only byte modification can be performed without re-linking resource tables.
2. **Android Framework Levels**:
   Target SDKs >= 35 require the matching platform framework jar installed in Apktool (`apktool if <path>/platforms/android-35/android.jar`). This has been configured in the current environment (`~/.local/share/apktool/framework/1.apk`).

---

## Reproduction

To reproduce the complete successful toolchain pipeline on any valid sample (e.g., `de.audioattack.openlink_28.apk`):

```bash
# 1. Environment configuration
export ANDROID_HOME=/home/naishring/Android/Sdk
export ANDROID_SDK_ROOT=/home/naishring/Android/Sdk
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk
export PATH="/home/naishring/APKForge/tools:/home/naishring/Android/Sdk/build-tools/35.0.0:$PATH"

# 2. Decode APK
/home/naishring/APKForge/tools/apktool d -f \
  -o work/sample_proof/decoded \
  samples/de.audioattack.openlink_28.apk

# 3. Apply harmless test modification to AndroidManifest.xml
sed -i 's|<application|<application>\n        <meta-data android:name="apkforge.toolchain.proof" android:value="verified"/>|' \
  work/sample_proof/decoded/AndroidManifest.xml

# 4. Rebuild APK
/home/naishring/APKForge/tools/apktool b \
  -o work/sample_proof/unaligned.apk \
  work/sample_proof/decoded

# 5. Zipalign (4-byte alignment)
/home/naishring/Android/Sdk/build-tools/35.0.0/zipalign -p -f -v 4 \
  work/sample_proof/unaligned.apk \
  work/sample_proof/aligned.apk

# 6. Cryptographically Sign (v1, v2, v3 schemes)
/home/naishring/Android/Sdk/build-tools/35.0.0/apksigner sign \
  --ks /home/naishring/APKForge/tools/test-signing-key.jks \
  --ks-pass pass:apkforge-test-pass \
  --ks-key-alias apkforge-test-key \
  --key-pass pass:apkforge-test-pass \
  --out work/sample_proof/signed.apk \
  work/sample_proof/aligned.apk

# 7. Verification Checks
# 7a. Verify alignment
/home/naishring/Android/Sdk/build-tools/35.0.0/zipalign -c -v 4 work/sample_proof/signed.apk

# 7b. Verify signature schemes
/home/naishring/Android/Sdk/build-tools/35.0.0/apksigner verify --verbose --print-certs work/sample_proof/signed.apk

# 7c. Automated test suite execution
python3 build-tests/run_proof.py
```
