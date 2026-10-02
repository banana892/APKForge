# APKForge Corpus Validation Report

- Run: `20261002T173537Z` (2026-10-02T17:35:37.356541+00:00 -> 2026-10-02T17:40:29.413163+00:00, 292.1s)
- APKForge: 0.1.0-dev commit `bff895a26e9fe9eff3687d1f907f65f679ade809` (working tree dirty)
- Corpus: 9 APKs from `/home/naishring/APKForge/tests/corpus`
- Manifest: `/home/naishring/APKForge/tests/corpus/manifest.json` sha256 `a6b0a9d518f35d2377c13f8e4f70f685e00ba95d10bbdd8eb16031cdaed9d427`
- Signing mode: development (APKForge development key)
- Attempts per APK: 2; stage timeout 900s
- Host: Linux 7.2.7-200.fc44.x86_64 x86_64, Python 3.14.7

## Toolchain

| Tool | Version | Path |
|---|---|---|
| java | 25.0.4.1 | `/usr/lib/jvm/java-25-openjdk/bin/java` |
| apktool | 3.0.3 | `/home/naishring/APKForge/tools/apktool_3.0.3.jar` |
| zipalign | 35.0.0 | `/home/naishring/Android/Sdk/build-tools/35.0.0/zipalign` |
| apksigner | 0.9 | `/home/naishring/Android/Sdk/build-tools/35.0.0/apksigner` |
| build_tools | 35.0.0 | `/home/naishring/Android/Sdk/build-tools/35.0.0` |
| android_platform | android-35 | `/home/naishring/Android/Sdk/platforms/android-35/android.jar` |

Toolchain matches the manifest's baseline toolchain.

## Results

| Corpus id | Prepare | Decode | Build | Align | Sign | Verify | Final | Expected | Comparison | Consistent | Time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| com.emanuelef.remote_capture@95 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 11.0s |
| com.oF2pks.applicationsinfo@19 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 2.4s |
| de.audioattack.openlink@28 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 2.6s |
| de.danoeh.antennapod@3120295 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 15.6s |
| eu.siacs.conversations@4218104 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 16.3s |
| godau.fynn.usagedirect@10 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 9.8s |
| io.github.muntashirakon.AppManager@451 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 25.9s |
| org.mozilla.fennec_fdroid@1560020 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 39.7s |
| org.schabi.newpipe@1015 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 20.2s |

## Summary

- Total: 9
- Successful: 9
- Failed: 0
- Not run (corpus errors): 0
- Known failures: 0
- Unexpected failures: 0
- Regressions: 0
- New failures: 0
- Improvements: 0
- Inconsistent across repeats: 0
- Versus previous run `20261002T165901Z`: UNCHANGED_SUCCESS=9

**Baseline check: PASSED**
