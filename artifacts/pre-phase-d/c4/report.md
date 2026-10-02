# APKForge Corpus Validation Report

- Run: `20261002T204014Z` (2026-10-02T20:40:14.449981+00:00 -> 2026-10-02T20:44:50.042133+00:00, 275.6s)
- APKForge: 0.1.0-dev commit `7415f671aa5b0e56f2e865b2167d43f74176a013` (working tree dirty)
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
| com.emanuelef.remote_capture@95 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 10.6s |
| com.oF2pks.applicationsinfo@19 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 2.2s |
| de.audioattack.openlink@28 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 2.4s |
| de.danoeh.antennapod@3120295 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 13.9s |
| eu.siacs.conversations@4218104 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 15.4s |
| godau.fynn.usagedirect@10 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 9.4s |
| io.github.muntashirakon.AppManager@451 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 22.8s |
| org.mozilla.fennec_fdroid@1560020 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 38.7s |
| org.schabi.newpipe@1015 | PASS | PASS | PASS | PASS | PASS | PASS | SUCCESS | SUCCESS | UNCHANGED_SUCCESS | yes (2) | 18.6s |

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

**Baseline check: PASSED**
