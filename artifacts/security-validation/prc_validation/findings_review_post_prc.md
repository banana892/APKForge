# Security Validation Review: Post-PRC Precision Fixes

## 1. Summary of Changes and Metrics

| Metric | Baseline (Pre-PRC) | Post-PRC (Current) | Change |
| :--- | :--- | :--- | :--- |
| **Total Findings** | 59 | 42 | -17 |
| **True Positives** | 35 | 35 | 0 (No TP regressions) |
| **False Positives** | 22 | 5 | -17 |
| **Unclear Findings** | 2 | 2 | 0 |
| **Overall FP Rate** | 37.3% | 11.9% | -25.4% |
| **OpenLink Findings** | 5 (5 TP) | 5 (5 TP) | 0 |
| **PCAPdroid Findings** | 9 (6 TP, 2 FP, 1 UNC) | 9 (6 TP, 2 FP, 1 UNC) | 0 |
| **AppManager Findings** | 45 (24 TP, 20 FP, 1 UNC) | 28 | -17 |
| **AppManager FP Rate** | 44.4% (20/45) | 17.9% (5/28) | -26.5% |

## 2. Disposition of 22 Reviewed False Positives

| App | Rule ID | Scope / Proposed Fix | Status | Detailed Disposition |
| :--- | :--- | :--- | :--- | :--- |
| `pcapdroid` | `SEC-SPY-ACCESSIBILITY-001` | PRC fix | **STILL_PRESENT** | Out-of-scope rule (PRC-01 / PRC-03); retained as known issue |
| `pcapdroid` | `SEC-SPY-ACCESSIBILITY-ABUSE` | PRC fix | **STILL_PRESENT** | Out-of-scope rule (PRC-01 / PRC-03); retained as known issue |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-23_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-24_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-25_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-26_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-27_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-28_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-29_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-30_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-31_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-32_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-33_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-34_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-35_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-MAL-PAYLOAD-APK-frameworks_android_android-36_apk` | PRC fix | **ELIMINATED** | Eliminated by PRC-05, PRC-06 |
| `appmanager` | `SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER` | PRC fix | **ELIMINATED** | Eliminated by PRC-07 |
| `appmanager` | `SEC-VULN-WEAK-CIPHER-001` | PRC fix | **ELIMINATED** | Eliminated by PRC-08 |
| `appmanager` | `SEC-VULN-CRYPTO-WEAK-CIPHER` | PRC fix | **ELIMINATED** | Eliminated by PRC-08, PRC-04 |
| `appmanager` | `SEC-NET-CLEARTEXT-URLS` | PRC fix | **STILL_PRESENT** | Out-of-scope rule (PRC-01 / PRC-03); retained as known issue |
| `appmanager` | `SEC-VULN-CRYPTO-WEAK-HASH` | PRC fix | **STILL_PRESENT** | Bundled BouncyCastle SHA1 eliminated; app-owned SHA-1 in Signer retained and attributed to app |
| `appmanager` | `SEC-VULN-WEAK-HASH-001` | PRC fix | **STILL_PRESENT** | Bundled BouncyCastle SHA1 eliminated; app-owned SHA-1 in Signer retained and attributed to app |

## 3. Per-App Detail

### OpenLink (`de.audioattack.openlink`)
- Findings: 5 (5 TP, 0 FP, 0 UNCLEAR).
- No regressions.

### PCAPdroid (`com.emanuelef.remote_capture`)
- Findings: 9 (6 TP, 2 FP, 1 UNCLEAR).
- The 2 FPs (`SEC-SPY-ACCESSIBILITY-001`, `SEC-SPY-ACCESSIBILITY-ABUSE`) are PRC-01 issues (accessibility service substring match), which are out of scope for this task and remain tracked.

### AppManager (`io.github.muntashirakon.AppManager`)
- Findings: 28 (down from 45).
- 14 `frameworks/android/android-NN.apk` code-free payload findings: ELIMINATED (PRC-05).
- 1 bare PEM armor key header: ELIMINATED (PRC-07).
- 2 weak ciphers (`SEC-VULN-WEAK-CIPHER-001`, `SEC-VULN-CRYPTO-WEAK-CIPHER`): ELIMINATED (PRC-08).
- 1 `SEC-NET-CLEARTEXT-URLS`: PRC-03 issue (XML schema URLs), out of scope and retained.
- 2 weak hash findings: `SHA1` from BouncyCastle eliminated; `SHA-1` present in AppManager's own `Signer` / `DigestUtils` correctly attributed to app class.
