# Phase B Security Analysis vs Phase F Privacy Intelligence Cross-Check

This report documents the cross-check between Phase B security analysis and Phase F privacy intelligence, comparing overlapping findings, new intelligence findings, and architectural reclassifications.

## Cross-Check Principles
1. **Preserve Both Verifications**: Phase B security findings remain intact and are not automatically overwritten or mutated.
2. **Explain Discrepancies**: Where Phase B labeled an SDK or capability with security severity, Phase F refines the finding with factual privacy evidence and technical justification.
3. **Attack Surface vs Observed Behavior**: Phase B reports potential attack surface; Phase F reports whether static bytecode actually exercises the protected capability.

## Corpus Cross-Check Statistics

| APK | Overlapping | New Privacy | Security Only | Strengthened | Incomplete | Discrepancies |
|---|---:|---:|---:|---:|---:|---:|
| `com.oF2pks.applicationsinfo_19.apk` | 0 | 1 | 1 | 0 | 0 | 0 |
| `de.audioattack.openlink_28.apk` | 1 | 1 | 4 | 1 | 0 | 0 |
| `com.emanuelef.remote_capture_95.apk` | 3 | 7 | 8 | 3 | 1 | 0 |
| `de.danoeh.antennapod_3120295.apk` | 3 | 10 | 17 | 3 | 3 | 0 |
| `eu.siacs.conversations_4218104.apk` | 9 | 10 | 23 | 9 | 5 | 0 |
| `godau.fynn.usagedirect_10.apk` | 2 | 10 | 6 | 2 | 2 | 0 |
| `io.github.muntashirakon.AppManager_451.apk` | 4 | 11 | 26 | 4 | 2 | 0 |
| `org.mozilla.fennec_fdroid_1560020.apk` | 9 | 11 | 23 | 9 | 3 | 0 |
| `org.schabi.newpipe_1015_cb84069.apk` | 3 | 10 | 13 | 3 | 2 | 0 |
