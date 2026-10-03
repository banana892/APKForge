# Phase F Real-Corpus Validation Summary

- **Execution Timestamp**: 2026-10-03T04:46:07.352003+00:00
- **Total APKs Analyzed**: 9
- **Total Duration**: 868.29s
- **Git Checkpoint Commit**: `e0d8e9b143bf15eb830ecc77dcf467b271319bcc`

## Aggregate Intelligence Metrics
- **Total Privacy Findings**: 105
- **Total Third-Party SDK Indicators**: 3
- **Total Endpoint Classifications**: 1063
- **Total UNKNOWN / PARTIAL Findings**: 18

### Findings by Category
- `accessibility`: 4
- `advertising`: 2
- `audio`: 2
- `background_execution`: 7
- `camera`: 10
- `clipboard`: 14
- `contacts`: 3
- `crash_reporting`: 1
- `device_identifiers`: 7
- `dynamic_code`: 7
- `identifiers`: 8
- `location`: 14
- `microphone`: 2
- `network`: 5
- `persistence`: 7
- `reflection`: 8
- `storage_files`: 4

### Findings by Severity
- `high`: 17
- `informational`: 53
- `low`: 24
- `medium`: 11

### SDK Indicators by Category
- `advertising`: 2
- `crash_reporting`: 1

## Per-APK Analysis Breakdown

| APK | Package | Status | Findings | UNKNOWN/PARTIAL | SDKs | Endpoints | Uncorrelated Perms |
|---|---|---|---:|---:|---:|---:|---:|
| `com.oF2pks.applicationsinfo_19.apk` | `com.oF2pks.applicationsinfo` | `complete` | 1 | 0 | 0 | 2 | 0 |
| `de.audioattack.openlink_28.apk` | `de.audioattack.openlink` | `complete` | 2 | 0 | 0 | 2 | 0 |
| `com.emanuelef.remote_capture_95.apk` | `com.emanuelef.remote_capture` | `complete` | 10 | 1 | 0 | 127 | 0 |
| `de.danoeh.antennapod_3120295.apk` | `de.danoeh.antennapod` | `complete` | 13 | 3 | 0 | 95 | 1 |
| `eu.siacs.conversations_4218104.apk` | `eu.siacs.conversations` | `complete` | 19 | 5 | 0 | 149 | 4 |
| `godau.fynn.usagedirect_10.apk` | `godau.fynn.usagedirect` | `complete` | 12 | 2 | 0 | 28 | 0 |
| `io.github.muntashirakon.AppManager_451.apk` | `io.github.muntashirakon.AppManager` | `complete` | 15 | 2 | 0 | 113 | 0 |
| `org.mozilla.fennec_fdroid_1560020.apk` | `org.mozilla.fennec_fdroid` | `partial` | 20 | 3 | 2 | 301 | 2 |
| `org.schabi.newpipe_1015_cb84069.apk` | `org.schabi.newpipe` | `complete` | 13 | 2 | 1 | 246 | 0 |
