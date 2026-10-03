# Phase F Privacy vs Phase B Security Cross-Check

- Overlapping Findings: 9
- New Phase F Privacy Findings: 11
- Security-Only Findings: 23
- Strengthened Findings: 9
- Incomplete / Partial Findings: 3
- Discrepancies Identified: 0

## 1. Overlapping Findings
- **Camera Access**: Privacy `[PRIV-CAP-CAMERA]` <-> Security `[SEC-SPY-CAMERA-001]`
- **Device Identifiers**: Privacy `[PRIV-CAP-DEVICE-IDENTIFIERS]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Camera Access**: Privacy `[PRIV-API-CAMERA]` <-> Security `[SEC-SPY-CAMERA-001]`
- **Location Capability**: Privacy `[PRIV-API-LOCATION]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`
- **Boot Persistence**: Privacy `[PRIV-REC-BOOT]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`
- **Device Identifiers**: Privacy `[PRIV-API-DEVICE-IDENTIFIER]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Dynamic Code Loading**: Privacy `[PRIV-API-DYNAMIC-CODE]` <-> Security `[SEC-MAL-DYN-LOAD]`
- **Device Identifiers**: Privacy `[PRIV-CAP-ADVERTISING-ID]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Location Capability**: Privacy `[PRIV-CAP-LOCATION]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`

## 2. New Phase F Findings (Trackers, Endpoints, Permissions)
- `[PRIV-CAP-MICROPHONE]` (audio): Microphone Audio Recording Capability Detected
- `[PRIV-API-CLIPBOARD]` (clipboard): Clipboard Access APIs
- `[PRIV-API-REFLECTION]` (reflection): Reflection on Internal or Sensitive Classes
- `[PRIV-API-SCHEDULING]` (background_execution): Background Job Scheduling & Alarm APIs
- `[PRIV-API-WEBVIEW]` (network): Embedded WebView & Web Interface APIs
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_AUDIO]` (storage_files): Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_AUDIO
- `[PRIV-PERM-UNCORRELATED-RECORD_AUDIO]` (microphone): Declared Permission Without Static Code Reference: android.permission.RECORD_AUDIO
- `[PRIV-SDK-TELEMETRY-SENTRY]` (crash_reporting): Third-Party Crash reporting SDK Detected: Sentry
- `[PRIV-CAP-CLIPBOARD]` (clipboard): Clipboard Access Capability Detected
- `[PRIV-SDK-AD-GOOGLE-ADMOB]` (advertising): Third-Party Advertising SDK Detected: Google AdMob / Google Mobile Ads
- `[PRIV-CAP-ACCESSIBILITY]` (accessibility): Accessibility Service Capability Detected

## 3. Strengthened Findings
- **Camera Access**: Corroborated by both Phase B (4 items) and Phase F (86 locations).
- **Device Identifiers**: Corroborated by both Phase B (9 items) and Phase F (3 locations).
- **Camera Access**: Corroborated by both Phase B (4 items) and Phase F (2 locations).
- **Location Capability**: Corroborated by both Phase B (4 items) and Phase F (2 locations).
- **Boot Persistence**: Corroborated by both Phase B (4 items) and Phase F (1 locations).
- **Device Identifiers**: Corroborated by both Phase B (9 items) and Phase F (3 locations).
- **Dynamic Code Loading**: Corroborated by both Phase B (2 items) and Phase F (1 locations).
- **Device Identifiers**: Corroborated by both Phase B (9 items) and Phase F (1 locations).
- **Location Capability**: Corroborated by both Phase B (4 items) and Phase F (74 locations).

## 4. Incomplete / Partial Analysis
- `[PRIV-CAP-MICROPHONE]`: Static analysis cannot prove runtime microphone activation.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_AUDIO]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.
- `[PRIV-PERM-UNCORRELATED-RECORD_AUDIO]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.

## 5. Discrepancies & Explanations
No contradictory evidence found between analyzers.