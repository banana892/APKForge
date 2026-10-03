# Phase F Privacy vs Phase B Security Cross-Check

- Overlapping Findings: 3
- New Phase F Privacy Findings: 10
- Security-Only Findings: 13
- Strengthened Findings: 3
- Incomplete / Partial Findings: 2
- Discrepancies Identified: 0

## 1. Overlapping Findings
- **Device Identifiers**: Privacy `[PRIV-CAP-DEVICE-IDENTIFIERS]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Boot Persistence**: Privacy `[PRIV-REC-BOOT]` <-> Security `[SEC-MAL-BOOT-001]`
- **Device Identifiers**: Privacy `[PRIV-API-DEVICE-IDENTIFIER]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`

## 2. New Phase F Findings (Trackers, Endpoints, Permissions)
- `[PRIV-CAP-CAMERA]` (camera): Camera Capture Capability Detected
- `[PRIV-API-CLIPBOARD]` (clipboard): Clipboard Access APIs
- `[PRIV-API-LOCATION]` (location): Location Framework API Invocations
- `[PRIV-API-REFLECTION]` (reflection): Reflection on Internal or Sensitive Classes
- `[PRIV-API-SCHEDULING]` (background_execution): Background Job Scheduling & Alarm APIs
- `[PRIV-API-WEBVIEW]` (network): Embedded WebView & Web Interface APIs
- `[PRIV-API-DYNAMIC-CODE]` (dynamic_code): Dynamic Code Loading Facilities
- `[PRIV-CAP-CLIPBOARD]` (clipboard): Clipboard Access Capability Detected
- `[PRIV-SDK-AD-GOOGLE-ADMOB]` (advertising): Third-Party Advertising SDK Detected: Google AdMob / Google Mobile Ads
- `[PRIV-CAP-LOCATION]` (location): Location Capability Detected

## 3. Strengthened Findings
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (2 locations).
- **Boot Persistence**: Corroborated by both Phase B (2 items) and Phase F (1 locations).
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (1 locations).

## 4. Incomplete / Partial Analysis
- `[PRIV-CAP-CAMERA]`: Static analysis cannot prove runtime camera usage.
- `[PRIV-CAP-LOCATION]`: Static analysis cannot establish runtime location collection.

## 5. Discrepancies & Explanations
No contradictory evidence found between analyzers.