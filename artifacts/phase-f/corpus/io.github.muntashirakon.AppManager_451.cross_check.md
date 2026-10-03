# Phase F Privacy vs Phase B Security Cross-Check

- Overlapping Findings: 4
- New Phase F Privacy Findings: 11
- Security-Only Findings: 26
- Strengthened Findings: 4
- Incomplete / Partial Findings: 2
- Discrepancies Identified: 0

## 1. Overlapping Findings
- **Device Identifiers**: Privacy `[PRIV-CAP-DEVICE-IDENTIFIERS]` <-> Security `[SEC-SPY-CALLS-001]`
- **Boot Persistence**: Privacy `[PRIV-REC-BOOT]` <-> Security `[SEC-MAL-BOOT-001]`
- **Device Identifiers**: Privacy `[PRIV-API-DEVICE-IDENTIFIER]` <-> Security `[SEC-SPY-CALLS-001]`
- **Dynamic Code Loading**: Privacy `[PRIV-API-DYNAMIC-CODE]` <-> Security `[SEC-MAL-DYN-LOAD]`

## 2. New Phase F Findings (Trackers, Endpoints, Permissions)
- `[PRIV-CAP-CAMERA]` (camera): Camera Capture Capability Detected
- `[PRIV-API-CAMERA]` (camera): Camera Hardware & Capture APIs
- `[PRIV-API-CLIPBOARD]` (clipboard): Clipboard Access APIs
- `[PRIV-API-LOCATION]` (location): Location Framework API Invocations
- `[PRIV-API-REFLECTION]` (reflection): Reflection on Internal or Sensitive Classes
- `[PRIV-API-SCHEDULING]` (background_execution): Background Job Scheduling & Alarm APIs
- `[PRIV-API-WEBVIEW]` (network): Embedded WebView & Web Interface APIs
- `[PRIV-API-ACCESSIBILITY]` (accessibility): Accessibility Service Declaration & APIs
- `[PRIV-CAP-CLIPBOARD]` (clipboard): Clipboard Access Capability Detected
- `[PRIV-CAP-ACCESSIBILITY]` (accessibility): Accessibility Service Capability Detected
- `[PRIV-CAP-LOCATION]` (location): Location Capability Detected

## 3. Strengthened Findings
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (5 locations).
- **Boot Persistence**: Corroborated by both Phase B (2 items) and Phase F (1 locations).
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (5 locations).
- **Dynamic Code Loading**: Corroborated by both Phase B (2 items) and Phase F (1 locations).

## 4. Incomplete / Partial Analysis
- `[PRIV-CAP-CAMERA]`: Static analysis cannot prove runtime camera usage.
- `[PRIV-CAP-LOCATION]`: Static analysis cannot establish runtime location collection.

## 5. Discrepancies & Explanations
No contradictory evidence found between analyzers.