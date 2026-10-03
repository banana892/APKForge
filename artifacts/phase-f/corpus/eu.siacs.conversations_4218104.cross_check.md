# Phase F Privacy vs Phase B Security Cross-Check

- Overlapping Findings: 9
- New Phase F Privacy Findings: 10
- Security-Only Findings: 23
- Strengthened Findings: 9
- Incomplete / Partial Findings: 5
- Discrepancies Identified: 0

## 1. Overlapping Findings
- **Camera Access**: Privacy `[PRIV-CAP-CAMERA]` <-> Security `[SEC-SPY-CAMERA-001]`
- **Device Identifiers**: Privacy `[PRIV-CAP-DEVICE-IDENTIFIERS]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Audio Recording**: Privacy `[PRIV-CAP-MICROPHONE]` <-> Security `[SEC-SPY-AUDIO-001]`
- **Audio Recording**: Privacy `[PRIV-API-AUDIO-CAPTURE]` <-> Security `[SEC-SPY-AUDIO-001]`
- **Camera Access**: Privacy `[PRIV-API-CAMERA]` <-> Security `[SEC-SPY-CAMERA-001]`
- **Location Capability**: Privacy `[PRIV-API-LOCATION]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`
- **Boot Persistence**: Privacy `[PRIV-REC-BOOT]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`
- **Device Identifiers**: Privacy `[PRIV-API-DEVICE-IDENTIFIER]` <-> Security `[SEC-SPY-DEVICE-IDENTIFIERS]`
- **Location Capability**: Privacy `[PRIV-CAP-LOCATION]` <-> Security `[SEC-COMB-PERSISTENT-LOC]`

## 2. New Phase F Findings (Trackers, Endpoints, Permissions)
- `[PRIV-CAP-CONTACTS]` (contacts): Contacts Access Capability Detected
- `[PRIV-API-CLIPBOARD]` (clipboard): Clipboard Access APIs
- `[PRIV-API-REFLECTION]` (reflection): Reflection on Internal or Sensitive Classes
- `[PRIV-API-SCHEDULING]` (background_execution): Background Job Scheduling & Alarm APIs
- `[PRIV-PERM-UNCORRELATED-READ_CONTACTS]` (contacts): Declared Permission Without Static Code Reference: android.permission.READ_CONTACTS
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_AUDIO]` (storage_files): Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_AUDIO
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_IMAGES]` (storage_files): Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_IMAGES
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_VIDEO]` (storage_files): Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_VIDEO
- `[PRIV-API-DYNAMIC-CODE]` (dynamic_code): Dynamic Code Loading Facilities
- `[PRIV-CAP-CLIPBOARD]` (clipboard): Clipboard Access Capability Detected

## 3. Strengthened Findings
- **Camera Access**: Corroborated by both Phase B (4 items) and Phase F (101 locations).
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (3 locations).
- **Audio Recording**: Corroborated by both Phase B (4 items) and Phase F (37 locations).
- **Audio Recording**: Corroborated by both Phase B (4 items) and Phase F (4 locations).
- **Camera Access**: Corroborated by both Phase B (4 items) and Phase F (3 locations).
- **Location Capability**: Corroborated by both Phase B (4 items) and Phase F (2 locations).
- **Boot Persistence**: Corroborated by both Phase B (4 items) and Phase F (3 locations).
- **Device Identifiers**: Corroborated by both Phase B (2 items) and Phase F (2 locations).
- **Location Capability**: Corroborated by both Phase B (4 items) and Phase F (26 locations).

## 4. Incomplete / Partial Analysis
- `[PRIV-CAP-CONTACTS]`: Static analysis cannot establish runtime contacts extraction.
- `[PRIV-PERM-UNCORRELATED-READ_CONTACTS]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_AUDIO]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_IMAGES]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_VIDEO]`: Static analysis cannot determine whether the permission is requested dynamically at runtime.

## 5. Discrepancies & Explanations
No contradictory evidence found between analyzers.