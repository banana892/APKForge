# Privacy & Tracker Intelligence Report: de.audioattack.openlink v1.5.11

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 2
- High-Risk / Dangerous Permissions: 0

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 2
- Accessibility Services: 0
- Notification Listeners: 0

## Section C: SDK & Library Indicators
- Total Third-Party SDK Indicators: 0
  - Trackers: 0
  - Advertising: 0
  - Analytics: 0
  - Telemetry / Crash: 0
- Network Traffic Determination: *Static presence of an SDK library does not prove actual data transmission at runtime.*

## Section D: Domains & Endpoints
- Total Extracted Endpoints: 2
- First-Party Domains: 0
- Third-Party Domains: 1
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `unknown` (2): example.org, http://example.org

## Section E: Sensitive API Indicators
- Device Identifiers: None
- Advertising ID Client: None
- Clipboard Access: None
- Dynamic Code Loading: None
- Sensitive Reflection: java.lang.Class, java.lang.reflect.Method
- Location APIs: None
- Contacts APIs: None
- Audio Capture APIs: None
- Camera APIs: None

## Section F: Correlated Findings
- Total Findings: 2
- `[PRIV-API-REFLECTION]` (INFORMATIONAL) **Reflection on Internal or Sensitive Classes** [OBSERVED] (Confidence: medium)
  - Description: Static references to reflection APIs combined with internal framework class names detected.
  - Evidence: api:java.lang.Class, api:java.lang.reflect.Method
  - Remediation Relevance: Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and policy compliance.
- `[PRIV-REC-BOOT]` (INFORMATIONAL) **Boot & Package Replacement Receivers** [OBSERVED] (Confidence: confirmed)
  - Description: Manifest declarations for broadcast receivers listening to device boot or package replacement events.
  - Evidence: receiver:de.audioattack.openlink.conf.PackageChangeBroadcastReceiver:action:android.intent.action.BOOT_COMPLETED, receiver:de.audioattack.openlink.conf.PackageChangeBroadcastReceiver:action:android.intent.action.MY_PACKAGE_REPLACED
  - Remediation Relevance: Review background startup persistence at device boot.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 0
- Unknown Findings Count: 0
- Inconclusive Items Count: 1
  - 2 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
