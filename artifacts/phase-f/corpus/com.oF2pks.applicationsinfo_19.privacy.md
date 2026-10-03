# Privacy & Tracker Intelligence Report: com.oF2pks.applicationsinfo v1.7-19

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 4
- High-Risk / Dangerous Permissions: 1

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 0
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
- Category `unknown` (2): http://xml.apache.org/xslt, xml.apache.org

## Section E: Sensitive API Indicators
- Device Identifiers: None
- Advertising ID Client: None
- Clipboard Access: None
- Dynamic Code Loading: None
- Sensitive Reflection: None
- Location APIs: None
- Contacts APIs: None
- Audio Capture APIs: None
- Camera APIs: None

## Section F: Correlated Findings
- Total Findings: 1
- `[PRIV-API-WEBVIEW]` (INFORMATIONAL) **Embedded WebView & Web Interface APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to Android WebView configuration and web execution interfaces detected.
  - Evidence: api:android.webkit.WebView
  - Remediation Relevance: Review WebView security settings (e.g. JavaScript execution and native interface bridges).

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 0
- Unknown Findings Count: 0
- Inconclusive Items Count: 1
  - 2 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
