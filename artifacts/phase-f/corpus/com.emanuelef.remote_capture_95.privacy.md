# Privacy & Tracker Intelligence Report: com.emanuelef.remote_capture v2.0.2

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 13
- High-Risk / Dangerous Permissions: 3

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 1
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
- Total Extracted Endpoints: 127
- First-Party Domains: 0
- Third-Party Domains: 96
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `unknown` (117): adblock.dns.mullvad.net, addlive.io, adult-filter-dns.cleanbrowsing.org, akamaiedge.net, akamaihd.net
- Category `update_infrastructure` (10): github.com, https://github.com/emanuele-f/PCAPdroid, https://github.com/emanuele-f/PCAPdroid-mitm, https://github.com/emanuele-f/PCAPdroid-mitm/releases/download/v, https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md

## Section E: Sensitive API Indicators
- Device Identifiers: Build.SERIAL, Settings.Secure.ANDROID_ID, TelephonyManager.getDeviceId
- Advertising ID Client: None
- Clipboard Access: Detected
- Dynamic Code Loading: loadClass
- Sensitive Reflection: android.app.ActivityThread, androidx.fragment.app.DefaultSpecialEffectsController$TransitionEffect$onStart$4.invoke, java.lang.Class, java.lang.reflect.Method
- Location APIs: Referenced location API: android.location.LocationManager, Referenced location API: android.location.LocationManager;->getLastKnownLocation(Ljava.lang.String;)Landroid.location.Location, Referenced location API: android.widget.PopupWindow;->showAtLocation(Landroid.view.View, Referenced location API: com.emanuelef.remote_capture.Geolocation;->downloadAndUnzip(Landroid.content.Context, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getASN(Ljava.net.InetAddress;)Lcom.emanuelef.remote_capture.model.Geomodel$ASN, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getAsnFile(Landroid.content.Context;)Ljava.io.File, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getCountryCode(Ljava.net.InetAddress;)Ljava.lang.String, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getCountryFile(Landroid.content.Context;)Ljava.io.File, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getDbDate(Landroid.content.Context;)Ljava.util.Date, Referenced location API: com.emanuelef.remote_capture.Geolocation;->getDbDate(Ljava.io.File;)Ljava.util.Date, Referenced location API: com.google.gson.stream.JsonReader;->locationString()Ljava.lang.String, android.location.LocationManager
- Contacts APIs: None
- Audio Capture APIs: None
- Camera APIs: None

## Section F: Correlated Findings
- Total Findings: 10
- `[PRIV-CAP-DEVICE-IDENTIFIERS]` (HIGH) **Device Identifier Access References Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Static code references found for device identifiers: TelephonyManager.getDeviceId, Settings.Secure.ANDROID_ID, Build.SERIAL.
  - Evidence: dex:TelephonyManager.getDeviceId, dex:Settings.Secure.ANDROID_ID
  - Remediation Relevance: Assess compliance with modern Android platform guidelines; prefer resettable identifiers.
- `[PRIV-API-CLIPBOARD]` (INFORMATIONAL) **Clipboard Access APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to ClipboardManager clip access methods detected.
  - Evidence: api:android.content.ClipboardManager
  - Remediation Relevance: Verify whether clipboard reads access user data unexpectedly.
- `[PRIV-API-LOCATION]` (INFORMATIONAL) **Location Framework API Invocations** [OBSERVED] (Confidence: high)
  - Description: Static references to Android LocationManager or Google Play Services location providers detected in bytecode.
  - Evidence: api:android.location.LocationManager
  - Remediation Relevance: Informational; examine whether precise or coarse location access is required for core functionality.
- `[PRIV-API-REFLECTION]` (INFORMATIONAL) **Reflection on Internal or Sensitive Classes** [OBSERVED] (Confidence: medium)
  - Description: Static references to reflection APIs combined with internal framework class names detected.
  - Evidence: api:java.lang.Class, api:java.lang.reflect.Method
  - Remediation Relevance: Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and policy compliance.
- `[PRIV-API-SCHEDULING]` (INFORMATIONAL) **Background Job Scheduling & Alarm APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to WorkManager, JobScheduler, or AlarmManager background execution detected.
  - Evidence: method:enqueue
  - Remediation Relevance: Evaluate whether background tasks perform unauthorized periodic synchronization or data transmission.
- `[PRIV-REC-BOOT]` (INFORMATIONAL) **Boot & Package Replacement Receivers** [OBSERVED] (Confidence: confirmed)
  - Description: Manifest declarations for broadcast receivers listening to device boot or package replacement events.
  - Evidence: receiver:com.emanuelef.remote_capture.BootReceiver:action:android.intent.action.BOOT_COMPLETED
  - Remediation Relevance: Review background startup persistence at device boot.
- `[PRIV-API-DEVICE-IDENTIFIER]` (LOW) **Hardware & Device Identifier Access** [OBSERVED] (Confidence: high)
  - Description: Static references to persistent device identifiers (IMEI, MEID, SIM serial, or ANDROID_ID) detected.
  - Evidence: string:android_id
  - Remediation Relevance: Assess compliance with modern Android platform privacy guidelines (prefer resettable advertising IDs or app-scoped UUIDs over hardware identifiers).
- `[PRIV-API-DYNAMIC-CODE]` (LOW) **Dynamic Code Loading Facilities** [OBSERVED] (Confidence: high)
  - Description: Static references to DexClassLoader, PathClassLoader, or InMemoryDexClassLoader detected.
  - Evidence: method:loadClass
  - Remediation Relevance: Dynamic loading allows runtime code execution bypassing static inspection; verify source and integrity.
- `[PRIV-CAP-CLIPBOARD]` (LOW) **Clipboard Access Capability Detected** [OBSERVED] (Confidence: medium)
  - Description: Application references android.content.ClipboardManager API.
  - Evidence: dex:android.content.ClipboardManager
  - Remediation Relevance: Verify clipboard reads access user data only upon direct user paste interaction.
- `[PRIV-CAP-LOCATION]` (MEDIUM) **Location Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application declares location permissions () and references location APIs (com.emanuelef.remote_capture.Geolocation;->getCountryCode(Ljava.net.InetAddress;)Ljava.lang.String, com.emanuelef.remote_capture.Geolocation;->getASN(Ljava.net.InetAddress;)Lcom.emanuelef.remote_capture.model.Geomodel$ASN, android.widget.PopupWindow;->showAtLocation(Landroid.view.View).
  - Evidence: api:com.emanuelef.remote_capture.Geolocation;->getCountryCode(Ljava.net.InetAddress;)Ljava.lang.String, api:com.emanuelef.remote_capture.Geolocation;->getASN(Ljava.net.InetAddress;)Lcom.emanuelef.remote_capture.model.Geomodel$ASN
  - Remediation Relevance: Ensure location access is transparent and justified by application features.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 1
- Unknown Findings Count: 0
- Inconclusive Items Count: 1
  - 117 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
