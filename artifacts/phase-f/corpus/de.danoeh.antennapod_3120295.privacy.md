# Privacy & Tracker Intelligence Report: de.danoeh.antennapod v3.12.2

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 11
- High-Risk / Dangerous Permissions: 1
- Declared Without Static Code Correlation: 1
  - `android.permission.BLUETOOTH` (declared only)

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
- Total Extracted Endpoints: 95
- First-Party Domains: 0
- Third-Party Domains: 57
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `unknown` (85): action.de, android.app, android.intent.extra.cc, android.net, android.support.v4.app
- Category `update_infrastructure` (10): github.com, https://github.com/, https://github.com/AntennaPod/AntennaPod/issues, https://github.com/Podcastindex-org/podcast-namespace/blob/main/docs/1.0.md, https://github.com/ReactiveX/RxJava/wiki/Error-Handling

## Section E: Sensitive API Indicators
- Device Identifiers: Build.SERIAL, Settings.Secure.ANDROID_ID, TelephonyManager.getDeviceId
- Advertising ID Client: None
- Clipboard Access: Detected
- Dynamic Code Loading: loadClass
- Sensitive Reflection: android.app.ActivityThread, android.os.SystemProperties, androidx.fragment.app.DefaultSpecialEffectsController$retainMatchingViews$1.invoke, androidx.work.impl.utils.CancelWorkRunnable.forName, java.lang.Class, java.lang.reflect.Method
- Location APIs: Referenced location API: android.location.Location, Referenced location API: android.location.LocationManager, Referenced location API: android.location.LocationManager;->getLastKnownLocation(Ljava.lang.String;)Landroid.location.Location, Referenced location API: android.widget.PopupWindow;->showAtLocation(Landroid.view.View, Referenced location API: androidx.appcompat.app.TwilightManager;->getLastKnownLocation()Landroid.location.Location, Referenced location API: androidx.appcompat.app.TwilightManager;->getLastKnownLocationForProvider(Ljava.lang.String;)Landroid.location.Location, Referenced location API: androidx.core.view.accessibility.AccessibilityNodeInfoCompat;->addSpanLocationToExtras(Landroid.text.style.ClickableSpan, Referenced location API: androidx.media3.exoplayer.source.SampleDataQueue;->readData(Landroidx.media3.exoplayer.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.material.carousel.CarouselLayoutManager;->calculateChildOffsetCenterForLocation(Landroid.view.View, Referenced location API: com.google.android.material.carousel.CarouselLayoutManager;->updateChildMaskForLocation(Landroid.view.View, Referenced location API: de.danoeh.antennapod.model.feed.FeedItem;->getImageLocation()Ljava.lang.String, Referenced location API: de.danoeh.antennapod.model.playback.Playable;->getImageLocation()Ljava.lang.String, Referenced location API: de.danoeh.antennapod.storage.preferences.UserPreferences$EnqueueLocation;-><init>(Ljava.lang.String, Referenced location API: de.danoeh.antennapod.storage.preferences.UserPreferences$EnqueueLocation;->valueOf(Ljava.lang.String;)Lde.danoeh.antennapod.storage.preferences.UserPreferences$EnqueueLocation, Referenced location API: de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getEpisodeListImageLocation(Lde.danoeh.antennapod.model.feed.FeedItem;)Ljava.lang.String, Referenced location API: de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getEpisodeListImageLocation(Lde.danoeh.antennapod.model.playback.Playable;)Ljava.lang.String, Referenced location API: de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getFallbackImageLocation(Lde.danoeh.antennapod.model.feed.FeedItem;)Ljava.lang.String, Referenced location API: de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getFallbackImageLocation(Lde.danoeh.antennapod.model.playback.Playable;)Ljava.lang.String, Referenced location API: org.jsoup.nodes.Document;->location()Ljava.lang.String, android.location.LocationManager, getLastKnownLocation
- Contacts APIs: android.provider.ContactsContract$Contacts;->lookupContact(Landroid.content.ContentResolver, android.provider.ContactsContract$Contacts;->openContactPhotoInputStream(Landroid.content.ContentResolver
- Audio Capture APIs: None
- Camera APIs: androidx.media3.exoplayer.DefaultRenderersFactory;->buildCameraMotionRenderers(Landroid.content.Context

## Section F: Correlated Findings
- Total Findings: 13
- `[PRIV-CAP-CAMERA]` (HIGH) **Camera Capture Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application requests camera permission and references camera capture APIs.
  - Evidence: api:androidx.media3.exoplayer.DefaultRenderersFactory;->buildCameraMotionRenderers(Landroid.content.Context
  - Remediation Relevance: Verify camera hardware access is necessary and accompanied by runtime prompts.
- `[PRIV-CAP-CONTACTS]` (HIGH) **Contacts Access Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application requests contacts permission and references ContactsContract APIs.
  - Evidence: api:android.provider.ContactsContract$Contacts;->openContactPhotoInputStream(Landroid.content.ContentResolver, api:android.provider.ContactsContract$Contacts;->lookupContact(Landroid.content.ContentResolver
  - Remediation Relevance: Review if address book access aligns with declared privacy policy.
- `[PRIV-CAP-DEVICE-IDENTIFIERS]` (HIGH) **Device Identifier Access References Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Static code references found for device identifiers: TelephonyManager.getDeviceId, Settings.Secure.ANDROID_ID, Build.SERIAL.
  - Evidence: dex:TelephonyManager.getDeviceId, dex:Settings.Secure.ANDROID_ID
  - Remediation Relevance: Assess compliance with modern Android platform guidelines; prefer resettable identifiers.
- `[PRIV-API-CLIPBOARD]` (INFORMATIONAL) **Clipboard Access APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to ClipboardManager clip access methods detected.
  - Evidence: api:android.content.ClipboardManager
  - Remediation Relevance: Verify whether clipboard reads access user data unexpectedly.
- `[PRIV-API-LOCATION]` (INFORMATIONAL) **Location Framework API Invocations** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to Android LocationManager or Google Play Services location providers detected in bytecode.
  - Evidence: api:android.location.LocationManager, method:getLastKnownLocation
  - Remediation Relevance: Informational; examine whether precise or coarse location access is required for core functionality.
- `[PRIV-API-REFLECTION]` (INFORMATIONAL) **Reflection on Internal or Sensitive Classes** [OBSERVED] (Confidence: medium)
  - Description: Static references to reflection APIs combined with internal framework class names detected.
  - Evidence: api:java.lang.Class, api:java.lang.reflect.Method
  - Remediation Relevance: Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and policy compliance.
- `[PRIV-API-SCHEDULING]` (INFORMATIONAL) **Background Job Scheduling & Alarm APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to WorkManager, JobScheduler, or AlarmManager background execution detected.
  - Evidence: api:android.app.AlarmManager, api:android.app.job.JobScheduler
  - Remediation Relevance: Evaluate whether background tasks perform unauthorized periodic synchronization or data transmission.
- `[PRIV-API-WEBVIEW]` (INFORMATIONAL) **Embedded WebView & Web Interface APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to Android WebView configuration and web execution interfaces detected.
  - Evidence: api:android.webkit.WebView
  - Remediation Relevance: Review WebView security settings (e.g. JavaScript execution and native interface bridges).
- `[PRIV-REC-BOOT]` (INFORMATIONAL) **Boot & Package Replacement Receivers** [OBSERVED] (Confidence: confirmed)
  - Description: Manifest declarations for broadcast receivers listening to device boot or package replacement events.
  - Evidence: receiver:androidx.work.impl.background.systemalarm.RescheduleReceiver:action:android.intent.action.BOOT_COMPLETED
  - Remediation Relevance: Review background startup persistence at device boot.
- `[PRIV-API-DEVICE-IDENTIFIER]` (LOW) **Hardware & Device Identifier Access** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to persistent device identifiers (IMEI, MEID, SIM serial, or ANDROID_ID) detected.
  - Evidence: api:android.telephony.TelephonyManager, method:de.danoeh.antennapod.storage.preferences.SynchronizationCredentials.getDeviceId
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
  - Description: Application declares location permissions () and references location APIs (androidx.media3.exoplayer.source.SampleDataQueue;->readData(Landroidx.media3.exoplayer.source.SampleDataQueue$AllocationNode, de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getFallbackImageLocation(Lde.danoeh.antennapod.model.playback.Playable;)Ljava.lang.String, de.danoeh.antennapod.model.playback.Playable;->getImageLocation()Ljava.lang.String).
  - Evidence: api:androidx.media3.exoplayer.source.SampleDataQueue;->readData(Landroidx.media3.exoplayer.source.SampleDataQueue$AllocationNode, api:de.danoeh.antennapod.ui.episodes.ImageResourceUtils;->getFallbackImageLocation(Lde.danoeh.antennapod.model.playback.Playable;)Ljava.lang.String
  - Remediation Relevance: Ensure location access is transparent and justified by application features.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 3
- Unknown Findings Count: 0
- Inconclusive Items Count: 2
  - Permission declared without API references: android.permission.BLUETOOTH
  - 85 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
