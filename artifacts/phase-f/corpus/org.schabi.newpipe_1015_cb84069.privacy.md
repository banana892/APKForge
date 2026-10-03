# Privacy & Tracker Intelligence Report: org.schabi.newpipe v0.29.1

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 11
- High-Risk / Dangerous Permissions: 3

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 1
- Accessibility Services: 0
- Notification Listeners: 0

## Section C: SDK & Library Indicators
- Total Third-Party SDK Indicators: 1
  - Trackers: 0
  - Advertising: 1
  - Analytics: 0
  - Telemetry / Crash: 0
- Network Traffic Determination: *Static presence of an SDK library does not prove actual data transmission at runtime.*
  - **Google AdMob / Google Mobile Ads** (`ad.google.admob`, category: `advertising`, confidence: `medium`)
    - Endpoints: googleads.g.doubleclick.net

## Section D: Domains & Endpoints
- Total Extracted Endpoints: 246
- First-Party Domains: 1
- Third-Party Domains: 118
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `advertising` (1): googleads.g.doubleclick.net
- Category `first_party` (1): newpipe.schabi.org
- Category `unknown` (236): android.app, android.googlesource.com, android.net, androidx.appcompat.app, androidx.core.app
- Category `update_infrastructure` (8): github.com, https://github.com/ReactiveX/RxJava/wiki/Error-Handling, https://github.com/ReactiveX/RxJava/wiki/What, https://github.com/TeamNewPipe/NewPipe, https://github.com/TeamNewPipe/NewPipe/issues

## Section E: Sensitive API Indicators
- Device Identifiers: Build.SERIAL, TelephonyManager.getDeviceId
- Advertising ID Client: None
- Clipboard Access: Detected
- Dynamic Code Loading: loadClass
- Sensitive Reflection: android.app.ActivityThread, android.os.SystemProperties, androidx.compose.foundation.pager.PagerKt$pagerSemantics$performForwardPaging$1.invoke, java.lang.Class, java.lang.reflect.Method
- Location APIs: Referenced location API: android.location.LocationManager, Referenced location API: android.location.LocationManager;->getLastKnownLocation(Ljava.lang.String;)Landroid.location.Location, Referenced location API: android.widget.PopupWindow;->showAtLocation(Landroid.view.View, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2$1$1;->invoke()Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2$1;->create(Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2$1;->invokeSuspend(Ljava.lang.Object;)Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2$2;->create(Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2$2;->invokeSuspend(Ljava.lang.Object;)Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2;->create(Ljava.lang.Object, Referenced location API: androidx.compose.foundation.relocation.BringIntoViewResponderNode$bringIntoView$2;->invokeSuspend(Ljava.lang.Object;)Ljava.lang.Object, Referenced location API: androidx.compose.runtime.composer.gapbuffer.SlotTableKt;->access$locationOf(Ljava.util.ArrayList, Referenced location API: androidx.compose.ui.relocation.BringIntoViewModifierNode;->bringIntoView(Landroidx.compose.ui.node.NodeCoordinator, Referenced location API: androidx.compose.ui.relocation.BringIntoViewModifierNodeKt$bringIntoView$2, Referenced location API: androidx.compose.ui.relocation.BringIntoViewModifierNodeKt$bringIntoView$2;->invoke()Ljava.lang.Object, Referenced location API: com.google.android.exoplayer2.container.Mp4LocationData, Referenced location API: com.google.android.exoplayer2.container.Mp4LocationData$1, Referenced location API: com.google.android.exoplayer2.container.Mp4LocationData$1;->createFromParcel(Landroid.os.Parcel;)Lcom.google.android.exoplayer2.container.Mp4LocationData, Referenced location API: com.google.android.exoplayer2.container.Mp4LocationData$1;->newArray(I)[Lcom.google.android.exoplayer2.container.Mp4LocationData, Referenced location API: com.google.android.exoplayer2.container.Mp4LocationData;-><init>(Landroid.os.Parcel, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue$AllocationNode;->clear()Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue$AllocationNode;->initialize(Lcom.google.android.exoplayer2.upstream.Allocation, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue;->getNodeContainingPosition(Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue;->readData(Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue;->readEncryptionData(Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.source.SampleDataQueue;->readSampleData(Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: com.google.android.exoplayer2.upstream.Allocation, Referenced location API: com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->getAllocation()Lcom.google.android.exoplayer2.upstream.Allocation, Referenced location API: com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->next()Lcom.google.android.exoplayer2.upstream.Allocator$AllocationNode, Referenced location API: com.google.android.exoplayer2.upstream.Allocator;->allocate()Lcom.google.android.exoplayer2.upstream.Allocation, Referenced location API: com.google.android.exoplayer2.util.ParsableByteArray;)Lcom.google.android.exoplayer2.source.SampleDataQueue$AllocationNode, Referenced location API: org.mozilla.javascript.commonjs.module.provider.ModuleSourceProviderBase;->loadFromFallbackLocations(Ljava.lang.String, Referenced location API: org.mozilla.javascript.commonjs.module.provider.ModuleSourceProviderBase;->loadFromPrivilegedLocations(Ljava.lang.String, android.location.LocationManager
- Contacts APIs: None
- Audio Capture APIs: None
- Camera APIs: com.google.android.exoplayer2.DefaultRenderersFactory;->buildCameraMotionRenderers(Landroid.content.Context, com.google.android.exoplayer2.video.spherical.CameraMotionListener, com.google.android.exoplayer2.video.spherical.CameraMotionRenderer, com.google.android.exoplayer2.video.spherical.SphericalGLSurfaceView;->getCameraMotionListener()Lcom.google.android.exoplayer2.video.spherical.CameraMotionListener

## Section F: Correlated Findings
- Total Findings: 13
- `[PRIV-CAP-CAMERA]` (HIGH) **Camera Capture Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application requests camera permission and references camera capture APIs.
  - Evidence: api:com.google.android.exoplayer2.video.spherical.CameraMotionRenderer, api:com.google.android.exoplayer2.video.spherical.SphericalGLSurfaceView;->getCameraMotionListener()Lcom.google.android.exoplayer2.video.spherical.CameraMotionListener
  - Remediation Relevance: Verify camera hardware access is necessary and accompanied by runtime prompts.
- `[PRIV-CAP-DEVICE-IDENTIFIERS]` (HIGH) **Device Identifier Access References Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Static code references found for device identifiers: TelephonyManager.getDeviceId, Build.SERIAL.
  - Evidence: dex:TelephonyManager.getDeviceId, dex:Build.SERIAL
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
- `[PRIV-API-SCHEDULING]` (INFORMATIONAL) **Background Job Scheduling & Alarm APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to WorkManager, JobScheduler, or AlarmManager background execution detected.
  - Evidence: api:android.app.AlarmManager, api:android.app.job.JobScheduler
  - Remediation Relevance: Evaluate whether background tasks perform unauthorized periodic synchronization or data transmission.
- `[PRIV-API-WEBVIEW]` (INFORMATIONAL) **Embedded WebView & Web Interface APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to Android WebView configuration and web execution interfaces detected.
  - Evidence: api:android.webkit.WebView, method:org.chromium.support_lib_boundary.WebViewBuilderBoundaryInterface$Config.addJavascriptInterface
  - Remediation Relevance: Review WebView security settings (e.g. JavaScript execution and native interface bridges).
- `[PRIV-REC-BOOT]` (INFORMATIONAL) **Boot & Package Replacement Receivers** [OBSERVED] (Confidence: confirmed)
  - Description: Manifest declarations for broadcast receivers listening to device boot or package replacement events.
  - Evidence: receiver:androidx.work.impl.background.systemalarm.RescheduleReceiver:action:android.intent.action.BOOT_COMPLETED
  - Remediation Relevance: Review background startup persistence at device boot.
- `[PRIV-API-DEVICE-IDENTIFIER]` (LOW) **Hardware & Device Identifier Access** [OBSERVED] (Confidence: high)
  - Description: Static references to persistent device identifiers (IMEI, MEID, SIM serial, or ANDROID_ID) detected.
  - Evidence: api:android.telephony.TelephonyManager
  - Remediation Relevance: Assess compliance with modern Android platform privacy guidelines (prefer resettable advertising IDs or app-scoped UUIDs over hardware identifiers).
- `[PRIV-API-DYNAMIC-CODE]` (LOW) **Dynamic Code Loading Facilities** [OBSERVED] (Confidence: high)
  - Description: Static references to DexClassLoader, PathClassLoader, or InMemoryDexClassLoader detected.
  - Evidence: method:loadClass
  - Remediation Relevance: Dynamic loading allows runtime code execution bypassing static inspection; verify source and integrity.
- `[PRIV-CAP-CLIPBOARD]` (LOW) **Clipboard Access Capability Detected** [OBSERVED] (Confidence: medium)
  - Description: Application references android.content.ClipboardManager API.
  - Evidence: dex:android.content.ClipboardManager
  - Remediation Relevance: Verify clipboard reads access user data only upon direct user paste interaction.
- `[PRIV-SDK-AD-GOOGLE-ADMOB]` (LOW) **Third-Party Advertising SDK Detected: Google AdMob / Google Mobile Ads** [OBSERVED] (Confidence: medium)
  - Description: Google Mobile Ads SDK for banner, interstitial, and rewarded advertisements.
  - Evidence: domain:googleads.g.doubleclick.net
  - Remediation Relevance: Review third-party library integration and privacy policy disclosures; static presence does not prove runtime data exfiltration.
- `[PRIV-CAP-LOCATION]` (MEDIUM) **Location Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application declares location permissions () and references location APIs (com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->getAllocation()Lcom.google.android.exoplayer2.upstream.Allocation, com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->next()Lcom.google.android.exoplayer2.upstream.Allocator$AllocationNode, com.google.android.exoplayer2.source.SampleDataQueue$AllocationNode).
  - Evidence: api:com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->getAllocation()Lcom.google.android.exoplayer2.upstream.Allocation, api:com.google.android.exoplayer2.upstream.Allocator$AllocationNode;->next()Lcom.google.android.exoplayer2.upstream.Allocator$AllocationNode
  - Remediation Relevance: Ensure location access is transparent and justified by application features.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 2
- Unknown Findings Count: 0
- Inconclusive Items Count: 1
  - 236 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
