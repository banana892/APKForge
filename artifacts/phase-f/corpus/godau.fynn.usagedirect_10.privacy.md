# Privacy & Tracker Intelligence Report: godau.fynn.usagedirect v0.8.1

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 2
- High-Risk / Dangerous Permissions: 1

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 0
- Accessibility Services: 1
- Notification Listeners: 0

## Section C: SDK & Library Indicators
- Total Third-Party SDK Indicators: 0
  - Trackers: 0
  - Advertising: 0
  - Analytics: 0
  - Telemetry / Crash: 0
- Network Traffic Determination: *Static presence of an SDK library does not prove actual data transmission at runtime.*

## Section D: Domains & Endpoints
- Total Extracted Endpoints: 28
- First-Party Domains: 0
- Third-Party Domains: 17
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `unknown` (24): android.app, android.intent.extra.cc, android.support.v4.app, androidx.core.app, androidx.fragment.app
- Category `update_infrastructure` (4): github.com, https://github.com/Madrapps/Pikolo/, https://github.com/googlesamples/android-AppUsageStatistics, https://github.com/ogaclejapan/SmartTabLayout

## Section E: Sensitive API Indicators
- Device Identifiers: Build.SERIAL, Settings.Secure.ANDROID_ID, TelephonyManager.getDeviceId, TelephonyManager.getImei
- Advertising ID Client: None
- Clipboard Access: Detected
- Dynamic Code Loading: loadClass
- Sensitive Reflection: android.app.ActivityThread, android.os.SystemProperties, java.lang.Class, java.lang.reflect.Method, kotlinx.coroutines.flow.FlowKt__ZipKt$combineTransform$7$1.invoke
- Location APIs: Referenced location API: android.location.GnssStatus, Referenced location API: android.location.GnssStatus$Callback, Referenced location API: android.location.GpsSatellite, Referenced location API: android.location.GpsStatus, Referenced location API: android.location.GpsStatus;->getSatellites()Ljava.lang.Iterable, Referenced location API: android.location.Location, Referenced location API: android.location.Location;->getExtras()Landroid.os.Bundle, Referenced location API: android.location.LocationListener, Referenced location API: android.location.LocationManager, Referenced location API: android.location.LocationManager;->getAllProviders()Ljava.util.List, Referenced location API: android.location.LocationManager;->getCurrentLocation(Ljava.lang.String, Referenced location API: android.location.LocationManager;->getGnssHardwareModelName()Ljava.lang.String, Referenced location API: android.location.LocationManager;->getGpsStatus(Landroid.location.GpsStatus;)Landroid.location.GpsStatus, Referenced location API: android.location.LocationManager;->getLastKnownLocation(Ljava.lang.String;)Landroid.location.Location, Referenced location API: android.location.LocationManager;->getProvider(Ljava.lang.String;)Landroid.location.LocationProvider, Referenced location API: android.location.LocationManager;->registerGnssStatusCallback(Landroid.location.GnssStatus$Callback, Referenced location API: android.location.LocationManager;->registerGnssStatusCallback(Ljava.util.concurrent.Executor, Referenced location API: android.location.LocationManager;->requestLocationUpdates(Ljava.lang.String, Referenced location API: android.location.LocationRequest, Referenced location API: android.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->build()Landroid.location.LocationRequest, Referenced location API: android.location.LocationRequest$Builder;->setDurationMillis(J)Landroid.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->setMaxUpdateDelayMillis(J)Landroid.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->setMaxUpdates(I)Landroid.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->setMinUpdateDistanceMeters(F)Landroid.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->setMinUpdateIntervalMillis(J)Landroid.location.LocationRequest$Builder, Referenced location API: android.location.LocationRequest$Builder;->setQuality(I)Landroid.location.LocationRequest$Builder, Referenced location API: android.widget.PopupWindow;->showAtLocation(Landroid.view.View, Referenced location API: androidx.appcompat.app.TwilightManager;->getLastKnownLocation()Landroid.location.Location, Referenced location API: androidx.appcompat.app.TwilightManager;->getLastKnownLocationForProvider(Ljava.lang.String;)Landroid.location.Location, Referenced location API: androidx.core.location.GnssStatusCompat;->wrap(Landroid.location.GnssStatus;)Landroidx.core.location.GnssStatusCompat, Referenced location API: androidx.core.location.GnssStatusCompat;->wrap(Landroid.location.GpsStatus;)Landroidx.core.location.GnssStatusCompat, Referenced location API: androidx.core.location.GnssStatusWrapper$Api26Impl;->getCarrierFrequencyHz(Landroid.location.GnssStatus, Referenced location API: androidx.core.location.GnssStatusWrapper$Api26Impl;->hasCarrierFrequencyHz(Landroid.location.GnssStatus, Referenced location API: androidx.core.location.GnssStatusWrapper$Api30Impl;->getBasebandCn0DbHz(Landroid.location.GnssStatus, Referenced location API: androidx.core.location.GnssStatusWrapper$Api30Impl;->hasBasebandCn0DbHz(Landroid.location.GnssStatus, Referenced location API: androidx.core.location.GpsStatusWrapper;->getSatellite(I)Landroid.location.GpsSatellite, Referenced location API: androidx.core.location.LocationCompat$Api26Impl;->setBearingAccuracyDegrees(Landroid.location.Location, Referenced location API: androidx.core.location.LocationCompat$Api26Impl;->setSpeedAccuracyMetersPerSecond(Landroid.location.Location, Referenced location API: androidx.core.location.LocationCompat$Api26Impl;->setVerticalAccuracyMeters(Landroid.location.Location, Referenced location API: androidx.core.location.LocationCompat;->getSetIsFromMockProviderMethod()Ljava.lang.reflect.Method, Referenced location API: androidx.core.location.LocationListenerCompat, Referenced location API: androidx.core.location.LocationListenerCompat;->onStatusChanged(Ljava.lang.String, Referenced location API: androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda0;-><init>(Landroidx.core.util.Consumer, Referenced location API: androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda2;-><init>(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api19Impl;->tryRequestLocationUpdates(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api24Impl;->registerGnssStatusCallback(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api24Impl;->unregisterGnssStatusCallback(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api28Impl;->getGnssHardwareModelName(Landroid.location.LocationManager;)Ljava.lang.String, Referenced location API: androidx.core.location.LocationManagerCompat$Api30Impl;->getCurrentLocation(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api30Impl;->registerGnssStatusCallback(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api30Impl;->tryRequestLocationUpdates(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api31Impl;->hasProvider(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$Api31Impl;->requestLocationUpdates(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$CancellableLocationListener$$ExternalSyntheticLambda1;-><init>(Landroidx.core.util.Consumer, Referenced location API: androidx.core.location.LocationManagerCompat$CancellableLocationListener;-><init>(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$CancellableLocationListener;->lambda$onLocationChanged$1(Landroidx.core.util.Consumer, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda0;-><init>(Landroidx.core.location.LocationManagerCompat$GpsStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda1;-><init>(Landroidx.core.location.LocationManagerCompat$GpsStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda2;-><init>(Landroidx.core.location.LocationManagerCompat$GpsStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda3;-><init>(Landroidx.core.location.LocationManagerCompat$GpsStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport;)Ljava.lang.Boolean, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport;-><init>(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport;->lambda$onGpsStatusChanged$2$androidx-core-location-LocationManagerCompat$GpsStatusTransport(Ljava.util.concurrent.Executor, Referenced location API: androidx.core.location.LocationManagerCompat$GpsStatusTransport;->lambda$onGpsStatusChanged$3$androidx-core-location-LocationManagerCompat$GpsStatusTransport(Ljava.util.concurrent.Executor, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerKey;-><init>(Ljava.lang.String, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda0;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerTransport, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda1;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerTransport, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda2;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerTransport, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda3;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerTransport, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda5;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerTransport, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport;-><init>(Landroidx.core.location.LocationManagerCompat$LocationListenerKey, Referenced location API: androidx.core.location.LocationManagerCompat$LocationListenerTransport;->lambda$onStatusChanged$3$androidx-core-location-LocationManagerCompat$LocationListenerTransport(Ljava.lang.String, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda0;-><init>(Landroidx.core.location.LocationManagerCompat$PreRGnssStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda1;-><init>(Landroidx.core.location.LocationManagerCompat$PreRGnssStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda2;-><init>(Landroidx.core.location.LocationManagerCompat$PreRGnssStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda3;-><init>(Landroidx.core.location.LocationManagerCompat$PreRGnssStatusTransport, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport;->lambda$onFirstFix$2$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport(Ljava.util.concurrent.Executor, Referenced location API: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport;->lambda$onSatelliteStatusChanged$3$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport(Ljava.util.concurrent.Executor, Referenced location API: androidx.core.location.LocationManagerCompat;->lambda$getCurrentLocation$0(Landroidx.core.util.Consumer, Referenced location API: androidx.core.location.LocationManagerCompat;->lambda$registerGnssStatusCallback$1(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat;->registerGnssStatusCallback(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationManagerCompat;->registerLocationListenerTransport(Landroid.location.LocationManager, Referenced location API: androidx.core.location.LocationRequestCompat, Referenced location API: androidx.core.location.LocationRequestCompat$Api19Impl;->toLocationRequest(Landroidx.core.location.LocationRequestCompat, Referenced location API: androidx.core.location.LocationRequestCompat$Api31Impl;->toLocationRequest(Landroidx.core.location.LocationRequestCompat;)Landroid.location.LocationRequest, Referenced location API: androidx.core.location.LocationRequestCompat;->toLocationRequest()Landroid.location.LocationRequest, Referenced location API: androidx.core.location.LocationRequestCompat;->toLocationRequest(Ljava.lang.String;)Landroid.location.LocationRequest, Referenced location API: androidx.core.util.HalfKt$$ExternalSyntheticApiModelOutline0;->m$1(Landroid.location.GnssStatus, Referenced location API: androidx.core.util.HalfKt$$ExternalSyntheticApiModelOutline0;->m$2(Landroid.location.GnssStatus, Referenced location API: androidx.core.util.HalfKt$$ExternalSyntheticApiModelOutline0;->m(Landroid.location.GnssStatus, Referenced location API: androidx.core.util.HalfKt$$ExternalSyntheticApiModelOutline0;->m(Ljava.lang.Object;)Landroid.location.GnssStatus, Referenced location API: androidx.core.util.HalfKt$$ExternalSyntheticApiModelOutline0;->m(Ljava.lang.Object;)Landroid.location.LocationRequest, Referenced location API: androidx.core.view.accessibility.AccessibilityNodeInfoCompat;->addSpanLocationToExtras(Landroid.text.style.ClickableSpan, android.location.LocationListener, android.location.LocationManager, getLastKnownLocation, requestLocationUpdates
- Contacts APIs: None
- Audio Capture APIs: None
- Camera APIs: android.hardware.camera2.CameraManager

## Section F: Correlated Findings
- Total Findings: 12
- `[PRIV-CAP-CAMERA]` (HIGH) **Camera Capture Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application requests camera permission and references camera capture APIs.
  - Evidence: api:android.hardware.camera2.CameraManager
  - Remediation Relevance: Verify camera hardware access is necessary and accompanied by runtime prompts.
- `[PRIV-CAP-DEVICE-IDENTIFIERS]` (HIGH) **Device Identifier Access References Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Static code references found for device identifiers: TelephonyManager.getDeviceId, TelephonyManager.getImei, Settings.Secure.ANDROID_ID, Build.SERIAL.
  - Evidence: dex:TelephonyManager.getDeviceId, dex:TelephonyManager.getImei
  - Remediation Relevance: Assess compliance with modern Android platform guidelines; prefer resettable identifiers.
- `[PRIV-API-CAMERA]` (INFORMATIONAL) **Camera Hardware & Capture APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to Camera, Camera2, or CameraX APIs detected in bytecode.
  - Evidence: api:android.hardware.camera2.CameraManager
  - Remediation Relevance: Ensure camera hardware access is necessary and accompanied by runtime consent prompts.
- `[PRIV-API-CLIPBOARD]` (INFORMATIONAL) **Clipboard Access APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to ClipboardManager clip access methods detected.
  - Evidence: api:android.content.ClipboardManager
  - Remediation Relevance: Verify whether clipboard reads access user data unexpectedly.
- `[PRIV-API-LOCATION]` (INFORMATIONAL) **Location Framework API Invocations** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to Android LocationManager or Google Play Services location providers detected in bytecode.
  - Evidence: api:android.location.LocationListener, api:android.location.LocationManager
  - Remediation Relevance: Informational; examine whether precise or coarse location access is required for core functionality.
- `[PRIV-API-REFLECTION]` (INFORMATIONAL) **Reflection on Internal or Sensitive Classes** [OBSERVED] (Confidence: medium)
  - Description: Static references to reflection APIs combined with internal framework class names detected.
  - Evidence: api:java.lang.Class, api:java.lang.reflect.Method
  - Remediation Relevance: Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and policy compliance.
- `[PRIV-API-SCHEDULING]` (INFORMATIONAL) **Background Job Scheduling & Alarm APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to WorkManager, JobScheduler, or AlarmManager background execution detected.
  - Evidence: api:android.app.AlarmManager, api:android.app.job.JobScheduler
  - Remediation Relevance: Evaluate whether background tasks perform unauthorized periodic synchronization or data transmission.
- `[PRIV-API-DEVICE-IDENTIFIER]` (LOW) **Hardware & Device Identifier Access** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to persistent device identifiers (IMEI, MEID, SIM serial, or ANDROID_ID) detected.
  - Evidence: api:android.telephony.TelephonyManager, method:androidx.core.telephony.TelephonyManagerCompat.getImei
  - Remediation Relevance: Assess compliance with modern Android platform privacy guidelines (prefer resettable advertising IDs or app-scoped UUIDs over hardware identifiers).
- `[PRIV-API-DYNAMIC-CODE]` (LOW) **Dynamic Code Loading Facilities** [OBSERVED] (Confidence: high)
  - Description: Static references to DexClassLoader, PathClassLoader, or InMemoryDexClassLoader detected.
  - Evidence: method:loadClass
  - Remediation Relevance: Dynamic loading allows runtime code execution bypassing static inspection; verify source and integrity.
- `[PRIV-CAP-CLIPBOARD]` (LOW) **Clipboard Access Capability Detected** [OBSERVED] (Confidence: medium)
  - Description: Application references android.content.ClipboardManager API.
  - Evidence: dex:android.content.ClipboardManager
  - Remediation Relevance: Verify clipboard reads access user data only upon direct user paste interaction.
- `[PRIV-CAP-ACCESSIBILITY]` (MEDIUM) **Accessibility Service Capability Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Application defines or references an Android AccessibilityService.
  - Evidence: manifest:service
  - Remediation Relevance: Accessibility services require explicit user opt-in in Android system settings.
- `[PRIV-CAP-LOCATION]` (MEDIUM) **Location Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application declares location permissions () and references location APIs (android.location.LocationRequest$Builder, androidx.core.location.LocationManagerCompat;->registerGnssStatusCallback(Landroid.location.LocationManager, android.location.LocationManager;->getCurrentLocation(Ljava.lang.String).
  - Evidence: api:android.location.LocationRequest$Builder, api:androidx.core.location.LocationManagerCompat;->registerGnssStatusCallback(Landroid.location.LocationManager
  - Remediation Relevance: Ensure location access is transparent and justified by application features.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 2
- Unknown Findings Count: 0
- Inconclusive Items Count: 1
  - 24 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
