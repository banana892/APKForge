# Privacy & Tracker Intelligence Report: eu.siacs.conversations v2.20.4+free

**Status**: `COMPLETE`

---

## Section A: Permissions
- Declared Permissions Count: 51
- High-Risk / Dangerous Permissions: 14
- Declared Without Static Code Correlation: 4
  - `android.permission.READ_CONTACTS` (declared only)
  - `android.permission.READ_MEDIA_AUDIO` (declared only)
  - `android.permission.READ_MEDIA_IMAGES` (declared only)
  - `android.permission.READ_MEDIA_VIDEO` (declared only)

## Section B: Components & Capabilities
- Background Capabilities: 0
- Boot / Persistence Receivers: 3
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
- Total Extracted Endpoints: 149
- First-Party Domains: 0
- Third-Party Domains: 97
- Disclaimer: *Static domain/URL extraction does not constitute proof that network traffic is sent to these destinations.*
- Category `unknown` (146): a.tile.opentopomap.org, add.cc, aead.cc, algorithm.cc, android.app
- Category `update_infrastructure` (3): github.com, https://github.com/felldo/JEmoji?tab=readme-ov-file#-jemoji-language-module, https://github.com/google/gson/blob/main/Troubleshooting.md#

## Section E: Sensitive API Indicators
- Device Identifiers: Build.SERIAL, Settings.Secure.ANDROID_ID, TelephonyManager.getDeviceId
- Advertising ID Client: None
- Clipboard Access: Detected
- Dynamic Code Loading: loadClass
- Sensitive Reflection: android.app.ActivityThread, androidx.emoji2.emojipicker.EmojiPickerView$3$1.invoke, java.lang.Class, java.lang.reflect.Method, org.conscrypt.metrics.Protocol.forName
- Location APIs: Declared permission: android.permission.ACCESS_COARSE_LOCATION, Declared permission: android.permission.ACCESS_FINE_LOCATION, Referenced location API: android.database.Cursor;)Leu.siacs.conversations.entities.Message$StorageLocation, Referenced location API: android.location.Location, Referenced location API: android.location.Location;->getProvider()Ljava.lang.String, Referenced location API: android.location.LocationManager, Referenced location API: android.location.LocationManager;->getAllProviders()Ljava.util.List, Referenced location API: android.location.LocationManager;->getLastKnownLocation(Ljava.lang.String;)Landroid.location.Location, Referenced location API: android.location.LocationManager;->requestLocationUpdates(Ljava.lang.String, Referenced location API: android.widget.PopupWindow;->showAtLocation(Landroid.view.View, Referenced location API: com.google.gson.stream.JsonReader;->locationString()Ljava.lang.String, Referenced location API: eu.siacs.conversations.databinding.ActivityShareLocationBinding;-><init>(Landroidx.databinding.DataBindingComponent, Referenced location API: eu.siacs.conversations.databinding.ActivityShowLocationBinding;-><init>(Landroidx.databinding.DataBindingComponent, Referenced location API: eu.siacs.conversations.entities.Message$StorageLocation, Referenced location API: eu.siacs.conversations.entities.Message$StorageLocation;-><init>(Ljava.io.File, Referenced location API: eu.siacs.conversations.entities.Message$StorageLocation;->toString()Ljava.lang.String, Referenced location API: eu.siacs.conversations.entities.Message;->storageLocationFromCursor(Landroid.content.Context, Referenced location API: eu.siacs.conversations.persistance.FileBackend;->getLegacyStorageLocation(Landroid.content.Context, Referenced location API: eu.siacs.conversations.persistance.FileBackend;->getSharedStorageLocation(Ljava.lang.String, Referenced location API: eu.siacs.conversations.persistance.FileBackend;->getStorageLocation(Ljava.lang.String, Referenced location API: eu.siacs.conversations.ui.ShowLocationActivity;->createGeoUri()Landroid.net.Uri, Referenced location API: eu.siacs.conversations.ui.ShowLocationActivity;->getStartNavigationIntent()Landroid.content.Intent, Referenced location API: eu.siacs.conversations.ui.util.LocationHelper;->isBetterLocation(Landroid.location.Location, Referenced location API: eu.siacs.conversations.ui.widget.MyLocation;-><init>(Leu.siacs.conversations.ui.LocationActivity, Referenced location API: eu.siacs.conversations.utils.GeoHelper;->showLocationIntent(Landroid.content.Context, Referenced location API: java.lang.String;)Leu.siacs.conversations.entities.Message$StorageLocation, android.location.LocationManager, requestLocationUpdates
- Contacts APIs: android.permission.READ_CONTACTS
- Audio Capture APIs: android.media.AudioRecord, android.media.AudioRecord$Builder, android.media.AudioRecord$Builder;->build()Landroid.media.AudioRecord, android.media.AudioRecord$Builder;->setAudioFormat(Landroid.media.AudioFormat;)Landroid.media.AudioRecord$Builder, android.media.AudioRecord$Builder;->setAudioSource(I)Landroid.media.AudioRecord$Builder, android.media.AudioRecord$Builder;->setBufferSizeInBytes(I)Landroid.media.AudioRecord$Builder, android.media.AudioRecord;)Ljava.lang.String, android.media.AudioRecord;->getFormat()Landroid.media.AudioFormat, android.media.AudioRecord;->getRoutedDevice()Landroid.media.AudioDeviceInfo, android.media.AudioRecord;->getTimestamp(Landroid.media.AudioTimestamp, android.media.AudioRecord;->read(Ljava.nio.ByteBuffer, android.media.AudioRecordingConfiguration, android.media.AudioRecordingConfiguration;->getAudioDevice()Landroid.media.AudioDeviceInfo, android.media.AudioRecordingConfiguration;->getClientFormat()Landroid.media.AudioFormat, android.media.AudioRecordingConfiguration;->getFormat()Landroid.media.AudioFormat, android.media.MediaRecorder, android.permission.READ_MEDIA_AUDIO, android.permission.RECORD_AUDIO, org.webrtc.audio.JavaAudioDeviceModule$AudioRecordErrorCallback, org.webrtc.audio.JavaAudioDeviceModule$AudioRecordErrorCallback;->onWebRtcAudioRecordStartError(Lorg.webrtc.audio.JavaAudioDeviceModule$AudioRecordStartErrorCode, org.webrtc.audio.JavaAudioDeviceModule$AudioRecordStartErrorCode;-><init>(Ljava.lang.String, org.webrtc.audio.JavaAudioDeviceModule$AudioRecordStateCallback, org.webrtc.audio.WebRtcAudioRecord, org.webrtc.audio.WebRtcAudioRecord$$ExternalSyntheticLambda1;-><init>(Lorg.webrtc.audio.WebRtcAudioRecord, org.webrtc.audio.WebRtcAudioRecord$AudioRecordThread;-><init>(Lorg.webrtc.audio.WebRtcAudioRecord, org.webrtc.audio.WebRtcAudioRecord;->$r8$lambda$Zpf0ZnAH8bhRwXfqZHjvFidZLgw(Lorg.webrtc.audio.WebRtcAudioRecord, org.webrtc.audio.WebRtcAudioRecord;->-$$Nest$fgetaudioRecord(Lorg.webrtc.audio.WebRtcAudioRecord;)Landroid.media.AudioRecord, org.webrtc.audio.WebRtcAudioRecord;->-$$Nest$fgetbyteBuffer(Lorg.webrtc.audio.WebRtcAudioRecord;)Ljava.nio.ByteBuffer, org.webrtc.audio.WebRtcAudioRecord;->-$$Nest$mreportWebRtcAudioRecordError(Lorg.webrtc.audio.WebRtcAudioRecord, org.webrtc.audio.WebRtcAudioRecord;->-$$Nest$sfgetnextSchedulerId()Ljava.util.concurrent.atomic.AtomicInteger, org.webrtc.audio.WebRtcAudioRecord;-><init>(Landroid.content.Context, org.webrtc.audio.WebRtcAudioRecord;->audioStateToString(I)Ljava.lang.String, org.webrtc.audio.WebRtcAudioRecord;->checkDeviceMatch(Landroid.media.AudioDeviceInfo, org.webrtc.audio.WebRtcAudioRecord;->lambda$scheduleLogRecordingConfigurationsTask$0(Landroid.media.AudioRecord;)Ljava.lang.String, org.webrtc.audio.WebRtcAudioRecord;->logRecordingConfigurations(Landroid.media.AudioRecord, org.webrtc.audio.WebRtcAudioRecord;->newDefaultScheduler()Ljava.util.concurrent.ScheduledExecutorService, org.webrtc.audio.WebRtcAudioRecord;->reportWebRtcAudioRecordStartError(Lorg.webrtc.audio.JavaAudioDeviceModule$AudioRecordStartErrorCode, retrofit2.Utils$$ExternalSyntheticBUOutline0;->m(Ljava.lang.Object;)Landroid.media.AudioRecordingConfiguration, setAudioSource, startRecording
- Camera APIs: android.hardware.Camera, android.hardware.Camera$AutoFocusCallback, android.hardware.Camera$CameraInfo, android.hardware.Camera$Parameters, android.hardware.Camera$Parameters;->flatten()Ljava.lang.String, android.hardware.Camera$Parameters;->getFlashMode()Ljava.lang.String, android.hardware.Camera$Parameters;->getFocusMode()Ljava.lang.String, android.hardware.Camera$Parameters;->getPreviewSize()Landroid.hardware.Camera$Size, android.hardware.Camera$Parameters;->getSupportedFlashModes()Ljava.util.List, android.hardware.Camera$Parameters;->getSupportedFocusModes()Ljava.util.List, android.hardware.Camera$Parameters;->getSupportedPictureSizes()Ljava.util.List, android.hardware.Camera$Parameters;->getSupportedPreviewFpsRange()Ljava.util.List, android.hardware.Camera$Parameters;->getSupportedPreviewSizes()Ljava.util.List, android.hardware.Camera$Size, android.hardware.Camera;->getParameters()Landroid.hardware.Camera$Parameters, android.hardware.Camera;->open(I)Landroid.hardware.Camera, android.hardware.camera2.CameraCaptureSession, android.hardware.camera2.CameraCaptureSession$CaptureCallback, android.hardware.camera2.CameraCaptureSession$StateCallback, android.hardware.camera2.CameraCaptureSession;->setRepeatingRequest(Landroid.hardware.camera2.CaptureRequest, android.hardware.camera2.CameraCharacteristics, android.hardware.camera2.CameraCharacteristics$Key, android.hardware.camera2.CameraCharacteristics;->get(Landroid.hardware.camera2.CameraCharacteristics$Key;)Ljava.lang.Object, android.hardware.camera2.CameraDevice, android.hardware.camera2.CameraDevice$StateCallback, android.hardware.camera2.CameraDevice;->createCaptureRequest(I)Landroid.hardware.camera2.CaptureRequest$Builder, android.hardware.camera2.CameraDevice;->createCaptureSession(Ljava.util.List, android.hardware.camera2.CameraManager, android.hardware.camera2.CameraManager;->getCameraCharacteristics(Ljava.lang.String;)Landroid.hardware.camera2.CameraCharacteristics, android.hardware.camera2.CameraManager;->getCameraIdList()[Ljava.lang.String, android.hardware.camera2.CameraManager;->openCamera(Ljava.lang.String, android.permission.CAMERA, android.permission.FOREGROUND_SERVICE_CAMERA, eu.siacs.conversations.ui.service.CameraManager;->findValue([Ljava.lang.String, eu.siacs.conversations.ui.service.CameraManager;->open(Landroid.view.TextureView, eu.siacs.conversations.ui.service.CameraManager;->setDesiredCameraParameters(Landroid.hardware.Camera, eu.siacs.conversations.xmpp.jingle.VideoSourceWrapper$Factory;->of(Lorg.webrtc.Camera2Enumerator, openCamera, org.webrtc.Camera1Capturer;-><init>(Ljava.lang.String, org.webrtc.Camera1Enumerator;->convertFramerates(Ljava.util.List;)Ljava.util.List, org.webrtc.Camera1Enumerator;->convertSizes(Ljava.util.List;)Ljava.util.List, org.webrtc.Camera1Enumerator;->enumerateFormats(I)Ljava.util.List, org.webrtc.Camera1Enumerator;->getCameraInfo(I)Landroid.hardware.Camera$CameraInfo, org.webrtc.Camera1Enumerator;->getDeviceName(I)Ljava.lang.String, org.webrtc.Camera1Enumerator;->getSupportedFormats(I)Ljava.util.List, org.webrtc.Camera1Session$SessionState;-><init>(Ljava.lang.String, org.webrtc.Camera1Session;->-$$Nest$fgetcamera(Lorg.webrtc.Camera1Session;)Landroid.hardware.Camera, org.webrtc.Camera1Session;->-$$Nest$fgetcameraThreadHandler(Lorg.webrtc.Camera1Session;)Landroid.os.Handler, org.webrtc.Camera1Session;-><init>(Lorg.webrtc.CameraSession$Events, org.webrtc.Camera1Session;->create(Lorg.webrtc.CameraSession$CreateSessionCallback, org.webrtc.Camera1Session;->findClosestCaptureFormat(Landroid.hardware.Camera$Parameters, org.webrtc.Camera1Session;->findClosestPictureSize(Landroid.hardware.Camera$Parameters, org.webrtc.Camera1Session;->updateCameraParameters(Landroid.hardware.Camera, org.webrtc.Camera2Capturer;-><init>(Landroid.content.Context, org.webrtc.Camera2Enumerator;->convertFramerates([Landroid.util.Range, org.webrtc.Camera2Enumerator;->convertSizes([Landroid.util.Size;)Ljava.util.List, org.webrtc.Camera2Enumerator;->getCameraCharacteristics(Ljava.lang.String;)Landroid.hardware.camera2.CameraCharacteristics, org.webrtc.Camera2Enumerator;->getSupportedFormats(Landroid.content.Context, org.webrtc.Camera2Enumerator;->getSupportedFormats(Landroid.hardware.camera2.CameraManager, org.webrtc.Camera2Enumerator;->getSupportedSizes(Landroid.hardware.camera2.CameraCharacteristics;)Ljava.util.List, org.webrtc.Camera2Session$CameraStateCallback;->getErrorDescription(I)Ljava.lang.String, org.webrtc.Camera2Session$SessionState;-><init>(Ljava.lang.String, org.webrtc.Camera2Session;->-$$Nest$fgetcameraCharacteristics(Lorg.webrtc.Camera2Session;)Landroid.hardware.camera2.CameraCharacteristics, org.webrtc.Camera2Session;->-$$Nest$fgetcameraDevice(Lorg.webrtc.Camera2Session;)Landroid.hardware.camera2.CameraDevice, org.webrtc.Camera2Session;->-$$Nest$fgetcameraThreadHandler(Lorg.webrtc.Camera2Session;)Landroid.os.Handler, org.webrtc.Camera2Session;->-$$Nest$fgetcaptureSession(Lorg.webrtc.Camera2Session;)Landroid.hardware.camera2.CameraCaptureSession, org.webrtc.Camera2Session;->-$$Nest$fgetsurface(Lorg.webrtc.Camera2Session;)Landroid.view.Surface, org.webrtc.Camera2Session;->-$$Nest$fputcameraDevice(Lorg.webrtc.Camera2Session, org.webrtc.Camera2Session;->-$$Nest$fputcaptureSession(Lorg.webrtc.Camera2Session, org.webrtc.Camera2Session;->-$$Nest$fputsurface(Lorg.webrtc.Camera2Session, org.webrtc.Camera2Session;->-$$Nest$mreportError(Lorg.webrtc.Camera2Session, org.webrtc.Camera2Session;-><init>(Lorg.webrtc.CameraSession$CreateSessionCallback, org.webrtc.Camera2Session;->create(Lorg.webrtc.CameraSession$CreateSessionCallback, org.webrtc.CameraCapturer$8;-><init>(Lorg.webrtc.CameraCapturer, org.webrtc.CameraCapturer$SwitchState;-><init>(Ljava.lang.String, org.webrtc.CameraCapturer;->-$$Nest$fgetapplicationContext(Lorg.webrtc.CameraCapturer;)Landroid.content.Context, org.webrtc.CameraCapturer;->-$$Nest$fgetcameraName(Lorg.webrtc.CameraCapturer;)Ljava.lang.String, org.webrtc.CameraCapturer;->-$$Nest$fgetopenCameraTimeoutRunnable(Lorg.webrtc.CameraCapturer;)Ljava.lang.Runnable, org.webrtc.CameraCapturer;->-$$Nest$fgetpendingCameraName(Lorg.webrtc.CameraCapturer;)Ljava.lang.String, org.webrtc.CameraCapturer;->-$$Nest$fgetstateLock(Lorg.webrtc.CameraCapturer;)Ljava.lang.Object, org.webrtc.CameraCapturer;->-$$Nest$fgetuiThreadHandler(Lorg.webrtc.CameraCapturer;)Landroid.os.Handler, org.webrtc.CameraCapturer;->-$$Nest$mswitchCameraInternal(Lorg.webrtc.CameraCapturer, org.webrtc.CameraCapturer;-><init>(Ljava.lang.String, org.webrtc.CameraCapturer;->createCameraSession(Lorg.webrtc.CameraSession$CreateSessionCallback, org.webrtc.CameraCapturer;->initialize(Lorg.webrtc.SurfaceTextureHelper, org.webrtc.CameraCapturer;->reportCameraSwitchError(Ljava.lang.String, org.webrtc.CameraCapturer;->switchCamera(Lorg.webrtc.CameraVideoCapturer$CameraSwitchHandler, org.webrtc.CameraCapturer;->switchCameraInternal(Lorg.webrtc.CameraVideoCapturer$CameraSwitchHandler, org.webrtc.CameraEnumerationAndroid$CaptureFormat, org.webrtc.CameraEnumerationAndroid;->getClosestSupportedFramerateRange(Ljava.util.List, org.webrtc.CameraEnumerationAndroid;->getClosestSupportedSize(Ljava.util.List, org.webrtc.CameraEnumerator;->createCapturer(Ljava.lang.String, org.webrtc.CameraEnumerator;->getDeviceNames()[Ljava.lang.String, org.webrtc.CameraEnumerator;->getSupportedFormats(Ljava.lang.String;)Ljava.util.List, org.webrtc.CameraSession$-CC;->stringValueOf(I)Ljava.lang.String, org.webrtc.CameraSession$CreateSessionCallback;->onFailure(Lorg.webrtc.CameraSession$FailureType, org.webrtc.CameraSession$Events, org.webrtc.CameraSession$Events;->onCameraError(Lorg.webrtc.CameraSession, org.webrtc.CameraSession$FailureType;-><init>(Ljava.lang.String, org.webrtc.CameraVideoCapturer$CameraEventsHandler, org.webrtc.CameraVideoCapturer$CameraEventsHandler;)Lorg.webrtc.CameraVideoCapturer, org.webrtc.CameraVideoCapturer$CameraSwitchHandler

## Section F: Correlated Findings
- Total Findings: 19
- `[PRIV-CAP-CAMERA]` (HIGH) **Camera Capture Capability Detected** [OBSERVED] (Confidence: high)
  - Description: Application requests camera permission and references camera capture APIs.
  - Evidence: permission:android.permission.FOREGROUND_SERVICE_CAMERA, permission:android.permission.CAMERA
  - Remediation Relevance: Verify camera hardware access is necessary and accompanied by runtime prompts.
- `[PRIV-CAP-CONTACTS]` (HIGH) **Contacts Access Capability Detected** [PARTIAL] (Confidence: medium)
  - Description: Application requests contacts permission and references ContactsContract APIs.
  - Evidence: permission:android.permission.READ_CONTACTS
  - Remediation Relevance: Review if address book access aligns with declared privacy policy.
- `[PRIV-CAP-DEVICE-IDENTIFIERS]` (HIGH) **Device Identifier Access References Detected** [OBSERVED] (Confidence: confirmed)
  - Description: Static code references found for device identifiers: TelephonyManager.getDeviceId, Settings.Secure.ANDROID_ID, Build.SERIAL.
  - Evidence: dex:TelephonyManager.getDeviceId, dex:Settings.Secure.ANDROID_ID
  - Remediation Relevance: Assess compliance with modern Android platform guidelines; prefer resettable identifiers.
- `[PRIV-CAP-MICROPHONE]` (HIGH) **Microphone Audio Recording Capability Detected** [OBSERVED] (Confidence: high)
  - Description: Application requests audio recording permission and references audio recording APIs.
  - Evidence: permission:android.permission.RECORD_AUDIO, api:android.media.AudioRecord$Builder;->setAudioFormat(Landroid.media.AudioFormat;)Landroid.media.AudioRecord$Builder
  - Remediation Relevance: Verify microphone recording prompts the user explicitly before capture.
- `[PRIV-API-AUDIO-CAPTURE]` (INFORMATIONAL) **Audio Recording / Microphone Capture APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to AudioRecord or MediaRecorder audio capture facilities detected.
  - Evidence: api:android.media.AudioRecord, api:android.media.MediaRecorder
  - Remediation Relevance: Ensure microphone usage is communicated to the user and required runtime permissions are requested.
- `[PRIV-API-CAMERA]` (INFORMATIONAL) **Camera Hardware & Capture APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to Camera, Camera2, or CameraX APIs detected in bytecode.
  - Evidence: api:android.hardware.Camera, api:android.hardware.camera2.CameraManager
  - Remediation Relevance: Ensure camera hardware access is necessary and accompanied by runtime consent prompts.
- `[PRIV-API-CLIPBOARD]` (INFORMATIONAL) **Clipboard Access APIs** [OBSERVED] (Confidence: high)
  - Description: Static references to ClipboardManager clip access methods detected.
  - Evidence: api:android.content.ClipboardManager
  - Remediation Relevance: Verify whether clipboard reads access user data unexpectedly.
- `[PRIV-API-LOCATION]` (INFORMATIONAL) **Location Framework API Invocations** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to Android LocationManager or Google Play Services location providers detected in bytecode.
  - Evidence: api:android.location.LocationManager, method:requestLocationUpdates
  - Remediation Relevance: Informational; examine whether precise or coarse location access is required for core functionality.
- `[PRIV-API-REFLECTION]` (INFORMATIONAL) **Reflection on Internal or Sensitive Classes** [OBSERVED] (Confidence: medium)
  - Description: Static references to reflection APIs combined with internal framework class names detected.
  - Evidence: api:java.lang.Class, api:java.lang.reflect.Method
  - Remediation Relevance: Reflection may access hidden or non-SDK interfaces; ensure platform compatibility and policy compliance.
- `[PRIV-API-SCHEDULING]` (INFORMATIONAL) **Background Job Scheduling & Alarm APIs** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to WorkManager, JobScheduler, or AlarmManager background execution detected.
  - Evidence: api:android.app.AlarmManager, api:android.app.job.JobScheduler
  - Remediation Relevance: Evaluate whether background tasks perform unauthorized periodic synchronization or data transmission.
- `[PRIV-PERM-UNCORRELATED-READ_CONTACTS]` (INFORMATIONAL) **Declared Permission Without Static Code Reference: android.permission.READ_CONTACTS** [PARTIAL] (Confidence: medium)
  - Description: Permission 'android.permission.READ_CONTACTS' is declared in AndroidManifest.xml, but no matching framework API calls or components were observed statically.
  - Evidence: manifest:permission:android.permission.READ_CONTACTS
  - Remediation Relevance: Informational; verify if this permission is needed dynamically or is an unused declaration residue.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_AUDIO]` (INFORMATIONAL) **Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_AUDIO** [PARTIAL] (Confidence: medium)
  - Description: Permission 'android.permission.READ_MEDIA_AUDIO' is declared in AndroidManifest.xml, but no matching framework API calls or components were observed statically.
  - Evidence: manifest:permission:android.permission.READ_MEDIA_AUDIO
  - Remediation Relevance: Informational; verify if this permission is needed dynamically or is an unused declaration residue.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_IMAGES]` (INFORMATIONAL) **Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_IMAGES** [PARTIAL] (Confidence: medium)
  - Description: Permission 'android.permission.READ_MEDIA_IMAGES' is declared in AndroidManifest.xml, but no matching framework API calls or components were observed statically.
  - Evidence: manifest:permission:android.permission.READ_MEDIA_IMAGES
  - Remediation Relevance: Informational; verify if this permission is needed dynamically or is an unused declaration residue.
- `[PRIV-PERM-UNCORRELATED-READ_MEDIA_VIDEO]` (INFORMATIONAL) **Declared Permission Without Static Code Reference: android.permission.READ_MEDIA_VIDEO** [PARTIAL] (Confidence: medium)
  - Description: Permission 'android.permission.READ_MEDIA_VIDEO' is declared in AndroidManifest.xml, but no matching framework API calls or components were observed statically.
  - Evidence: manifest:permission:android.permission.READ_MEDIA_VIDEO
  - Remediation Relevance: Informational; verify if this permission is needed dynamically or is an unused declaration residue.
- `[PRIV-REC-BOOT]` (INFORMATIONAL) **Boot & Package Replacement Receivers** [OBSERVED] (Confidence: confirmed)
  - Description: Manifest declarations for broadcast receivers listening to device boot or package replacement events.
  - Evidence: receiver:androidx.work.impl.background.systemalarm.RescheduleReceiver:action:android.intent.action.BOOT_COMPLETED, receiver:eu.siacs.conversations.receiver.SystemEventReceiver:action:android.intent.action.BOOT_COMPLETED
  - Remediation Relevance: Review background startup persistence at device boot.
- `[PRIV-API-DEVICE-IDENTIFIER]` (LOW) **Hardware & Device Identifier Access** [OBSERVED] (Confidence: confirmed)
  - Description: Static references to persistent device identifiers (IMEI, MEID, SIM serial, or ANDROID_ID) detected.
  - Evidence: api:android.telephony.TelephonyManager, string:android_id
  - Remediation Relevance: Assess compliance with modern Android platform privacy guidelines (prefer resettable advertising IDs or app-scoped UUIDs over hardware identifiers).
- `[PRIV-API-DYNAMIC-CODE]` (LOW) **Dynamic Code Loading Facilities** [OBSERVED] (Confidence: high)
  - Description: Static references to DexClassLoader, PathClassLoader, or InMemoryDexClassLoader detected.
  - Evidence: method:loadClass
  - Remediation Relevance: Dynamic loading allows runtime code execution bypassing static inspection; verify source and integrity.
- `[PRIV-CAP-CLIPBOARD]` (LOW) **Clipboard Access Capability Detected** [OBSERVED] (Confidence: medium)
  - Description: Application references android.content.ClipboardManager API.
  - Evidence: dex:android.content.ClipboardManager
  - Remediation Relevance: Verify clipboard reads access user data only upon direct user paste interaction.
- `[PRIV-CAP-LOCATION]` (MEDIUM) **Location Capability Detected** [OBSERVED] (Confidence: high)
  - Description: Application declares location permissions (android.permission.ACCESS_COARSE_LOCATION, android.permission.ACCESS_FINE_LOCATION) and references location APIs (eu.siacs.conversations.entities.Message$StorageLocation;->toString()Ljava.lang.String, android.widget.PopupWindow;->showAtLocation(Landroid.view.View, eu.siacs.conversations.persistance.FileBackend;->getSharedStorageLocation(Ljava.lang.String).
  - Evidence: permission:android.permission.ACCESS_COARSE_LOCATION, permission:android.permission.ACCESS_FINE_LOCATION
  - Remediation Relevance: Ensure location access is transparent and justified by application features.

## Section G: Unknown / Partial Analysis
- Partial Findings Count: 5
- Unknown Findings Count: 0
- Inconclusive Items Count: 5
  - Permission declared without API references: android.permission.READ_CONTACTS
  - Permission declared without API references: android.permission.READ_MEDIA_AUDIO
  - Permission declared without API references: android.permission.READ_MEDIA_IMAGES
  - Permission declared without API references: android.permission.READ_MEDIA_VIDEO
  - 146 endpoints cannot be reliably classified statically

## Section H: Evidence Limitations
- Static analysis cannot establish actual runtime data collection, transmission, or dynamic execution.
