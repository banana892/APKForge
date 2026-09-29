# APKForge Privacy & Tracker Engine (Phase 4)

The APKForge Privacy & Tracker Engine answers the question:

> **What data-related capabilities does this APK declare or appear to contain, which third-party tracking/analytics/advertising technologies are present, and what network endpoints are associated with them?**

The Privacy Engine produces **evidence-based technical analysis**, not arbitrary or opaque privacy scores (e.g. `37/100`). It operates purely on **structured, static technical evidence** collected during Phase 1 intake and Phase 2 inspection without independently reparsing the APK per detector.

In accordance with APKForge security invariants, the Privacy Engine does **not** execute application code, does **not** make dynamic network connections or query external APIs, does **not** perform APK modification/rebuilding, and does **not** emit subjective malware verdicts.

---

## 1. Privacy Architecture

The privacy subsystem is located in `src/apkforge/privacy/`:

```text
src/apkforge/privacy/
├── __init__.py          # Package exports
├── models.py            # Pydantic v2 domain models (PrivacyResult, Findings, SDKs, Endpoints)
├── engine.py            # PrivacyEngine orchestrator & EvidenceIndex builder
├── permissions.py       # PermissionAnalyzer (taxonomy, protection levels, API correlation)
├── trackers.py          # TrackerDetector (tracking & attribution SDKs)
├── advertising.py       # AdvertisingDetector (ad networks & ad mediation SDKs)
├── analytics.py         # AnalyticsDetector (event tracking & user analytics)
├── telemetry.py         # TelemetryDetector (crash reporting & performance telemetry)
├── endpoints.py         # EndpointAnalyzer (domain/URL classification, first-party vs third-party, provenance)
├── data_collection.py   # DataCollectionAnalyzer (device IDs, AAID, clipboard, accessibility, background correlation)
├── rules.py             # PrivacyRule, EvidenceIndex, and rule evaluation engine
└── rules_data/          # Declarative rule definitions (YAML/JSON)
    ├── advertising.yaml # AdMob, AppLovin, Unity Ads, Facebook Audience Network, InMobi, ironSource, Vungle
    ├── analytics.yaml   # Firebase Analytics, Flurry, Mixpanel, Amplitude, Segment, CleverTap
    ├── attribution.yaml # AppsFlyer, Adjust, Branch Metrics, Kochava, Singular
    ├── telemetry.yaml   # Sentry, Crashlytics, Bugsnag, Microsoft App Center
    ├── trackers.yaml    # Criteo, mParticle, OneSignal
    └── endpoints.yaml   # Static CDNs (Google, Cloudflare, CloudFront)
```

### Orchestration Pipeline

```text
APK / InspectionResult
          │
          ▼
   Single-Pass Pre-Indexing
   (EvidenceIndex: classes, prefixes, methods, strings, APIs, domains, URLs, permissions)
          │
          ├──────────────────────────┬──────────────────────────┐
          ▼                          ▼                          ▼
   PermissionAnalyzer         RuleEngine                DataCollectionAnalyzer
          │                          │                          │
          ├─ Categorization          ├─ TrackerDetector         ├─ Device Identifiers
          ├─ Protection Levels       ├─ AdvertisingDetector     ├─ Advertising ID (AAID)
          ├─ API Correlation         ├─ AnalyticsDetector       ├─ Clipboard Access
          └─ Usage Statuses          ├─ TelemetryDetector       ├─ Accessibility Services
                                     │                          └─ Background Services
                                     ▼
                              EndpointAnalyzer
                                     │
                                     ├─ First-Party Domain Discovery
                                     ├─ Third-Party Classification
                                     ├─ SDK-to-Endpoint Mapping
                                     └─ Provenance Preservation
                                     │
                                     ▼
                              Finding Synthesis
                                     │
                                     ▼
                               PrivacyResult
```

---

## 2. Permission Taxonomy & Classification

The permission analyzer classifies Android permissions into a structured taxonomy of privacy-relevant data and device capability categories.

### Supported Permission Categories

| Category | Description | Representative Permissions |
|---|---|---|
| `location` | Fine, coarse, or background physical location | `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION` |
| `contacts` | Address book and contact data | `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS` |
| `phone` | Phone state, call logs, and telephony | `READ_PHONE_STATE`, `CALL_PHONE`, `READ_CALL_LOG` |
| `sms` | SMS/MMS reading, writing, and transmission | `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS` |
| `calendar` | Calendar events and appointment data | `READ_CALENDAR`, `WRITE_CALENDAR` |
| `microphone` | Audio recording and speech recognition | `RECORD_AUDIO` |
| `camera` | Video recording and camera capture | `CAMERA` |
| `storage` | External storage and shared media access | `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` |
| `bluetooth` | Bluetooth discovery, connection, and beacons | `BLUETOOTH`, `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN` |
| `nearby_devices` | UWB, Wi-Fi Direct, and nearby awareness | `NEARBY_WIFI_DEVICES`, `UWB_RANGING` |
| `network` | Internet connectivity and network state | `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` |
| `notifications` | Notification posting and listeners | `POST_NOTIFICATIONS`, `BIND_NOTIFICATION_LISTENER_SERVICE` |
| `identifiers` | Advertising IDs and installation tokens | `com.google.android.gms.permission.AD_ID` |
| `sensors` | Body sensors and biometric hardware | `BODY_SENSORS`, `USE_BIOMETRIC`, `ACTIVITY_RECOGNITION` |
| `other` | System, development, or unclassified permissions | `WAKE_LOCK`, `VIBRATE`, custom vendor permissions |

### Permission-to-Code Correlation

Rather than simply listing manifest declarations, the analyzer correlates declared permissions with framework API references and class namespaces extracted during Phase 2 DEX inspection:

```text
Declared Permission: android.permission.ACCESS_FINE_LOCATION
      ├── Target API: android.location.LocationManager
      ├── Target API: com.google.android.gms.location.FusedLocationProviderClient
      └── Correlated Classes: com.example.app.LocationService, com.example.app.MapActivity
```

### Permission Usage Status

Permissions are evaluated and classified into verified evidence statuses:

| Status | Meaning |
|---|---|
| `DECLARED_ONLY` | Declared in the manifest, but no known related framework APIs or classes were found in bytecode. |
| `DECLARED_AND_REFERENCED` | Declared in the manifest, and related framework APIs are referenced in DEX code. |
| `DECLARED_WITH_STRONG_CODE_CORRELATION` | Declared, APIs referenced, and application-specific classes match the capability domain. |
| `UNKNOWN` | Custom or non-standard permission whose correlation cannot be determined statically. |

> **Analysis Limitation:** Static analysis can verify that APIs are referenced in bytecode, but cannot prove that the capability is actually exercised during normal execution or dynamic runtime conditions.

---

## 3. SDK & Tracker Detection Engine

APKForge uses a declarative rule-based detection engine rather than hardcoded logic scattered across Python files.

### SDK Categories

* **`ADVERTISING`**: Ad delivery, mediation, and interstitial networks (e.g. AdMob, AppLovin, Unity Ads, InMobi).
* **`ANALYTICS`**: User behavior tracking, event logging, and product analytics (e.g. Firebase Analytics, Amplitude, Mixpanel).
* **`TRACKING`**: Cross-app tracking, retargeting, and user graph tracking (e.g. Criteo, mParticle).
* **`ATTRIBUTION`**: Install tracking, referral attribution, and deep linking (e.g. AppsFlyer, Adjust, Branch).
* **`TELEMETRY`**: Diagnostic reporting, crash collection, and performance monitoring (e.g. Sentry, Crashlytics, Bugsnag).

### Rule Schema

Rules are defined in YAML or JSON files:

```yaml
id: ad.google.admob
name: Google AdMob
vendor: Google LLC
category: advertising
description: Google mobile advertising SDK and mediation platform.

packages:
  - com.google.android.gms.ads
  - com.google.ads.mediation

classes:
  - com.google.android.gms.ads.AdView
  - com.google.android.gms.ads.MobileAds
  - com.google.android.gms.ads.interstitial.InterstitialAd

strings:
  - "googleads.g.doubleclick.net"
  - "admob"

domains:
  - googleads.g.doubleclick.net
  - pagead2.googlesyndication.com

confidence:
  package_match: high
  class_match: high
  string_match: low
```

### Multi-Evidence Matching & Precedence

When multiple signatures match for a given SDK (e.g. package namespace + class signature + domain), the engine consolidates them into **a single `DetectedSDK` record** with multiple evidence items, preventing duplicate findings.

### Version Extraction

Where available, the engine detects SDK versions from:
* Class constants and version fields
* Embedded metadata in DEX string pools
* Manifest `<meta-data>` values

If the version cannot be verified, it is reported as `unknown`.

---

## 4. False-Positive Prevention Strategy

Static string matches in large compiled applications can trigger false positives if generic terms are matched naively. APKForge enforces strict false-positive controls:

1. **Generic Blocklist:** Words like `analytics`, `tracker`, `tracking`, `location`, `advertising`, `ad`, `telemetry`, `event`, and `service` are blocked from matching on strings alone.
2. **String Length & Uniqueness Guard:** If a rule match consists only of string signatures with no matching packages, classes, or endpoints, the match is accepted only if the string is $\ge 12$ characters and not in the blocklist.
3. **Conservative Confidence Scaling:**
   * Package prefix match $\implies$ **HIGH** confidence.
   * Specific class signature match $\implies$ **HIGH** confidence.
   * String match alone $\implies$ **LOW** confidence.
   * Multiple corroborating evidence types $\implies$ **CONFIRMED** confidence.

---

## 5. Network Endpoint Classification & Provenance

The endpoint analyzer processes URLs and domains extracted by Phase 2 network inspection:

```text
Domain / URL
     │
     ├── First-Party Domain Discovery (e.g. api.company.com derived from com.company.app)
     │
     ├── Third-Party Classification (via rule database & endpoint patterns)
     │   └── Categories: FIRST_PARTY, ADVERTISING, ANALYTICS, TRACKING,
     │                  TELEMETRY, ATTRIBUTION, CDN, UNKNOWN
     │
     ├── SDK-to-Endpoint Mapping (correlate endpoints with detected SDKs)
     │
     └── Provenance Tracking (classes.dex -> ClassName -> MethodName)
```

### Preserved Provenance

Every classified endpoint preserves its origin:
* Source archive: `classes.dex`, `AndroidManifest.xml`, or resources
* Enclosing class: `com.example.app.NetworkClient`
* Calling method: `sendTrackingEvent()`

---

## 6. Data Capability Assessments

The engine identifies data collection capabilities and potential data flows by correlating manifest declarations, framework APIs, third-party SDKs, and network endpoints:

* **Location:** Permissions (`ACCESS_FINE_LOCATION`) + Framework APIs (`LocationManager`) + Background services.
* **Microphone:** Audio recording permissions (`RECORD_AUDIO`) + Audio APIs (`AudioRecord`, `MediaRecorder`).
* **Camera:** Camera permissions (`CAMERA`) + Camera APIs (`CameraManager`).
* **Contacts:** Address book permissions (`READ_CONTACTS`) + Content provider APIs (`ContactsContract`).
* **Device Identifiers:** Telephony and hardware ID APIs (`getDeviceId`, `getImei`, `Build.SERIAL`, `ANDROID_ID`).
* **Advertising ID (AAID):** Google Play Services `AdvertisingIdClient` references.
* **Clipboard Access:** `ClipboardManager` API references.
* **Accessibility Services:** `AccessibilityService` component declarations and bindings.

Each capability is recorded with a clear limitation statement emphasizing that static references do not prove runtime collection or data exfiltration.

---

## 7. CLI Usage

### Basic Privacy Analysis

```bash
apkforge privacy target.apk
```

### Verbose Mode with Specific Categories

```bash
# Filter specific sections
apkforge privacy target.apk --permissions --trackers

# Show full details across all categories
apkforge privacy target.apk --verbose
```

### Machine-Readable JSON Output

```bash
apkforge privacy target.apk --json > privacy_report.json
```

---

## 8. Determinism and Error Isolation

* **Determinism:** All dictionaries, sets, permissions, SDKs, endpoints, and findings are sorted before serialization. Analysis of identical inputs produces identical results.
* **Error Isolation:** Detectors run in isolated execution blocks (`_safe_run`). A failure in one detector (e.g. endpoint classification) does not abort the entire pipeline. The result status degrades to `PARTIAL`, recording the failure reason in `limitations`.
