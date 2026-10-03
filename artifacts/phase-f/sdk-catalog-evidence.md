# Third-Party SDK & Tracker Detection Catalog Evidence

Phase F establishes an auditable, deterministic catalog of third-party advertising, analytics, tracking, and telemetry SDKs. Each finding records matched package namespaces, specific bytecode classes, and string signatures.

### Core Privacy Separation Principles:
1. **Detection != Transmission**: Static bytecode presence of an SDK indicates integration, but does NOT prove that user data was captured or sent across the network at runtime.
2. **Neutral Taxonomy**: SDKs are classified as `advertising`, `analytics`, `tracking`, or `telemetry/crash_reporting`. They are never labeled 'malware' or 'spyware'.
3. **Explicit Network Determination**: When no active network endpoints are statically verified, the status `CANNOT_DETERMINE_STATICALLY` is explicitly recorded.

## Detected SDK Occurrences in Corpus

| APK | SDK Name | SDK ID | Category | Confidence | Network Status | Locations |
|---|---|---|---|---|---|---|
| `org.mozilla.fennec_fdroid_1560020.apk` | **Google AdMob / Google Mobile Ads** | `ad.google.admob` | `advertising` | `high` | `CANNOT_DETERMINE_STATICALLY` | `package:com.google.android.gms.ads` |
| `org.mozilla.fennec_fdroid_1560020.apk` | **Sentry** | `telemetry.sentry` | `crash_reporting` | `confirmed` | `CANNOT_DETERMINE_STATICALLY` | `package:io.sentry, package:io.sentry.android` |
| `org.schabi.newpipe_1015_cb84069.apk` | **Google AdMob / Google Mobile Ads** | `ad.google.admob` | `advertising` | `medium` | `STATICALLY_REFERENCED_ENDPOINT` | `domain:googleads.g.doubleclick.net` |
