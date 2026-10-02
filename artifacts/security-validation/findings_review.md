# Phase B Close-Out — Security Findings Hand Review

Evidence artifacts (every number on this page comes from these files):

| artifact | contents |
|---|---|
| `artifacts/security-validation/findings_review.json` | structured per-finding review (verdicts, cited evidence, independent verification) |
| `artifacts/security-validation/raw_pcapdroid_security.json` | raw `apkforge security --json` output for com.emanuelef.remote_capture |
| `artifacts/security-validation/raw_openlink_security.json` | raw `apkforge security --json` output for de.audioattack.openlink |
| `artifacts/security-validation/raw_appmanager_security.json` | raw `apkforge security --json` output for io.github.muntashirakon.AppManager |
| `artifacts/security-validation/build_review.py` | script that builds the JSON; recomputes all counts and fails if any finding lacks a verdict |

## Method

Every finding's cited evidence was re-derived from the APK itself and compared against what the detector reported. Verification used: `unzip -l` / extraction of the APK, ManifestInspector output, DEXInspector api_references / strings / class inventory, and the SecurityEvidenceIndex the rule engine actually evaluates. A finding is TRUE_POSITIVE only where the cited evidence was independently reproduced AND supports the claim the finding makes; FALSE_POSITIVE where the artifact exists but does not support the claim (or the matched artifact is not what was cited); UNCLEAR where the evidence is partly unsubstantiated.

**Scope note:** No rule severity, confidence, scoring, or detection threshold was changed by this review. Proposed changes are recorded in proposed_rule_changes and were NOT implemented.

## Per-app counts and false-positive rates

| app | package | findings | TRUE_POSITIVE | FALSE_POSITIVE | UNCLEAR | FP rate |
|---|---|---|---|---|---|---|
| pcapdroid | `com.emanuelef.remote_capture` | 9 | 6 | 2 | 1 | 22.2% |
| openlink | `de.audioattack.openlink` | 5 | 5 | 0 | 0 | 0.0% |
| appmanager | `io.github.muntashirakon.AppManager` | 45 | 24 | 20 | 1 | 44.4% |
| **total** | — | **59** | **35** | **22** | **2** | **37.3%** |

Severity breakdown of the false positives:

| app | severity | count |
|---|---|---|
| pcapdroid | medium | 2 |
| appmanager | high | 16 |
| appmanager | low | 3 |
| appmanager | medium | 1 |

## Dominant false-positive causes

1. **Bundled third-party library strings attributed to the application.** AppManager bundles 6,139
   `org.bouncycastle.*` classes. A general-purpose crypto provider necessarily names every algorithm
   it implements, so `DES/CBC/PKCS5Padding`, `DESede`, `Blowfish`, `SHA1` and the PEM armor header
   `-----BEGIN RSA PRIVATE KEY-----` all appear as strings without the application ever selecting a
   weak cipher or embedding a key. This single cause accounts for 5 of AppManager's 20 false positives,
   including both HIGH-severity ones. (`PRC-07`, `PRC-08`)
2. **Code-free archives classified as executable payloads.** AppManager's 14
   `frameworks/android/android-NN.apk` entries were extracted and contain only `resources.arsc` +
   `AndroidManifest.xml` — no DEX, no native code — so they cannot be payloads. 14 of 20 AppManager
   false positives. (`PRC-05`, `PRC-06`)
3. **Substring matching across similar API names.** `android.accessibilityservice.AccessibilityService`
   matches `...AccessibilityServiceInfo`, the read-only class used to *enumerate* accessibility
   services. PCAPdroid declares no accessibility service at all yet was flagged twice. (`PRC-01`)
4. **XML namespace / parser-feature URIs treated as network endpoints.** AppManager's cleartext-URL
   finding cites only `http://xmlpull.org/...`, `http://apache.org/xml/features/...` and
   `http://xml.org/sax/features/...`. (`PRC-03`)

## Precision defects found in otherwise-correct findings

These did not change a verdict to FALSE_POSITIVE but make evidence non-traceable:

- Evidence cites the rule's **probe pattern** rather than the artifact that matched. PCAPdroid's
  device-identifier finding cites `Build.SERIAL`, but no such string exists in the APK (only the bare
  token `SERIAL`); that is why that finding is UNCLEAR rather than TRUE_POSITIVE. (`PRC-02`)
- `getDeviceIdleController` is listed as a "telephony hardware identifier" — it is the doze/power
  service, matched only via the `getDeviceId` substring. (`PRC-11`)
- Package names whose last segment collides with a TLD are extracted as domains
  (`androidx.core.app`, `io.github.muntashirakon.io`). (`PRC-10`)
- Five rule pairs report one underlying fact twice. (`PRC-04`)

## AppManager vulnerability-finding traceability

Item 1 required every AppManager finding to be traced to exact APK evidence. All 45 were; the
`independent_verification` field of each entry in `findings_review.json` records the artifact and the
observed value. Summary of what each evidence class resolved to:

| evidence class | traced to | outcome |
|---|---|---|
| embedded APKs (14) | `unzip -l` entries + extraction of `android-23.apk` → `resources.arsc` (546652 B) + `AndroidManifest.xml` (1396 B) only | FALSE_POSITIVE as payload |
| high-entropy assets (7) | `unzip -l` sizes match cited sizes exactly; `am.jar`/`main.jar` contain real `classes.dex` | TRUE_POSITIVE |
| ProcessBuilder / PathClassLoader | `DEXInspector` api_references | TRUE_POSITIVE |
| accessibility + overlay | manifest service `NoRootAccessibilityService` (BIND_ACCESSIBILITY_SERVICE, exported=False) + `SYSTEM_ALERT_WINDOW` | TRUE_POSITIVE |
| device identifiers | `TelephonyManager;->getImei()`, `->getDeviceId()`, `IPhoneSubInfo;->getSubscriberIdForSubscriber` | TRUE_POSITIVE (1 mis-grouped item) |
| crypto strings + PEM header | bundled `org.bouncycastle.crypto.engines.DESEngine` / `DESedeEngine` / … | FALSE_POSITIVE |
| exported receivers (4) | all four are AppWidgetProviders | TRUE_POSITIVE (benign by design) |
| root indicators | 8 app-owned `…AppManager.magisk.*` classes | TRUE_POSITIVE |
| allowBackup | `application.allow_backup == True` | TRUE_POSITIVE |
| cleartext URLs | XML parser feature URIs only | FALSE_POSITIVE |

No finding was traced to evidence that does not exist in the APK. In every FALSE_POSITIVE case the
cited artifact **is** present — the defect is the inference drawn from it, not a fabricated citation.
The two exceptions are the probe-pattern citations noted above, where the cited string itself is not
the matched artifact.

## Proposed rule changes (recorded, NOT implemented)

### PRC-01 — Accessibility-service detection must require an implemented service, not a substring match

- **Problem:** `android.accessibilityservice.AccessibilityService` is matched as a substring, so it also matches `android.accessibilityservice.AccessibilityServiceInfo` -- the read-only metadata class used to *enumerate* accessibility services installed on the device. An app that merely lists other apps' accessibility services is flagged as implementing one.
- **Proposal:** Require either (a) a manifest <service> bound with BIND_ACCESSIBILITY_SERVICE, or (b) an exact class reference to android.accessibilityservice.AccessibilityService, before firing.
- **Affects:** `SEC-SPY-ACCESSIBILITY-001`, `SEC-SPY-ACCESSIBILITY-ABUSE`

### PRC-02 — Evidence should cite the matched artifact, not the rule's probe pattern

- **Problem:** Several findings print the rule's configured probe string as the evidence snippet rather than the artifact that actually matched. Example: PCAPdroid's device-identifier finding cites `Build.SERIAL`, but the only matching string in the APK is the bare token `SERIAL`; AppManager's accessibility finding cites `...AccessibilityService` while the matched artifact is `...AccessibilityServiceInfo`. This makes evidence non-traceable to the APK.
- **Proposal:** Record the matched artifact value (and its source: api/string/method/manifest) in Evidence.snippet.
- **Affects:** `SEC-SPY-DEVICE-IDENTIFIERS`, `SEC-SPY-ACCESSIBILITY-001`

### PRC-03 — Cleartext-URL detection must exclude XML namespace and parser-feature URIs

- **Problem:** `http://xmlpull.org/v1/doc/features.html#...`, `http://apache.org/xml/features/...`, `http://xml.org/sax/features/...`, `http://schemas.android.com/apk/res/android` and XMPP protocol namespaces are API constant identifiers that are never dereferenced over the network. For AppManager, every cited 'cleartext URL' is of this kind.
- **Proposal:** Maintain an allowlist of well-known namespace/feature URI hosts and exclude them, or require the URL to co-occur with an HTTP client API reference.
- **Affects:** `SEC-NET-CLEARTEXT-URLS`

### PRC-04 — Deduplicate overlapping rule pairs that report the same underlying fact

- **Problem:** Pairs of rules fire on one fact: SEC-VULN-BACKUP-001 + SEC-VULN-MANIFEST-BACKUP (allowBackup), SEC-MAL-CODE-EXEC + SEC-MAL-EXEC-001 (ProcessBuilder), SEC-MAL-DYN-LOAD + SEC-MAL-DYNLOAD-001 (PathClassLoader), SEC-VULN-CRYPTO-WEAK-CIPHER + SEC-VULN-WEAK-CIPHER-001, SEC-VULN-CRYPTO-WEAK-HASH + SEC-VULN-WEAK-HASH-001. This inflates finding counts.
- **Proposal:** Merge each pair, or mark one of each pair as a sub-finding of the other.
- **Affects:** `SEC-VULN-BACKUP-001`, `SEC-VULN-MANIFEST-BACKUP`, `SEC-MAL-CODE-EXEC`, `SEC-MAL-EXEC-001`, `SEC-MAL-DYN-LOAD`, `SEC-MAL-DYNLOAD-001`, `SEC-VULN-CRYPTO-WEAK-CIPHER`, `SEC-VULN-WEAK-CIPHER-001`, `SEC-VULN-CRYPTO-WEAK-HASH`, `SEC-VULN-WEAK-HASH-001`

### PRC-05 — Nested-APK payload detection must check whether the nested APK contains code

- **Problem:** AppManager's 14 `frameworks/android/android-NN.apk` entries are flagged HIGH severity as `payload`. Each one was extracted and verified to contain only resources.arsc + AndroidManifest.xml -- zero DEX, zero native code. They are Android framework resource tables used to resolve other apps' resource IDs per API level, and cannot execute.
- **Proposal:** Inspect the nested archive: only classify as `payload` when it contains classes*.dex or a native library; otherwise report as an informational embedded-resource observation.
- **Affects:** `SEC-MAL-PAYLOAD-APK-*`

### PRC-06 — Aggregate per-file findings instead of emitting one finding per file

- **Problem:** 14 separate HIGH findings (one per embedded framework APK) and 7 separate entropy findings dominate AppManager's result set: 21 of 45 findings describe two phenomena.
- **Proposal:** Emit one finding per phenomenon with the file list as evidence items.
- **Affects:** `SEC-MAL-PAYLOAD-APK-*`, `SEC-MAL-PAYLOAD-ENTROPY-*`

### PRC-07 — Hardcoded-secret detection must require key material, not just PEM armor

- **Problem:** `-----BEGIN RSA PRIVATE KEY-----` is present in AppManager, but it is the PEM parser constant shipped inside the bundled BouncyCastle provider (6,139 org.bouncycastle.* classes verified). No key body accompanies it.
- **Proposal:** Require a base64 key body following the armor header before reporting a secret.
- **Affects:** `SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER`

### PRC-08 — Crypto-weakness findings must attribute the algorithm string to its owning package

- **Problem:** `DES/CBC/PKCS5Padding`, `DESede`, `Blowfish`, `SHA1`/`SHA-1` in AppManager all originate from the bundled BouncyCastle provider's algorithm registry (org.bouncycastle.crypto.engines.DESEngine / DESedeEngine / DESedeWrapEngine verified present). A general-purpose crypto provider necessarily names every algorithm it supports; this is not evidence that the application selects a weak cipher. SHA-1 additionally appears legitimately for v1 JAR signature verification, which AppManager performs.
- **Proposal:** Attribute the matched string to the declaring class/package and suppress (or downgrade to informational) when it belongs to a known crypto provider rather than application code.
- **Affects:** `SEC-VULN-WEAK-CIPHER-001`, `SEC-VULN-CRYPTO-WEAK-CIPHER`, `SEC-VULN-CRYPTO-WEAK-HASH`, `SEC-VULN-WEAK-HASH-001`

### PRC-09 — Entropy findings should account for inherently-compressed file formats

- **Problem:** assets/blanks/blank.{odp,odt,pdf,pptx} and assets/dexopt/baseline.prof are flagged as high-entropy `payload`. ODF/OOXML are ZIP containers and PDF/baseline profiles are compressed, so high entropy is expected and carries no signal.
- **Proposal:** Treat known-compressed extensions as informational unless paired with a loader reference.
- **Affects:** `SEC-MAL-PAYLOAD-ENTROPY-*`

### PRC-10 — Domain extraction must reject package-name-shaped tokens and namespace hosts

- **Problem:** AppManager's SEC-NET-CAPABILITY-FLOW cites `androidx.core.app` and `io.github.muntashirakon.io` as 'external domain endpoints'. These are Java package names whose final segment collides with a real TLD (.app, .io). `schemas.android.com` is an XML namespace host, not a contacted endpoint.
- **Proposal:** Exclude tokens that match a declared application/library package prefix, and namespace hosts, from the domain set used by network-flow rules.
- **Affects:** `SEC-NET-CAPABILITY-FLOW`

### PRC-11 — Device-identifier pattern list contains a non-identifier entry

- **Problem:** AppManager's SEC-SPY-DEVICE-IDENTIFIERS cites `getDeviceIdleController` as a 'telephony hardware identifier method reference'. DeviceIdleController is the doze/power-management service and is unrelated to device identity; it matches only because of the `getDeviceId` substring.
- **Proposal:** Anchor identifier patterns (word boundary / exact method name) to exclude getDeviceIdleController.
- **Affects:** `SEC-SPY-DEVICE-IDENTIFIERS`

### PRC-12 — Exported-receiver finding should note the AppWidgetProvider exemption as context

- **Problem:** AppManager's 4 exported unprotected receivers were all verified to be app-widget providers (ClearCacheAppWidget, RecordingWidgetProvider, DataUsageAppWidget, ScreenTimeAppWidget). An AppWidgetProvider must be exported to receive launcher broadcasts.
- **Proposal:** Keep the finding (the exposure is real) but add context when the receiver's intent filter is APPWIDGET_UPDATE, rather than suppressing it.
- **Affects:** `SEC-VULN-EXPORTED-RECEIVER`

## Rules recommended to remain unchanged

26 distinct rule IDs are recommended to remain exactly as they are:

`SEC-COMB-ACCESSIBILITY-OVERLAY`, `SEC-MAL-CODE-EXEC`, `SEC-MAL-DYN-LOAD`, `SEC-MAL-DYNLOAD-001`, `SEC-MAL-EXEC-001`, `SEC-MAL-PERSISTENCE-BOOT`, `SEC-MAL-PERSISTENCE-FG-SERVICE`, `SEC-MAL-ROOT-INDICATORS`, `SEC-NET-CAPABILITY-FLOW`, `SEC-NET-CLEARTEXT-URLS`, `SEC-SPY-ACCESSIBILITY-001`, `SEC-SPY-ACCESSIBILITY-ABUSE`, `SEC-SPY-CALLS-001`, `SEC-SPY-CLIPBOARD-001`, `SEC-SPY-DEVICE-IDENTIFIERS`, `SEC-SPY-OVERLAY-001`, `SEC-VULN-BACKUP-001`, `SEC-VULN-EXPORTED-RECEIVER`, `SEC-VULN-MANIFEST-BACKUP`, plus the 7 `SEC-MAL-PAYLOAD-ENTROPY-*` instances.

22 distinct rule IDs have a recorded proposed change (none applied in this task):

`SEC-NET-CLEARTEXT-URLS`, `SEC-SPY-ACCESSIBILITY-001`, `SEC-SPY-ACCESSIBILITY-ABUSE`, `SEC-VULN-CRYPTO-WEAK-CIPHER`, `SEC-VULN-CRYPTO-WEAK-HASH`, `SEC-VULN-SECRET-GENERIC_PRIVATE_KEY_HEADER`, `SEC-VULN-WEAK-CIPHER-001`, `SEC-VULN-WEAK-HASH-001`, plus the 14 `SEC-MAL-PAYLOAD-APK-*` instances.

## Verdict

**PASS** for the review task itself: all 59 findings across the three APKs were hand-reviewed with
independent verification, and no detector was found to fabricate evidence. The 37.3% overall
false-positive rate is a *rule-precision* problem concentrated in AppManager (44.4%), driven almost
entirely by two causes (bundled-library string attribution and code-free archive classification) that
are recorded as `PRC-05`/`PRC-07`/`PRC-08` for a future task, per the instruction not to change rule
behaviour here.
