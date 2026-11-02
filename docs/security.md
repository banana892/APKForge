# APKForge Security Analysis Engine (Phase 5)

The APKForge Security Analysis Engine answers critical technical questions:

> **What security-sensitive capabilities exist in the APK, which suspicious combinations of capabilities exist, are there indicators consistent with malware or spyware behavior, what vulnerabilities or dangerous configurations are present, and did modifications introduce security regressions?**

The fundamental principle governing APKForge security analysis is:

> **APKForge provides local technical evidence and analysis. It must not pretend that static analysis alone can prove that an APK is malware, spyware, or safe.**

Every significant security finding rigorously distinguishes:
- **Evidence**: Concrete, traceable locations in manifest, DEX bytecode, strings, or archive files.
- **Severity**: Potential security impact if capability is exploited or malicious.
- **Confidence**: Strength of the static evidence supporting the finding.
- **Assessment**: Technical evaluation explaining the observed capability.
- **Limitations**: Explicit boundaries of static analysis (e.g. no proof of runtime execution).

In accordance with strict safety invariants, APKForge does **not** execute application code, does **not** launch Android components, does **not** connect to external endpoints or URLs, does **not** query external dynamic sandboxes, and does **not** emit arbitrary single-score malware probabilities.

---

## 1. Security Architecture

The security subsystem is located in `src/apkforge/security/`:

```text
src/apkforge/security/
├── __init__.py              # Public exports (SecurityEngine, models, rules)
├── models.py                # SecurityResult, SecurityFinding, SecuritySummary, FullAnalysisResult
├── engine.py                # SecurityEngine orchestrator, index builder, error isolation
├── rules.py                 # Declarative SecurityRule, SecurityCondition, RuleEngine, EvidenceIndex
├── diff_analyzer.py         # DiffSecurityAnalyzer (diff regression and modification findings)
│
├── malware/                 # Malware Indicator Analyzers
│   ├── __init__.py          # MalwareAnalyzer coordinator
│   ├── payloads.py          # PayloadAnalyzer (embedded DEX, ELF, APK, high-entropy assets)
│   ├── suspicious_code.py   # SuspiciousCodeAnalyzer (Runtime.exec, DexClassLoader, root checks)
│   ├── persistence.py       # PersistenceAnalyzer (BOOT_COMPLETED, services, alarms)
│   └── network.py           # NetworkSecurityAnalyzer (raw IPs, sensitive data exfil correlation)
│
├── spyware/                 # Spyware & Surveillance Indicator Analyzers
│   ├── __init__.py          # SpywareAnalyzer coordinator
│   ├── surveillance.py      # SurveillanceAnalyzer (audio, camera, location, surveillance suites)
│   └── collection.py        # CollectionAnalyzer (SMS OTP, contacts, hardware IDs, accessibility)
│
├── vulnerabilities/         # Vulnerability & Configuration Analyzers
│   ├── __init__.py          # VulnerabilityAnalyzer coordinator
│   ├── manifest.py          # ManifestVulnerabilityAnalyzer (debuggable, cleartext, allowBackup)
│   ├── components.py        # ComponentVulnerabilityAnalyzer (exported providers, services, receivers)
│   └── crypto.py            # CryptoVulnerabilityAnalyzer (ECB, DES, MD5, masked secret tokens)
│
└── rules_data/              # Built-in Declarative Rules (YAML)
    ├── spyware.yaml         # SEC-SPY-CALLS-001, -CONTACTS-001, -CLIPBOARD-001, -OVERLAY-001
    ├── malware.yaml         # SEC-MAL-EMBEDDED-DEX-001, SEC-MAL-EMBEDDED-ELF-001
    └── combinations.yaml    # Rules SEC-COMB-SURVEILLANCE-SUITE through SEC-COMB-DYNLOAD-PAYLOAD

A fact is reported by one rule only. The YAML rules that repeated an analyzer's finding
(command execution, dynamic loading, boot persistence, debuggable/cleartext/allowBackup,
weak cipher/hash, audio/camera/location/SMS/accessibility surveillance) were removed in
favour of the analyzers, which attribute crypto strings to the app and grade severity by
context (PRC-04, docs/known-limitations.md §6).
```

### Analysis Pipeline

```text
       APK / Package
             │
             ▼
      Phase 1 Intake
             │
             ▼
     Phase 2 Inspection
             │
   ┌─────────┴─────────┐
   │                   │
   ▼                   ▼
Phase 3 Diff     Phase 4 Privacy
   │                   │
   └─────────┬─────────┘
             ▼
     SecurityEvidenceIndex
   (permissions, APIs, components,
    strings, domains, diffs, entropy)
             │
  ┌──────────┼──────────┬──────────┬──────────┐
  ▼          ▼          ▼          ▼          ▼
Rule      Malware    Spyware      Vuln       Diff
Engine    Analyzer   Analyzer   Analyzer   Analyzer
  │          │          │          │          │
  └──────────┴──────────┼──────────┴──────────┘
                        ▼
             Deduplication & Sorting
                        │
                        ▼
                 SecurityResult
```

---

## 2. Security Result & Finding Model

### Overall Security Status

APKForge deliberately avoids definitive claims like `SAFE` or `MALWARE`. Instead, it provides a neutral, evidence-driven status:
- `FINDINGS_PRESENT`: One or more security findings were identified.
- `NO_SIGNIFICANT_STATIC_FINDINGS`: Static analysis identified no high-confidence or high-severity indicators.
- `ANALYSIS_INCOMPLETE`: An error or parsing limitation (e.g. unparsed DEX) prevented full inspection.

### Finding Schema

Every finding conforms to `SecurityFinding`:

```python
class SecurityFinding(BaseModel):
    id: str                                  # Unique identifier (e.g. SEC-SPY-AUDIO-001)
    category: SecurityCategory               # malware_indicator, spyware_indicator, vulnerability, etc.
    title: str                               # Descriptive title
    description: str                         # Technical explanation of the finding
    severity: Severity                       # Potential security impact (CRITICAL .. INFO)
    confidence: Confidence                   # Certainty based on evidence (CONFIRMED .. UNKNOWN)
    evidence: list[Evidence]                 # Traceable evidence items with location and snippets
    assessment: str                          # Analytical assessment of capability
    limitations: list[str]                   # Explicit boundaries of static analysis
    references: list[str]                    # Standards references (e.g. CWE-215, CWE-319)
    tags: list[str]                          # Searchable categorization tags
```

---

## 3. Severity & Confidence Taxonomy

### Severity Taxonomy

Severity defines the **potential security significance** of a finding if malicious or abused:
- `CRITICAL`: High-impact vulnerability, hardcoded private keys, or confirmed malicious payload pattern.
- `HIGH`: Covert surveillance capability, remote command execution, credential access, or critical manifest exposure.
- `MEDIUM`: Suspicious API combination, legacy cryptography (DES/RC4), unprotected exported service, or high-entropy payload.
- `LOW`: Insecure configuration default (`allowBackup=true`, `testOnly=true`), deprecated hash (MD5/SHA-1), or added endpoint.
- `INFO`: Descriptive capability inventory or developmental flags.

### Confidence Taxonomy

Confidence measures **how reliably the static evidence supports the finding**:
- `CONFIRMED`: Directly verified by structural manifest attribute or binary inspection (e.g. `android:debuggable="true"`, embedded `.dex` file).
- `HIGH`: Multiple correlating independent indicators present (e.g. permission + API + background service).
- `MEDIUM`: Indicative API or string reference observed without complete execution chain proof.
- `LOW`: Heuristic or single string match in decompiled data.
- `UNKNOWN`: Unverified or third-party reported indicator.

*Note: High severity with Low confidence (e.g. possible shell invocation string) and Low severity with High confidence (e.g. `allowBackup=true` in manifest) are completely valid and decoupled.*

---

## 4. Rule Engine & Declarative Schemas

The declarative rule engine allows defining detection rules in YAML without code modifications.

### Rule Operators

The engine supports logical composition operators:
- `all`: All child conditions must be satisfied.
- `any`: At least one child condition must be satisfied.
- `none`: None of the child conditions may be satisfied.
- `min_count`: A specified threshold of conditions must match.

### Example Declarative Rule (`rules/security/spyware/audio.yaml`)

```yaml
id: SEC-SPY-AUDIO-001
title: Background Audio Recording Capability
category: spyware_indicator
severity: high
confidence: high

conditions:
  all:
    - permission: android.permission.RECORD_AUDIO
    - api_any:
        - android.media.AudioRecord
        - android.media.MediaRecorder
    - component_type: service

assessment: >
  The APK contains static indicators consistent with background audio recording capabilities.

limitations:
  - Static analysis cannot establish that audio recording occurs during normal runtime execution.
  - User consent and runtime permission prompts cannot be evaluated statically.

references:
  - CWE-359: Exposure of Private Personal Information
```

---

## 5. Analyzers & Detection Capabilities

### 1. Malware Analyzers (`src/apkforge/security/malware/`)
- **`PayloadAnalyzer`**:
  - Embedded DEX files (`classes2.dex`, assets/sub-dexes).
  - Standalone ELF binaries packaged outside standard `lib/` paths.
  - Nested APK archives bundled within assets or resources.
  - High-entropy assets ($\ge 7.2$ bits/byte) indicating encrypted/packed secondary payloads.
- **`SuspiciousCodeAnalyzer`**:
  - Command execution via `java.lang.Runtime.exec`, `java.lang.ProcessBuilder`, and `/system/bin/sh`.
  - Dynamic code loading via `dalvik.system.DexClassLoader` and `PathClassLoader`.
  - Root detection heuristics (checking `/system/bin/su`, `/system/xbin/which`).
- **`PersistenceAnalyzer`**:
  - Devices boot persistence listening for `BOOT_COMPLETED` or `LOCKED_BOOT_COMPLETED`.
  - Persistent foreground services and scheduled alarms/work managers.
- **`NetworkSecurityAnalyzer`**:
  - Hardcoded raw IPv4/IPv6 address endpoints in bytecode or assets.
  - Cleartext HTTP URLs in code references.
  - Correlation between sensitive data permissions, HTTP clients, and external network domains.

### 2. Spyware Analyzers (`src/apkforge/security/spyware/`)
- **`SurveillanceAnalyzer`**:
  - Audio recording correlated with background services and network transmission.
  - Camera capture and video recording capabilities.
  - Fine/coarse location tracking combined with background services and geofencing.
  - Multi-vector surveillance suite detection ($\ge 3$ simultaneous sensory collection channels).
- **`CollectionAnalyzer`**:
  - SMS interception, read permissions, and OTP/verification keyword monitoring.
  - Telephony and call log extraction (`READ_PHONE_STATE`, `READ_CALL_LOG`).
  - Contact book harvesting (`READ_CONTACTS`, `ContactsContract`).
  - Hardware device identifier collection (`getDeviceId`, `getImei`, `getSubscriberId`, `getMacAddress`, `ANDROID_ID`).
  - Accessibility service declaration and window content inspection capabilities.
  - System alert window / overlay capabilities (`SYSTEM_ALERT_WINDOW`).

### 3. Vulnerability Analyzers (`src/apkforge/security/vulnerabilities/`)
- **`ManifestVulnerabilityAnalyzer`**:
  - `android:debuggable="true"`: Enables arbitrary debugger attachment and memory dumping.
  - `android:usesCleartextTraffic="true"`: Allows unencrypted network communications.
  - `android:allowBackup="true"`: Allows application data extraction via ADB backup.
  - `android:testOnly="true"`: Development-only package flags.
- **`ComponentVulnerabilityAnalyzer`**:
  - Exported Content Providers lacking read/write permissions (`CWE-926`).
  - Exported Services accessible without permission constraints.
  - Exported Broadcast Receivers listening for arbitrary intents.
- **`CryptoVulnerabilityAnalyzer`**:
  - Insecure cipher modes: Electronic Codebook (ECB) mode detection.
  - Deprecated legacy ciphers: DES, 3DES, RC4 references.
  - Collision-prone hash algorithms: MD5 and SHA-1 references.
  - Hardcoded API keys and secrets: Matching patterns for AWS, Google API, Stripe, Slack, RSA Private Keys, GitHub tokens, and generic bearer secrets.
  - **Secret Masking**: All detected credentials are automatically sanitized (e.g. `AKIA************WXYZ`) in logs, CLI, and JSON outputs to prevent leaking sensitive values.

---

## 6. Diff-Aware Security Analysis

When comparing an original APK with a modified APK (`apkforge security mod.apk --diff orig.apk`), the `DiffSecurityAnalyzer` identifies security regressions:
- **Added Dangerous Permissions**: Detects introduction of sensitive permissions not present in the original build.
- **Certificate Changes / Re-signing**: Detects modifications to signing keys or certificate fingerprints.
- **Added Exported Components**: Detects new activities, services, or receivers exposed to IPC.
- **Added Native Libraries**: Detects new `.so` binaries introduced in the update.
- **Added Network Domains**: Detects new external network endpoints referenced in the modified APK.
- **Added Execution / Dynamic Loading APIs**: Detects new invocations of `Runtime.exec` or `DexClassLoader`.

---

## 7. False-Positive Controls & Negative Fixture Testing

Static analysis often flags legitimate utilities (audio recorders, camera tools, navigation apps, backup managers) as suspicious.

APKForge avoids false positives through:
1. **Capability vs. Context**: Having `RECORD_AUDIO` produces an informational capability finding. It only elevates to high-severity surveillance if combined with background services or exfiltration channels.
2. **Generic Word Blocklists**: String matching ignores generic substrings (e.g. "key", "token", "exec") unless bounded by structured regex or API context.
3. **Explicit Negative Fixture Tests**: Validated against legitimate standalone audio recorders (no background service) and clean calculator applications, confirming no false malware or surveillance findings are emitted.

---

## 8. CLI & Output Formats

### Security Analysis Command

```bash
# Analyze single APK
apkforge security app.apk

# Filter by category
apkforge security app.apk --malware
apkforge security app.apk --spyware
apkforge security app.apk --vulns

# Diff-aware security analysis
apkforge security modded.apk --diff original.apk

# Machine-readable JSON output
apkforge security app.apk --json
```

### Full Unified Analysis Command

```bash
# Orchestrate Inspection + Privacy + Security in one command
apkforge analyze app.apk

# Export unified report as JSON
apkforge analyze app.apk --json
```

### Example JSON Structure

```json
{
  "status": "complete",
  "security_status": "findings_present",
  "package_name": "com.example.app",
  "version_name": "1.0.0",
  "version_code": 1,
  "summary": {
    "total_findings": 3,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 2,
    "low_count": 0,
    "info_count": 0,
    "malware_count": 1,
    "spyware_count": 1,
    "vulnerability_count": 1,
    "diff_count": 0,
    "overall_security_status": "findings_present"
  },
  "findings": [
    {
      "id": "SEC-SPY-AUDIO-SURVEILLANCE",
      "category": "surveillance",
      "title": "Background Audio Recording Capability",
      "description": "Application pairs audio recording permissions with background service components.",
      "severity": "high",
      "confidence": "high",
      "evidence": [
        {
          "description": "Declared permission: android.permission.RECORD_AUDIO",
          "location": "manifest:permission:android.permission.RECORD_AUDIO",
          "snippet": "RECORD_AUDIO",
          "source": null
        }
      ],
      "assessment": "The APK contains capabilities consistent with background audio recording.",
      "limitations": [
        "Static analysis cannot establish that audio recording occurs during normal execution."
      ],
      "references": [
        "CWE-359: Exposure of Private Personal Information"
      ],
      "tags": [
        "audio",
        "microphone",
        "surveillance"
      ]
    }
  ],
  "warnings": [],
  "errors": [],
  "limitations": []
}
```

---

## 9. Explicit Non-Goals & Invariants

To maintain product integrity and safety:
1. **No Code Execution**: Bytecode and native libraries are parsed statically; nothing is executed or loaded into a runtime environment.
2. **No Network Traffic**: No external IP/domain queries, threat intelligence cloud queries, or live TLS probing.
3. **No Automatic Malware Label**: Findings describe capabilities and indicators; APKForge does not generate a single aggregate "87% malware score".
4. **No Modification Yet**: APK modification, rebuilding, signing, and patching are reserved for Phase 6+.
