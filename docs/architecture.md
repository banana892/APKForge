# APKForge Architecture

## Layered Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
│               CLI (Typer)  │  GUI (Phase 4+)                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Application Layer                         │
│   (orchestrates plugins; enforces security invariants)          │
│                                                                 │
│   AnalysisService │ DiffService │ ModificationService          │
│   BuildService    │ VerificationService │ ReportingService      │
│   PrivacyAnalysisService                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Core                                    │
│                                                                 │
│   APKForgeConfig  │  Models  │  Exceptions  │  Logging         │
│   PluginRegistry  │  Workspace                                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
          ┌─────────────────┼──────────────────────┐
          ▼                 ▼                      ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│  Analysis /  │  │   Modification   │  │    Build /           │
│  Security /  │  │   (Phase 3+)     │  │    Verification      │
│  Privacy     │  └──────────────────┘  │    (Phase 3+)        │
│  (Phase 1+)  │                        └──────────────────────┘
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Integrations                               │
│   JADX (read-only)  │  APKTool  │  ReVanced  │  VirusTotal     │
│                          (Phase 2+)                             │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Reporting                                 │
│   Text │ JSON │ HTML │ Markdown │ SARIF      (Phase 1+)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Analysis Pipeline

```
Original APK (immutable)
        │
        ▼
    APKInput
        │
        ▼
    Workspace.create()          ← isolated temp directory
        │
        ▼
    Extraction (Phase 1+)       ← ZIP entries with size limits
        │
        ▼
    AnalyzerPlugins (Phase 1+)  ← parallel or sequential
        │                            ↓ each returns AnalysisResult
        ▼
    Report assembly             ← overall_status derived
        │
        ▼
    ReporterPlugin              ← text / JSON / HTML
        │
        ▼
    Workspace.cleanup()
```

### Diff Pipeline (Phase 3)

```
APK A                                   APK B
  │                                       │
  ▼                                       ▼
APKInput A                              APKInput B
  │                                       │
  ▼                                       ▼
Intake & Inspection A                   Intake & Inspection B
  │                                       │
  └───────────────────┬───────────────────┘
                      │
                      ▼
                 DiffEngine
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
   IdentityDiffer FileDiffer  ManifestDiffer
   PermissionDiff Component   DEXDiffer
   StringDiffer   NetworkDiff NativeDiffer
   ResourceDiffer AssetDiffer EmbeddedDiffer
         │            │            │
         └────────────┼────────────┘
                      ▼
                SummaryEngine
                      │
                      ▼
                 DiffResult
              (Text CLI / JSON)
```

### Privacy & Tracker Pipeline (Phase 4)

```
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
                          (Text CLI / JSON)
```

### Modification Pipeline (Phase D)

The implemented pipeline is `apkforge.modification.pipeline.ModificationPipeline`; see
`docs/modification-framework.md`. Modifiers plan and edit decoded files, BuildService
decodes/builds/aligns/signs/verifies, DiffEngine + `verify_expectations` compare the
rebuilt APK with the combined plan. The diagram below is the original Phase 5 sketch.

### Modification Pipeline (Phase 5+, original sketch)

```
Original APK (immutable read-only)
        │
        ▼
    APKInput + ModificationPlan
        │
        ▼
    Workspace.create()          ← isolated working copy
        │
        ▼
    ModifierPlugins             ← each returns ModificationStep results
        │
        ▼
    BuilderPlugin               ← rebuilds APK from workspace
        │
        ▼
    VerifierPlugin              ← checks signature, integrity
        │
        ▼
    Output APK
        │
        ▼
    Workspace.cleanup()
```

---

## Package Structure

```
src/apkforge/
├── __init__.py         — version
├── __main__.py         — python -m apkforge entry point
│
├── cli/
│   └── main.py         — Typer CLI app (thin layer; delegates to services)
│
├── core/
│   ├── config.py       — APKForgeConfig (Pydantic, all defaults safe)
│   ├── exceptions.py   — APKForgeError hierarchy
│   ├── logging.py      — setup_logging(), get_logger()
│   ├── models.py       — All data models (APKInput, Finding, Report, …)
│   ├── plugins.py      — Plugin Protocol + PluginRegistry
│   └── workspace.py    — Workspace (isolated temp dir, path-traversal protection)
│
├── intake/             — Phase 1: Package identification, safety checks, hashes, certificates
│   ├── archive.py      — SafeZipExtractor (zip-slip & bomb limits)
│   ├── certificates.py — X.509 signature & certificate parsing
│   ├── detector.py     — Format detection (APK, APKS, XAPK, splits)
│   ├── handlers/       — Format-specific intake handlers
│   ├── hashing.py      — Streaming cryptographic hashes (MD5, SHA-1, SHA-256)
│   ├── inventory.py    — Structural package inventory
│   ├── manifest.py     — Fast identity extraction from AndroidManifest.xml
│   └── service.py      — APKIntakeService orchestrator
│
├── inspection/         — Phase 2: Static technical inspection
│   ├── assets.py       — Non-code asset analysis & Shannon entropy
│   ├── dex.py          — DEX header, classes, methods, fields, framework APIs
│   ├── embedded.py     — Magic-byte detection of nested APKs, DEX, ELF, scripts
│   ├── engine.py       — InspectionEngine coordinator
│   ├── manifest.py     — Deep binary XML manifest inspection (permissions, components)
│   ├── models.py       — Inspection domain models & EvidenceSource provenance
│   ├── native.py       — 32/64-bit ELF analysis, ABIs, symbols, strings
│   ├── network.py      — Static URL, domain, and IPv4/IPv6 extractor
│   ├── obfuscation.py  — Quantitative identifier naming patterns
│   ├── resources.py    — resources.arsc presence & res/ categorization
│   └── strings.py      — Standalone printable ASCII/UTF-8 string extractor
│
├── diff/               — Phase 3: Structured APK Diff Engine
│   ├── assets.py       — Asset differences & Shannon entropy deltas
│   ├── certificates.py — Signing certificate & fingerprint deltas
│   ├── components.py   — Activity, service, receiver, provider, intent-filter deltas
│   ├── dex.py          — DEX file, class, method, field, API reference deltas
│   ├── embedded.py     — Embedded APK, DEX, ELF payload deltas
│   ├── engine.py       — DiffEngine coordinator with error isolation
│   ├── files.py        — Archive file-level entry deltas (sizes, hashes)
│   ├── identity.py     — Package name, version, and SDK level deltas
│   ├── manifest.py     — Manifest application attributes and SDK deltas
│   ├── models.py       — DiffResult, DiffChange, category diff Pydantic models
│   ├── native.py       — ELF shared library, ABI, and symbol deltas
│   ├── network.py      — URL (with provenance), domain, IP address deltas
│   ├── permissions.py  — Declared and requested permission deltas
│   ├── resources.py    — resources.arsc and res/ structural breakdown deltas
│   ├── strings.py      — Printable ASCII/UTF-8 string inventory deltas
│   └── summary.py      — SummaryEngine aggregating metrics and summary lines
│
│
├── privacy/            — Phase F: Privacy, Tracker & Ads Intelligence Layer
│   ├── advertising.py  — AdvertisingDetector (ad networks & mediation)
│   ├── analytics.py    — AnalyticsDetector (event logging & metrics)
│   ├── behavior.py     — BehaviorAnalyzer (13 static behavior indicator patterns)
│   ├── cross_check.py  — compare_privacy_with_security (Phase B cross-check reconciliation)
│   ├── data_collection.py — DataCollectionAnalyzer (identifiers, clipboard, accessibility)
│   ├── endpoints.py    — EndpointAnalyzer (domains, URLs, first-party, CDN, sensitive)
│   ├── engine.py       — PrivacyEngine coordinator & EvidenceIndex builder
│   ├── models.py       — PrivacyResult, PrivacyFinding, PrivacyReport (Sections A-H), SDKs, endpoints
│   ├── permissions.py  — PermissionAnalyzer (taxonomy, risk, component & API correlation)
│   ├── rules.py        — Declarative rule engine, single-pass indexer, confidence logic
│   ├── rules_data/     — External declarative rules (YAML/JSON with auditable metadata)
│   ├── service.py      — PrivacyAnalysisService (programmatic API service)
│   ├── telemetry.py    — TelemetryDetector (crash reporting & diagnostics)
│   └── trackers.py     — TrackerDetector (attribution & tracking SDKs)
│
├── remediation/        — Phase G: Controlled Privacy & Security Remediation
│   ├── catalog.py      — RemediationCatalog (G-REM-001 through G-REM-004)
│   ├── compare.py      — compare_privacy_before_after (finding transition & resolution classifier)
│   ├── execution.py    — RemediationExecutor (orchestrates ModificationPipeline, BuildService, Verification)
│   ├── mapping.py      — map_finding_to_remediations (finding-to-candidate mapper)
│   ├── models.py       — RemediationPlan, RemediationExecutionResult, states, and definitions
│   ├── modifiers.py    — RemovePermissionModifier, DisableComponentModifier, remediation catalog
│   ├── planner.py      — RemediationPlanner (machine-checkable preconditions, deterministic plan generator)
│   ├── report.py       — format_remediation_diff_report, format_remediation_plan_report
│   └── service.py      — RemediationService (high-level programmatic API)
│
├── security/           — Phase 5: Security Analysis Engine
│   ├── engine.py       — SecurityEngine coordinator, index builder, error isolation
│   ├── models.py       — SecurityResult, SecurityFinding, SecuritySummary, FullAnalysisResult
│   ├── rules.py        — Declarative rule engine, SecurityRule, SecurityCondition, indexer
│   ├── diff_analyzer.py — DiffSecurityAnalyzer (diff regression and modification findings)
│   ├── rules_data/     — Declarative rules (spyware, malware, vulnerabilities, combinations)
│   ├── malware/        — MalwareAnalyzer, payloads, suspicious_code, persistence, network
│   ├── spyware/        — SpywareAnalyzer, surveillance (audio, camera, location), collection
│   └── vulnerabilities/ — VulnerabilityAnalyzer, manifest flags, exported components, crypto/secrets
├── modification/       — Phase 6+: ModifierPlugin implementations
├── builders/           — Phase 6+: BuilderPlugin implementations
├── verification/       — Phase 6+: VerifierPlugin implementations
├── integrations/       — Phase 6+: IntegrationPlugin implementations
└── reporting/          — Phase 6+: ReporterPlugin implementations
```

---

## Key Design Decisions

### 1. Protocol-based plugin interface

Plugins implement a `Protocol` (structural subtyping) rather than an abstract
base class.  This means third-party plugins can satisfy the interface without
importing from APKForge internals, and the core never needs to depend on plugin
implementations.

### 2. No global mutable state

The `PluginRegistry` is an instance, not a singleton.  Configuration is passed
explicitly.  This makes unit testing straightforward — each test constructs its
own registry and config.

### 3. Pydantic v2 models for all inter-module communication

Every data structure exchanged between layers is a validated Pydantic model.
This provides:
- Runtime validation with clear error messages
- Automatic JSON serialisation for reporting
- Documented, typed interfaces between modules

### 4. Workspace isolation

APK contents are always extracted into a unique temporary directory (the
workspace).  The original APK is never modified.  The workspace enforces
path-traversal protection via `Workspace.subpath()`.

### 5. CLI delegates to services

The CLI layer only parses arguments and calls application-layer services.
Business logic never lives in `cli/main.py`.  This means a future GUI or REST
API can use the exact same core services without going through Typer.

### 6. Security-first defaults

- Extraction limits configured from the start (zip-bomb protection)
- `FAILED` and `PARTIAL` analysis statuses are never silently treated as clean
- No APK execution in any code path
- No automatic external network requests

---

## Dependency Strategy

| Library | Purpose | When introduced |
|---------|---------|----------------|
| `pydantic` | Data validation and models | Phase 0 |
| `typer` | CLI framework | Phase 0 |
| `rich` | Terminal output | Phase 0 |
| `androguard` | APK/DEX parsing | Phase 1+ |
| `apktool` (subprocess) | Disassembly/rebuild | Phase 3+ |
| `jadx` (subprocess) | Decompilation | Phase 2+ |

The core package never imports `androguard` directly.  Instead, Phase 1 will
introduce an `AnalyzerPlugin` that wraps it.  This prevents the entire
application from depending on the Androguard installation state.
