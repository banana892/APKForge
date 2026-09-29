# APKForge Diff Engine (Phase 3)

The APKForge Diff Engine answers the question:

> **What changed between APK A and APK B?**

While the primary use case is comparing an **Original APK** against a **Modified / Modded APK**, the architecture treats both inputs symmetrically as **APK A** and **APK B** without assuming either is necessarily the original or benign.

The Diff Engine operates purely on **structured, evidence-based comparisons** across Phase 1 intake models and Phase 2 inspection models. It does **not** rely solely on binary or archive hashes, does **not** execute code, makes **no network connections**, and makes **no security risk or privacy conclusions** (which belong to later phases).

---

## 1. Diff Architecture

The subsystem is organized in `src/apkforge/diff/`:

```
src/apkforge/diff/
├── __init__.py         # Package exports
├── models.py           # Diff models (DiffResult, DiffChange, DiffSummary, category diffs)
├── engine.py           # DiffEngine coordinator
├── identity.py         # IdentityDiffer (package, versions, SDK levels)
├── files.py            # FileDiffer (archive-level entry comparison, sizes, SHA-256)
├── manifest.py         # ManifestDiffer (application attributes, SDKs)
├── permissions.py      # PermissionDiffer (declared & requested permissions)
├── components.py       # ComponentDiffer (activities, services, receivers, providers, intent filters)
├── dex.py              # DEXDiffer (DEX files, classes, methods, fields, framework APIs)
├── strings.py          # StringDiffer (printable string additions, removals, metrics)
├── network.py          # NetworkDiffer (URLs with provenance, domains, IP addresses)
├── native.py           # NativeDiffer (ELF shared libraries, ABIs, symbols)
├── resources.py        # ResourceDiffer (resources.arsc, res/ structure by type)
├── assets.py           # AssetDiffer (assets/ directory, Shannon entropy deltas)
├── embedded.py         # EmbeddedDiffer (nested APKs, DEX, ELF, scripts)
├── certificates.py     # CertificateDiffer (fingerprints, subjects, issuers, serials)
└── summary.py          # SummaryEngine (deterministic quantitative aggregation)
```

### Orchestration Pipeline

```
APK A ────► Intake & Inspection A ───┐
                                      ├──► DiffEngine ──► DiffResult (JSON / Rich CLI)
APK B ────► Intake & Inspection B ───┘        │
                                              ├── IdentityDiffer
                                              ├── FileDiffer
                                              ├── ManifestDiffer
                                              ├── PermissionDiffer
                                              ├── ComponentDiffer
                                              ├── DEXDiffer
                                              ├── StringDiffer
                                              ├── NetworkDiffer
                                              ├── NativeDiffer
                                              ├── ResourceDiffer
                                              ├── AssetDiffer
                                              ├── EmbeddedDiffer
                                              ├── CertificateDiffer
                                              └── SummaryEngine
```

---

## 2. Comparison Categories & Significance

Every difference is classified into a neutral significance category:

| Category | Significance Scope | Examples |
|---|---|---|
| `FILE` | Low-level archive structure | Entry added/removed, SHA-256 change |
| `STRUCTURAL` | Package components & packaging | Activities, services, assets, resources |
| `METADATA` | Package configuration | Package name, version, SDK, manifest flags |
| `CODE` | Bytecode & executable artifacts | DEX classes, methods, fields, APIs, native libs |
| `NETWORK` | Network endpoints & domains | URLs, domain names, IPv4/IPv6 addresses |
| `SIGNATURE` | Cryptographic signing identity | Signer certificates, SHA-256 fingerprints |

---

## 3. Matching Strategy

To ensure deterministic and accurate comparisons, every entity is matched using a stable identifier:

| Target Category | Stable Matching Key |
|---|---|
| Archive Files | Normalized ZIP path (e.g. `classes.dex`, `res/layout/main.xml`) |
| Package Identity | Package name |
| Permissions | Fully-qualified permission name (e.g. `android.permission.CAMERA`) |
| Components | Fully-qualified class name (e.g. `com.example.app.MainActivity`) |
| Intent Filters | Normalized action name, category name, or data scheme/host/port |
| DEX Files | Normalized archive path (e.g. `classes.dex`, `classes2.dex`) |
| Classes | Fully-qualified Dalvik/Java class name (e.g. `com.example.util.Crypto`) |
| Methods | Class name + signature: `methodName(param1,param2)ReturnType` |
| Fields | Class name + field name |
| API References | Fully-qualified API identifier (e.g. `android.location.LocationManager`) |
| URLs | Normalized URL string |
| Domains | Normalized lowercase domain name |
| IP Addresses | Canonical IPv4/IPv6 string |
| Native Libraries | Normalized library path (e.g. `lib/arm64-v8a/libnative.so`) |
| Native Symbols | Symbol name |
| Assets | Normalized asset path (e.g. `assets/database.db`) |
| Certificates | Certificate SHA-256 fingerprint |

---

## 4. Normalization Rules

Deterministic diffing requires strict normalization before comparison:

1. **Path Normalization**: All ZIP file paths are stripped of leading slashes, trailing slashes, and converted to forward slashes (`/`).
2. **Domain Normalization**: Hostnames and domains are converted to lowercase and stripped of trailing dots (`.`): e.g. `API.EXAMPLE.COM.` becomes `api.example.com`.
3. **URL Normalization**: Trailing whitespace is trimmed; schemes and hosts are lowercased.
4. **Ordering & Determinism**: All lists and dictionary iterations are explicitly sorted (`sorted(...)`) before computing additions, removals, and serialization, ensuring byte-identical JSON outputs across executions.
5. **Rename Handling**: Renamed classes or components are **not** guessed. Renaming heuristics are unreliable in static analysis; instead, an entity that ceased to exist is reported as `REMOVED` and a new entity is reported as `ADDED`.

---

## 5. Binary vs. Semantic Differences

A key design pillar of APKForge is distinguishing **binary changes** from **semantic changes**:

- **Binary-Level Difference**: `classes.dex` has a different SHA-256 hash or file size.
- **Semantic-Level Difference**: In `classes.dex`, exactly 2 new classes were added (`com.example.Tracker`), 1 legacy method was modified, and 45 classes remained byte-for-byte and signature-identical.
- **Archive Difference**: ZIP compression or entry ordering may change without any code changes.
- **Signature Difference**: An APK resigned with a different certificate will have a modified `META-INF/` binary structure; the engine isolates this to a `SIGNATURE` change while recognizing that classes, assets, and resources may be unchanged.

---

## 6. Limitations & Partial Analysis Behavior

If an APK contains damaged structures or unsupported features:

1. **Error Isolation**: Individual differ failures never crash the entire diff engine. A failure in DEX parsing or ELF symbol extraction generates a limitation notice and marks the status as `PARTIAL`, allowing manifest, file, permission, and asset comparisons to proceed safely.
2. **Package Identity Mismatch**: If `APK A` and `APK B` have different package names (e.g. `com.example.old` vs `com.example.new`), the engine does not abort. It flags `is_same_package = False`, records the package name change, and proceeds with all structural and code comparisons.
3. **Obfuscation**: For heavily obfuscated applications (e.g. ProGuard, DexGuard), method signatures may appear identical (e.g. `a()V`) across different classes. Class-scoped matching prevents cross-class collisions.

---

## 7. CLI Usage

### Basic Comparison
```bash
apkforge diff original.apk modified.apk
```

### Verbose Mode
Display detailed additions, removals, and modifications for every category:
```bash
apkforge diff original.apk modified.apk --verbose
```

### Category Filtering
Focus comparison on specific subsystems:
```bash
apkforge diff original.apk modified.apk --manifest
apkforge diff original.apk modified.apk --dex
apkforge diff original.apk modified.apk --native
apkforge diff original.apk modified.apk --network
apkforge diff original.apk modified.apk --resources
apkforge diff original.apk modified.apk --assets
apkforge diff original.apk modified.apk --embedded
apkforge diff original.apk modified.apk --files
```

### Machine-Readable JSON Output
```bash
apkforge diff original.apk modified.apk --json > diff_report.json
```

---

## 8. JSON Representation

The output of `--json` conforms to the `DiffResult` Pydantic v2 model:

```json
{
  "status": "complete",
  "apk_a": {
    "package_name": "com.example.app",
    "version_name": "1.0.0",
    "version_code": "100",
    "min_sdk": "24",
    "target_sdk": "34",
    "sha256": "4b92b6..."
  },
  "apk_b": {
    "package_name": "com.example.app",
    "version_name": "1.1.0",
    "version_code": "110",
    "min_sdk": "24",
    "target_sdk": "34",
    "sha256": "8c12a4..."
  },
  "identity": {
    "is_same_package": true,
    "package_name_change": null,
    "version_name_change": {
      "change_type": "modified",
      "category": "metadata",
      "identifier": "version_name",
      "before": "1.0.0",
      "after": "1.1.0",
      "details": {}
    }
  },
  "summary": {
    "total_changes": 12,
    "files_added": 2,
    "files_removed": 1,
    "files_modified": 5,
    "files_unchanged": 142,
    "permissions_added": 1,
    "permissions_removed": 0,
    "activities_added": 1,
    "services_added": 0,
    "receivers_added": 0,
    "providers_added": 0,
    "classes_added": 3,
    "classes_removed": 0,
    "classes_modified": 2,
    "urls_added": 2,
    "domains_added": 1,
    "ips_added": 0,
    "native_libraries_added": 0,
    "certificate_changed": false,
    "summary_lines": [
      "+ 1 permissions",
      "+ 1 activities",
      "+ 3 classes",
      "~ 2 classes modified",
      "+ 2 URLs",
      "+ 1 domains",
      "+ 2 files",
      "- 1 files",
      "~ 5 files modified"
    ]
  },
  "permissions": { ... },
  "components": { ... },
  "dex": { ... },
  "network": { ... },
  "native": { ... },
  "resources": { ... },
  "assets": { ... },
  "embedded": { ... },
  "certificates": { ... },
  "files": { ... },
  "warnings": [],
  "errors": [],
  "limitations": []
}
```
