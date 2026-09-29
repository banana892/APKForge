# APKForge — Phase 2: Core APK Inspection

The **Core APK Inspection** pipeline provides fundamental, descriptive static inspection of Android packages. It takes the normalized [`AndroidPackage`](file:///home/naishring/APKForge/src/apkforge/intake/__init__.py) model produced by Phase 1 Intake and produces a comprehensive, cross-referenced technical inventory of everything inside the package.

> [!IMPORTANT]
> **Descriptive Invariant & Disclaimer**
> Phase 2 describes APK contents. It does NOT establish that an application is malicious or safe, does not classify permissions as dangerous, does not execute code, and does not connect to any network endpoints.

---

## 1. Inspection Pipeline Architecture

```text
APK / Container (.apk, .apks, .xapk, split directory)
                      │
                      ▼
            Phase 1 Intake Service
                      │
                      ▼
          Normalized AndroidPackage
                      │
                      ▼
┌────────────────────────────────────────────────────────┐
│                   InspectionEngine                     │
├────────────────────────────────────────────────────────┤
│  ├── ManifestInspector       (Permissions, Components) │
│  ├── DEXInspector            (Classes, Methods, APIs)  │
│  ├── NativeInspector         (ELF Headers, ABIs, Libs) │
│  ├── ResourceInspector       (resources.arsc, res/)    │
│  ├── AssetInspector          (Assets, Shannon Entropy) │
│  ├── NetworkInspector        (URLs, Domains, IPs)      │
│  ├── EmbeddedFileInspector   (Dropped APKs, DEX, ELF)  │
│  └── ObfuscationInspector    (Structural Indicators)   │
└────────────────────────────────────────────────────────┘
                      │
                      ▼
          Unified InspectionResult
           (with EvidenceSource)
```

---

## 2. Specialized Sub-Inspectors

### Manifest Inspector (`ManifestInspector`)
Performs binary XML parsing using Androguard with a fallback standard ElementTree parser:
- **Package Metadata**: Reuses Phase 1 package name, version codes, and SDK levels.
- **Permissions**: Complete inventory of requested permissions (`<uses-permission>`) and custom declared permissions (`<permission>`) with protection levels (`normal`, `dangerous`, `signature`, etc.).
- **Components**:
  - **Activities**: Names, exported flags, permissions, and intent filters.
  - **Services**: Names, exported flags, permissions, and foreground service types.
  - **Broadcast Receivers**: Names, exported flags, permissions, and intent filters.
  - **Content Providers**: Names, authorities, exported flags, read/write permissions, and URI permissions.
- **Intent Filters**: Structured actions, categories, and data schemes/hosts/path prefixes/patterns/MIME types.
- **Application Attributes**: `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, and application label.

### DEX Inspector (`DEXInspector`)
Extracts code architecture and structural metadata without decompilation or reverse engineering:
- **DEX Headers**: Magic bytes, DEX version format (`035`, `037`, `038`, `039`), SHA-1 signature, and file size.
- **Class Inventory**: Package hierarchy, class names, superclasses, interfaces, access flags.
- **Methods & Fields**: Signatures, descriptors, parameter types, return types, access modifiers.
- **Android Framework APIs**: Identification of calls into standard Android framework APIs (`android.*`, `java.*`, `javax.*`).
- **Strings**: Deduplicated string constants extracted from DEX string pools with configurable limits and character filters.

### Native Inspector (`NativeInspector`)
Statically analyzes native shared libraries (`.so`) located in `lib/<abi>/`:
- **ELF Header Analysis**: 32-bit (`ELF32`) and 64-bit (`ELF64`) parsing, endianness (little/big), and machine architecture (`ARM`, `AArch64`, `x86`, `x86_64`, `MIPS`, `RISC-V`).
- **ABI Grouping**: Inventory organized by ABI directory.
- **Symbol Extraction**: Defined/exported dynamic symbols and imported global symbols from `.dynsym`.
- **Embedded Strings**: Printable ASCII string extraction (minimum length 4) with offsets.

### Resource Inspector (`ResourceInspector`)
Analyzes compiled Android resource tables and resource files:
- **Resource Table**: Presence, size, and integrity of `resources.arsc`.
- **Resource Directory (`res/`)**: File counts and categorization by resource type (`drawable`, `layout`, `values`, `xml`, `raw`, `mipmap`, `anim`, `color`, `menu`).

### Asset Inspector (`AssetInspector`)
Inventories non-compiled application assets located in `assets/`:
- **File Metadata**: Relative paths, sizes, and inferred MIME types.
- **Shannon Entropy**: Measures randomness per asset on a 0.0–8.0 scale to identify compressed, encrypted, or packed blobs.

### Network Inspector (`NetworkInspector`)
Statically extracts network indicators from DEX string pools, native libraries, and manifest deep links:
- **URLs**: Structured URL matching (`http://`, `https://`) with URL normalization and deduplication.
- **Domains**: Hostname extraction with noise filtering (excluding standard schema URLs like `schemas.android.com` and `w3.org`).
- **IP Addresses**: Validated IPv4 and IPv6 addresses, excluding loopback (`127.0.0.1`), broadcast (`255.255.255.255`), and wildcard addresses (`0.0.0.0`).
- **Provenance**: Retains the source (`EvidenceSource`) of every extracted indicator.

### Embedded File Inspector (`EmbeddedFileInspector`)
Inspects APK contents (especially `assets/`, `res/raw/`, and non-standard root locations) for nested executables:
- **Embedded APKs & JARs**: Identifies nested archives containing `AndroidManifest.xml` or `.class` files.
- **Embedded DEX Files**: Detects Dalvik executables stored outside standard `classes*.dex` locations.
- **Embedded ELF Binaries**: Detects ELF shared libraries or executables outside `lib/<abi>/`.
- **Scripts**: Detects shell scripts (`.sh`, `.bash`), Python scripts (`.py`), or batch files.

### Obfuscation Inspector (`ObfuscationInspector`)
Computes quantitative structural metrics from DEX naming patterns:
- **Short Identifiers**: Calculates percentage of single- or double-letter class names, method names, and field names (e.g., `a.b.c()`).
- **Package Depth**: Evaluates distribution of package depth and nesting anomalies.
- **Descriptive Evidence**: Generates boolean indicator flags (`is_likely_obfuscated`) based on threshold criteria without making subjective verdicts.

---

## 3. Security Invariants & Guarantees

1. **Untrusted Input Invariant**: All input files are treated as untrusted and potentially malicious.
2. **Zero Code Execution**: Neither Dalvik bytecode nor native binaries (`.so` or ELF) are ever executed or loaded into memory as runnable code.
3. **Zero Network Connections**: The inspection engine never connects to any URL, domain, or IP address found inside the APK.
4. **Error Isolation**: Failure in an individual inspector does not abort the entire pipeline. Unhandled errors are caught, logged, and converted into structured `limitations` entries, degrading the overall status from `COMPLETE` to `PARTIAL`.
5. **Original Input Preservation**: Source packages remain read-only. Temporary files created during extraction are cleaned up automatically upon inspection completion unless `--keep-workspace` is specified.

---

## 4. CLI Usage

### Basic Inspection
Run full static inspection with summary terminal output:

```bash
apkforge inspect app.apk
```

### Targeted Inspector Selection
Run only specific inspectors to optimize speed or isolate findings:

```bash
# Manifest inspection only
apkforge inspect app.apk --manifest

# DEX and native inspection
apkforge inspect app.apk --dex --native

# Network and embedded file inspection
apkforge inspect app.apk --network --embedded
```

Available selective flags:
- `--manifest`
- `--dex`
- `--native`
- `--resources`
- `--assets`
- `--network`
- `--embedded`
- `--obfuscation`

### JSON Output
Output the full structured `InspectionResult` model as JSON:

```bash
# Using the --json convenience flag
apkforge inspect app.apk --json > report.json

# Using the format option
apkforge inspect app.apk --format json > report.json
```

### Workspace Retention
Retain the temporary extraction directory for manual debugging or inspection:

```bash
apkforge inspect app.apk --keep-workspace
```

---

## 5. Output Data Model & Evidence Provenance

Every item discovered during inspection links to an `EvidenceSource` tracking:
- `file`: Path within the APK (e.g. `classes2.dex`, `lib/arm64-v8a/libfoo.so`)
- `class_name`: Java/Kotlin class name if applicable
- `method_name`: Method identifier if applicable
- `offset`: Byte offset within binary files

The resulting `InspectionResult` adheres to Pydantic v2 schemas and serializes cleanly to JSON, providing complete backward compatibility with Phase 1 fields (`package_type`, `metadata`, `hashes`, `package`, `inventory`).
