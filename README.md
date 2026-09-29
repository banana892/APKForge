# APKForge — Android APK Security & Modification Workbench

> **A local-first workbench for static analysis, security review, privacy auditing,
> comparison, and controlled modification of Android APK files.**

---

## 📦 Current Status — Phase 5: Security Analysis Engine Complete

APKForge has completed **Phase 0 (Foundation)**, **Phase 1 (Intake & Identification)**, **Phase 2 (Core APK Inspection)**, **Phase 3 (APK Diff Engine)**, **Phase 4 (Privacy & Tracker Engine)**, and **Phase 5 (Security Analysis Engine)**.

The security analysis engine operates on structured evidence collected across Phases 1–4:
- **Core Analysis Philosophy**: Local technical evidence and analysis. Distinguishes Evidence, Severity, Confidence, Assessment, and Limitations on every finding. Static analysis never claims to definitively prove that an APK is malware, spyware, or safe.
- **Malware Indicators**: Embedded payloads (DEX, ELF, nested APKs, high-entropy assets), command execution (`Runtime.exec`, `ProcessBuilder`, shell binaries), dynamic code loading (`DexClassLoader`), persistence (`BOOT_COMPLETED`, foreground services), and direct IP/exfiltration channels.
- **Spyware & Surveillance Indicators**: Covert audio recording, camera capture, location tracking, SMS/OTP interception, call and contact harvesting, hardware device identifiers, accessibility service abuse, and multi-vector surveillance suites.
- **Vulnerability Indicators**: Insecure manifest flags (`debuggable`, `usesCleartextTraffic`, `allowBackup`), unprotected exported components (providers, services, receivers), cryptographic weaknesses (ECB mode, DES, MD5/SHA-1), and masked hardcoded credential detection.
- **Diff-Aware Security Analysis**: Automated regression detection when comparing original vs modified builds (added dangerous permissions, certificate changes, new exported attack surfaces, added native binaries, and new external network endpoints).
- **Unified Orchestration**: `apkforge analyze` command orchestrating Core Inspection, Privacy Auditing, and Security Analysis in a single invocation.

---

## What APKForge Is

A **local-first** command-line workbench that will allow security researchers,
privacy advocates, and Android developers to:

- **Inspect** APK structure and metadata (manifest, permissions, components)
- **Analyze** an APK for security and privacy concerns using static analysis
- **Scan** quickly for high-signal findings
- **Diff** two APK versions to understand what changed between releases
- **Modify** an APK using a structured, reversible modification plan
- **Verify** a rebuilt APK for structural and signature integrity

## What APKForge Is Not

- **Not a malware sandbox** — APKForge performs static analysis only; it never executes APKs
- **Not a VirusTotal clone** — APKForge does not automatically upload to external services
- **Not a one-click "is it malware?" tool** — findings carry severity, confidence, evidence, and limitations
- **Not a dynamic analysis engine** — no emulators, no dynamic instrumentation in scope

---

## Architecture Overview

```
   User
    │
    ▼
  CLI (Typer)
    │
    ▼
  Core Services
    ├── Configuration (APKForgeConfig)
    ├── Models (APKInput, Finding, AnalysisResult, …)
    ├── Logging
    ├── Workspace
    └── Plugin Registry
         │
         ├── Analysis Plugins   (Phase 1+)
         ├── Security Plugins   (Phase 1+)
         ├── Privacy Plugins    (Phase 1+)
         ├── Diff Plugins       (Phase 2+)
         ├── Modification       (Phase 3+)
         ├── Builders           (Phase 3+)
         ├── Verification       (Phase 3+)
         ├── Integrations       (Phase 2+)
         └── Reporters          (Phase 1+)
```

See [docs/architecture.md](docs/architecture.md) for the detailed design.

---

## Installation

### Requirements

- Python 3.11+
- pip / uv

### From source (development)

```bash
git clone https://github.com/apkforge/apkforge.git
cd apkforge
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## CLI Usage

```bash
# Show help
apkforge --help

# Show version
apkforge version

# Full static inspection (Phase 1 & Phase 2)
apkforge inspect path/to/app.apk

# Targeted inspector runs
apkforge inspect path/to/app.apk --manifest
apkforge inspect path/to/app.apk --dex --native
apkforge inspect path/to/app.apk --network --embedded

# Machine-readable JSON output
apkforge inspect path/to/app.apk --json > report.json

# Retain isolated workspace for debugging
apkforge inspect path/to/app.apk --keep-workspace

# Security analysis (Phase 5)
apkforge security path/to/app.apk
apkforge security path/to/app.apk --verbose
apkforge security path/to/app.apk --malware
apkforge security path/to/app.apk --spyware
apkforge security path/to/app.apk --vulns
apkforge security path/to/app.apk --diff original.apk
apkforge security path/to/app.apk --json > security.json

# Unified full analysis (Inspection + Privacy + Security)
apkforge analyze path/to/app.apk
apkforge analyze path/to/app.apk --json > full_report.json

# (Phase 6+) Apply a modification plan
apkforge modify path/to/app.apk --plan plan.toml

# (Phase 6+) Verify a built APK
apkforge verify output.apk
```

---

## Development Setup

See [docs/development.md](docs/development.md) for the full development guide.

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/ tests/

# Format code
ruff format src/ tests/

# Type checking
mypy src/
```

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| **Phase 0** | ✅ Complete | Foundation: architecture, CLI, models, plugin system |
| **Phase 1** | ✅ Complete | Intake & identification: safe extraction, multi-format (.apk, .apks, .xapk, splits), metadata, hashing, certificates |
| **Phase 2** | ✅ Complete | Core APK inspection: manifest, DEX, native ELF, resources, assets, network, embedded files, obfuscation |
| **Phase 3** | ✅ Complete | APK Diff Engine: structured delta analysis across identity, files, manifest, permissions, components, DEX, network, native libs, resources, assets, and certificates |
| **Phase 4** | ✅ Complete | Privacy & tracker engine (permissions, API correlation, SDK/tracker detection, endpoint mapping, data capabilities) |
| **Phase 5** | ✅ Complete | Security analysis engine: malware indicators, spyware/surveillance indicators, vulnerabilities, combinations, diff regressions, secret masking |
| **Phase 6** | ⏳ Planned | Modification engine, rebuild, signing, verification |
| **Phase 7** | ⏳ Planned | GUI (consuming Phase 1–6 core engines) |

---

## Security Principles

APKForge treats every APK as **untrusted input** from the moment it is loaded:

1. **APKs are never executed** — not by APKForge, not by triggered child processes
2. **Extracted files are never executed** — `.dex`, `.so`, `.sh`, binary payloads
3. **Extraction limits are enforced** — zip-bomb protection, max size, max depth
4. **Analysis failures are FAILED** — never interpreted as "clean"
5. **No automatic external uploads** — hash lookups require explicit configuration

---

## License

MIT — see [LICENSE](LICENSE).
