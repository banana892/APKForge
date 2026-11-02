# APKForge — Android APK Security & Modification Workbench

> **A local-first workbench for static analysis, security review, privacy auditing,
> comparison, and controlled modification of Android APK files.**

---

## Phase H.4 — Transformation Verification Hardening

`apkforge verify ORIGINAL.apk TRANSFORMED.apk --plan PLAN.json --control CONTROL.apk
--built-locally` (or `--build-control`) verifies an H-TRANS-001 output against its original
*and* an unmodified control rebuild of it. original -> control measures the toolchain noise
floor; original -> transformed is the complete observed change; control -> transformed is the
transformation signal. Every difference is classified `NOISE` (reproduced by the control with
the same content), `EXPECTED_TRANSFORMATION` (declared from the plan and present in the
signal), `UNEXPECTED_CHANGE` or `UNKNOWN`, per domain (dex, manifest, resources, assets,
native, archive, signing, endpoints) with an explicit completeness (`COMPLETE`, `PARTIAL`,
`UNKNOWN`, `NOT_ANALYZED`). The result — `VERIFIED`, `VERIFIED_WITH_LIMITATIONS`,
`UNVERIFIED`, `FAILED` or `UNKNOWN` — is never stronger than the weakest mandatory domain.
APK byte differences between independent rebuilds are not treated as transformation
differences. Static verification does not establish that the transformed application is
safe, malware-free, spyware-free, or functionally correct when executed. Programmatic API:
`TransformationVerifier(service).verify(original, control, transformed, plan)` and the
`ControlExperiment` harness. See [docs/transformation.md](docs/transformation.md).

## Phase H.3 — Controlled Transformation (H-TRANS-001 only)

`apkforge transform APP.apk --plan PLAN.json --apply -o OUT.apk` applies exactly one
previously generated, ELIGIBLE H.2 plan of H-TRANS-001 (remove isolated class) to a copy of
the APK: plan integrity (source SHA-256, plan id, H.2 re-evaluation with an identical plan)
-> remove one smali class -> BuildService build/align/sign/verify -> Phase E diff with every
expected change declared before mutation -> H.1 re-analysis -> an expected-vs-actual
matrix. The output is written only when every check passes (`VERIFIED`); otherwise the run
is `REFUSED`, `FAILED` or `UNKNOWN` with a machine-readable reason. There is no override,
the input APK is never modified, and H-TRANS-002 stays planning-only. Without `--apply`
the plan is only validated. Programmatic API: `TransformationExecutor(service).run(apk,
plan, apply=True, output_apk=...)`. See [docs/transformation.md](docs/transformation.md).

## Phase H.2 — Transformation Eligibility & Deterministic Planning (planning only)

`apkforge transform APP.apk --transform H-TRANS-001 --target com.example.Foo --dry-run`
(or `H-TRANS-002` with `--target 'com.example.Foo->bar(I)V'`) decides from the H.1
evidence whether removing an isolated class / method is supported: `ELIGIBLE`,
`CONDITIONALLY_ELIGIBLE`, `REFUSED`, `UNSUPPORTED` or `UNDETERMINED`, with machine-readable
reason codes, and emits a deterministic plan for eligible requests. H.2 determines whether a
proposed transformation is supported by the available static evidence and produces a
deterministic plan. It does not apply the transformation (`--apply` needs a saved plan,
see H.3) and does not establish that the target behavior is malicious. Programmatic API:
`TransformationPlanningService.plan(apk, requests)`. See
[docs/transformation.md](docs/transformation.md).

## Phase H.1 — Evidence & Reference Model (read-only)

`apkforge references APP.apk [--class com.example.Foo] [--json] [--report PATH] [--verbose]`
indexes class / method / field / type / string / constructor / `const-class` references,
reflection and native/JNI indicators, and manifest and resource references — each with
provenance and an explicit `COMPLETE` / `PARTIAL` / `UNKNOWN` / `NOT_ANALYZED` state.
Absence of observed references is only reported as established when every relevant
analysis component is COMPLETE. H.1 does not perform APK transformations; it produces the
evidence future transformation stages will consume. Programmatic API:
`ReferenceAnalysisService.analyze(apk)`. See [docs/transformation.md](docs/transformation.md).

## Phase G — Controlled Privacy/Security Remediation

`apkforge remediate APP.apk --finding FINDING_ID` enables evidence-backed, controlled remediation of findings identified by Phase F or Phase B.
Remediation follows a strict lifecycle: `Finding -> Evidence -> Candidate -> Plan -> User Approval (--apply) -> Modifier -> BuildService -> Phase E Verification -> Post-Remediation Privacy Analysis -> Diff Report`.
Modifications are never automatic or silent: `--apply` is strictly required. Built-in remediations include:
- `G-REM-001`: Disable Boot Receiver (e.g. boot persistence)
- `G-REM-002`: Remove Specific Permission (manifest `<uses-permission>` removal with DEX reference detection)
- `G-REM-003`: Disable Specific Manifest Component (`android:enabled="false"`)
- `G-REM-004`: Guarded SDK Artifact Removal (conditional)

Remediations preserve original APK byte-integrity, detect conflicts, support automatic rollback on failure, and classify finding resolution as `REMEDIATED`, `PARTIALLY_REMEDIATED`, or `STILL_PRESENT`. Successful remediation does not claim the APK is "safe", "malware-free", or "spyware-free".
See [docs/remediation.md](docs/remediation.md).

## Phase F — Privacy, Tracker & Ads Intelligence

`apkforge privacy APP.apk` provides dedicated static privacy auditing, third-party SDK detection,
endpoint classification, and permission-to-code correlation with inspectable evidence provenance.
It clearly separates observed facts, inferred capabilities, suspected third-party SDKs, confidence
ratings, and explicit unknown/partial analysis states. It disclaims unverified runtime network traffic,
avoids arbitrary privacy scores or spyware probabilities, and never labels apps "malware" solely based
on static indicators. Output supports `--json` (ANSI-free guaranteed) and `--report PATH`. Programmatic
workflows use `PrivacyAnalysisService`. See [docs/privacy-analysis.md](docs/privacy-analysis.md).

## Phase E — Diff and verification

`apkforge diff A B` reports a raw archive diff, per-comparator semantic status (never
`unchanged` when a comparison could not complete), a full manifest-tree comparison and,
with `--security`, the security-relevant changes. `apkforge verify ORIGINAL MODIFIED`
produces a verification matrix (structural, signature, noise baseline, expected and
unexpected changes, semantic and security diff) with an overall VERIFIED / FAILED /
UNDETERMINED. Rebuild noise is accepted only when it is byte-identical to the APK's
measured no-op rebuild with the same toolchain. A clean diff does not prove an APK is
malware-free, and a verified signature does not prove it is safe.
See [docs/verification.md](docs/verification.md).

## Phase D — Modification framework

`apkforge modifiers` lists the available modifiers; `apkforge modify app.apk -m <id> [-m <id>]`
plans them (`--dry-run`) or applies them to the decoded APK, rebuilds, aligns, signs and
verifies it through BuildService, and compares the rebuilt APK with the plan
(expected change / rebuild noise / unexpected / unknown). Modification verification is
reported separately from APK signature verification, and a modifier without a
verification is reported *not verified*. A verified result does not mean the APK is safe.
See [docs/modification-framework.md](docs/modification-framework.md).

## 📦 Current Status — Phase 7: Modification Framework Complete

APKForge has completed **Phase 0 (Foundation)**, **Phase 1 (Intake & Identification)**, **Phase 2 (Core APK Inspection)**, **Phase 3 (APK Diff Engine)**, **Phase 4 (Privacy & Tracker Engine)**, **Phase 5 (Security Analysis Engine)**, **Phase 6 (Modification Planning Engine)**, and **Phase 7 (Modification Framework)**.

The modification framework turns approved modification plans into controlled, executed changes:
- **Workspace Isolation**: All modifications operate on a working copy inside an isolated workspace. The original APK is never modified.
- **Approval Enforcement**: Only explicitly approved plans with accepted changes reach execution.
- **Built-in Modifiers**: ManifestModifier, PermissionModifier, TrackerModifier, ComponentModifier, ResourceModifier, DexModifier, PayloadModifier.
- **Modifier Registry**: Extensible dispatch system mapping change types to modifier implementations.
- **Preflight Validation**: All changes are validated before any modification is applied.
- **Dry-Run Mode**: Simulate all modifications without writing any changes.
- **Rollback Support**: Automatic rollback of applied changes on failure.
- **Truthful Status**: Each step is reported as executed (and verified, where the modifier can verify), skipped, failed, verification-failed or not attempted. A skipped change is never counted as a success: the run is `skipped` or `partial` and `apkforge modify` exits with code 3.
- **CLI Modify Command**: `apkforge modify` command with `--dry-run`, `--approve-all`, `--plan`, and `--json` support.

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

# Modification Planning (Phase 6)
apkforge plan path/to/app.apk
apkforge plan path/to/app.apk --diff original.apk
apkforge plan path/to/app.apk --type permission
apkforge plan path/to/app.apk --type tracker
apkforge plan path/to/app.apk --risk high
apkforge plan path/to/app.apk --json > plan.json
apkforge plan path/to/app.apk --yaml > plan.yaml
apkforge plan path/to/app.apk --output plan.yaml

# Modification Execution (Phase 7)
apkforge modify path/to/app.apk --plan plan.json --dry-run
apkforge modify path/to/app.apk --plan plan.yaml --approve-all
apkforge modify path/to/app.apk --approve-all --workspace ./output
apkforge modify path/to/app.apk --approve-all --json > result.json

# Verify a built APK (structure + signature), or a modified APK against its original
apkforge verify output.apk
apkforge verify original.apk modified.apk --baseline tests/corpus/results/phase-e-noise-baseline.json --built-locally

# Reference & evidence analysis (Phase H.1, read-only)
apkforge references path/to/app.apk --class com.example.Foo --verbose
apkforge references path/to/app.apk --json > references.json

# Transformation eligibility & planning (Phase H.2, never applied)
apkforge transform path/to/app.apk --transform H-TRANS-001 --target com.example.Foo --dry-run
apkforge transform path/to/app.apk -t H-TRANS-002 --target 'com.example.Foo->bar()V' --json

# Controlled transformation (Phase H.3): validate, then apply a saved ELIGIBLE plan
apkforge transform path/to/app.apk -t H-TRANS-001 --target com.example.Foo --report plan.json
apkforge transform path/to/app.apk --plan plan.json
apkforge transform path/to/app.apk --plan plan.json --apply -o transformed.apk --report h3.md

# Transformation verification hardening (Phase H.4): original + control rebuild + output
apkforge verify path/to/app.apk transformed.apk --plan plan.json --build-control --report h4.md

# Controlled Remediation (Phase G)
# List available remediation definitions
apkforge remediations
apkforge remediations --json

# Plan remediation (dry-run by default, no APK modification)
apkforge remediate path/to/app.apk --finding PRIV-REC-BOOT

# Apply remediation with explicit approval and output artifact
apkforge remediate path/to/app.apk --finding PRIV-REC-BOOT --apply --output modified.apk --report report.md
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
| **Phase 6** | ✅ Complete | Modification planning engine: evidence-driven change proposals, risk assessment, impact analysis, dependencies, conflicts, serialization, staleness tracking |
| **Phase 7** | ✅ Complete | Modification framework: workspace isolation, approval enforcement, 7 built-in modifiers (Manifest, Permission, Tracker, Component, Resource, DEX, Payload), preflight validation, dry-run, rollback |
| **Phase 8** | ✅ Complete | APK Rebuild & Signing: apktool integration, zipalign, apksigner, post-modification verification (`BuildService`, see [docs/build-service.md](docs/build-service.md); verification in Phases D/E/H.4) |
| **Phase 9** | 🚧 In progress | GUI & Interactive Workbench: 9.1 local web workbench (`apkforge gui`: analyze, diff, ModKit runs/chains), see [docs/gui.md](docs/gui.md) |

Later work continued as lettered phases (D–H, documented at the top of this README):
modification, diff/verification, privacy, remediation, controlled transformations, and
third-party ModKits including the Morphe adapter ([docs/modkits.md](docs/modkits.md)).

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
