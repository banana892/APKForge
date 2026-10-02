# APKForge — Full Implementation Plan

**Working name:** APKForge
**Positioning:** Android APK Security & Modification Workbench

---

# 1. Product Definition

APKForge is a **local-first workbench for inspecting, analyzing, comparing, modifying, rebuilding, and verifying Android packages**.

It is not intended to be simply another antivirus or VirusTotal replacement.

The product should answer four fundamental questions:

1. **What is inside this APK?**
2. **What changed between two APKs?**
3. **What security, privacy, advertising, and tracking issues exist?**
4. **What can be modified, and did the modification actually do what was intended?**

The core workflow is:

```text
INSPECT
   ↓
ANALYZE
   ↓
COMPARE
   ↓
PLAN
   ↓
MODIFY
   ↓
REBUILD
   ↓
VERIFY
```

External modification projects such as ReVanced should eventually be integrations/backends rather than becoming the foundation of APKForge.

---

# 2. Core Product Principles

These principles apply throughout the entire implementation.

## 2.1 Evidence before conclusions

APKForge should report:

```text
Evidence
Severity
Confidence
Limitations
```

rather than making unsupported claims such as:

```text
MALWARE = TRUE
```

Static analysis can identify suspicious indicators, but an indicator is not automatically proof of malware.

---

## 2.2 Recommend before modifying

The default workflow should be:

```text
Analyze
   ↓
Identify possible modification
   ↓
Explain evidence
   ↓
Show expected impact
   ↓
User approval
   ↓
Modify
   ↓
Rebuild
   ↓
Verify
```

APKForge should not blindly remove permissions, trackers, advertisements, or components.

---

## 2.3 APKs are untrusted input

APKForge must treat every APK as potentially hostile.

The analysis pipeline should account for:

* malformed APKs
* corrupted archives
* excessive extraction sizes
* decompression bombs
* unusual resource structures
* malformed DEX
* unexpected native libraries
* analysis failures
* unsupported APK structures

A failed or partial analysis must be reported explicitly rather than silently producing an incomplete result.

---

## 2.4 Modification must be auditable

Every modification should have:

```text
Original state
      ↓
Requested change
      ↓
Actual change
      ↓
Verification
      ↓
Final state
```

The user should be able to understand what APKForge changed.

---

## 2.5 CLI first

The CLI is the actual product engine.

The GUI comes later and should call the same core services rather than implementing separate logic.

---

# 3. Architecture

The repository should remain modular:

```text
apkforge/
├── pyproject.toml
├── README.md
├── LICENSE
│
├── src/
│   └── apkforge/
│       ├── cli/
│       ├── core/
│       ├── analysis/
│       ├── security/
│       ├── privacy/
│       ├── diff/
│       ├── modification/
│       ├── builders/
│       ├── verification/
│       ├── integrations/
│       └── reporting/
│
├── rules/
├── tests/
├── samples/
└── docs/
```

The major architectural areas are:

```text
Core
 ├── Analysis
 ├── Security
 ├── Privacy
 ├── Diff
 ├── Modification
 ├── Builders
 ├── Verification
 ├── Integrations
 └── Reporting
```

The existing project direction already separates these concerns.

---

# 4. Roadmap Status Policy

A phase is not considered complete merely because its code exists.

Every phase must have:

```text
Objective
Deliverables
Tests
Exit criteria
Known limitations
```

Status should use:

```text
NOT STARTED
IN PROGRESS
VERIFIED
BLOCKED
```

Avoid declaring a phase complete without evidence.

In particular, the current project material does not contain a formal Phase B completion report, so Phase B must be validated rather than retroactively treated as fully proven.

---

# PHASE A — PRODUCT DIRECTION

## Status

**COMPLETE**

## Objective

Define what APKForge is and what it is not.

## Established direction

APKForge is:

```text
Android APK Security & Modification Workbench
```

with the workflow:

```text
Inspect
  ↓
Analyze
  ↓
Compare
  ↓
Plan
  ↓
Modify
  ↓
Rebuild
  ↓
Verify
```

The product is not primarily an antivirus.

The revised product direction explicitly establishes this workbench model.

## Exit criteria

* Product direction documented
* Architecture defined
* CLI-first strategy established
* External tools treated as integrations
* Modification workflow defined

---

# PHASE B — CORE FOUNDATION

## Objective

Establish and verify the core APK inspection and analysis foundation.

## Core APK representation

APKForge should be able to represent important APK information including:

```text
Identity
Manifest
Permissions
Components
DEX
Native libraries
Resources
URLs/domains
Certificates
```

This structure is already part of the intended architecture.

## Core services

The foundation should support the major analysis areas:

```text
APK loader
Manifest parser
Permission analyzer
Component analyzer
DEX analyzer
Resource analyzer
Certificate analyzer
Network/domain extraction
Reporting
```

## Evidence model

Findings should contain concepts such as:

```text
Finding
├── type
├── evidence
├── severity
├── confidence
├── affected object
└── limitations
```

## Phase B validation

Before moving forward, test the foundation against a defined APK corpus.

The corpus should contain several different APK types rather than one ideal APK.

At minimum, test:

* ordinary APKs
* different Android target versions
* APKs containing native libraries
* APKs with multiple components
* APKs with different permission profiles
* at least some structurally unusual APKs

## Exit criteria

Phase B is **VERIFIED** only when:

* core APK parsing works against the defined corpus
* analysis results are reproducible
* failures are surfaced clearly
* findings contain evidence
* known limitations are documented

---

# SECURITY VALIDATION GATE

This is a gate between the foundation and the modification/build pipeline.

It is not a giant independent development phase.

## Purpose

Before APKForge starts modifying APKs, verify that its analysis foundation has a known baseline.

## Define

```text
Test APK
Expected finding
Actual finding
Correctness
Known limitation
```

For example:

```text
APK
 ↓
Expected permission
 ↓
Expected component
 ↓
Expected domain
 ↓
APKForge result
```

## Exit criteria

The gate passes when:

* the test corpus is defined
* expected baseline findings are documented
* important analysis failures are understood
* unsafe APK input is handled appropriately
* no major unexplained regression blocks Phase C

This prevents the project from building its modification system on top of an unvalidated analysis layer.

---

# PHASE C — APK BUILD + FIRST MODIFICATION PIPELINE

## Priority

**NEXT**

This is the most important immediate milestone.

## Objective

Prove that APKForge can take a real APK through:

```text
Original APK
    ↓
Analyze
    ↓
Decode
    ↓
Controlled modification
    ↓
Rebuild
    ↓
Zipalign
    ↓
Sign
    ↓
Verify
    ↓
Re-analyze
    ↓
Minimal diff
    ↓
Expected-vs-actual check
```

The project material already identifies decode → modify → rebuild → sign → verify as the critical missing pipeline.

---

## C1 — Toolchain

Establish:

```text
Java
Apktool
Android Build Tools
 ├── zipalign
 └── apksigner
```

The previous project audit indicated that Java/`jarsigner` existed while Apktool, `apksigner`, and `zipalign` still needed verification/setup.

Do not assume the current machine state. Verify every tool.

---

## C2 — Independent toolchain proof

Before deeply integrating the tools into APKForge:

```text
test.apk
   ↓
apktool decode
   ↓
controlled harmless change
   ↓
apktool build
   ↓
zipalign
   ↓
apksigner
   ↓
verify
```

This separates:

```text
Toolchain failures
```

from:

```text
APKForge implementation failures
```

---

# C3 — BuildService

Create a controlled build abstraction:

```text
BuildService
├── decode()
├── prepare_workspace()
├── build()
├── align()
├── sign()
└── verify()
```

The build system should produce structured results rather than only shell output.

For example:

```text
BuildResult
├── success
├── output_apk
├── logs
├── warnings
├── errors
├── certificate
└── verification_result
```

---

# C4 — Real APK Corpus

Do not validate the entire build system using one APK.

Use a small corpus of real APKs.

Record each result as:

```text
APK
Toolchain result
Decode result
Build result
Alignment result
Signing result
Verification result
Failure category
Notes
```

Possible failure categories:

```text
SUCCESS
DECODE_FAILURE
RESOURCE_FAILURE
FRAMEWORK_FAILURE
BUILD_FAILURE
ALIGNMENT_FAILURE
SIGNING_FAILURE
VERIFICATION_FAILURE
UNSUPPORTED
```

The goal is not to make every APK rebuild successfully immediately.

The goal is to understand the actual operating envelope.

---

# C5 — First Harmless Modifier

Implement exactly one controlled modification.

It should be deliberately low-risk.

For example, a controlled manifest/resource modification.

The purpose is not to build the permission remover yet.

The purpose is to prove:

```text
APKForge
   ↓
Modifier
   ↓
BuildService
   ↓
Valid modified APK
```

---

# C6 — Minimal Verification

After rebuilding:

```text
Modified APK
   ↓
APK structural validation
   ↓
Signature verification
   ↓
Re-analysis
```

Verify:

* APK exists
* APK can be parsed
* signature is valid
* requested modification exists
* critical APK structures remain valid

---

# C7 — Minimal Semantic Diff

Do **not** build the complete diff engine yet.

Phase C only needs enough diff functionality to prove the first modification.

Initial comparison should focus on:

```text
Manifest
Permissions
Components
Certificate
Selected semantic metadata
```

The diff must understand that some changes are expected consequences of rebuilding.

For example:

```text
Certificate:
CHANGED — EXPECTED
```

rather than:

```text
Certificate:
UNEXPECTED CHANGE
```

---

# C8 — Phase C Exit Criteria

Phase C passes only when APKForge can successfully demonstrate:

```text
Original APK
     ↓
Analyze
     ↓
Decode
     ↓
Harmless modification
     ↓
Rebuild
     ↓
Zipalign
     ↓
Sign
     ↓
Verify
     ↓
Re-analyze
     ↓
Minimal semantic diff
     ↓
Expected change confirmed
```

And the result is reproducible on the defined test corpus.

---

# PHASE D — MODIFICATION FRAMEWORK

## Objective

Turn the first experimental modifier into a proper modification architecture.

Every modifier follows:

```text
Modifier
├── identify()
├── analyze()
├── plan()
├── apply()
└── verify()
```

This lifecycle is already defined in the project architecture.

---

## D1 — Modifier API

Define common objects such as:

```text
ModificationRequest
ModificationPlan
ModificationResult
VerificationResult
```

Every modification should be explainable.

Example:

```text
ModificationPlan

Target:
READ_CONTACTS

Action:
REMOVE

Evidence:
No identified usage

Confidence:
LOW

Potential impact:
Application contact functionality may fail
```

---

# D2 — Manifest Modifier

Support controlled manifest modifications.

Potential operations:

```text
Add permission
Remove permission
Modify component configuration
Modify selected manifest attributes
```

All changes require verification.

---

# D3 — Permission Modifier

The permission modifier must not automatically assume that unused-looking permissions are unnecessary.

Its job is to apply an approved plan.

---

# D4 — Resource Modifier

Support controlled resource modifications.

---

# D5 — Component Modifier

Support carefully controlled component modifications.

Examples:

```text
Activity
Service
Receiver
Provider
```

Component changes must be treated carefully because removing a component can break application behavior.

---

# PHASE E — DIFF + VERIFICATION HARDENING

## Objective

Turn the minimal Phase C diff into one of APKForge's major capabilities.

This phase exists after we have real rebuilt APKs and therefore know what rebuild noise actually looks like.

---

# E1 — Raw Diff

Compare:

```text
APK A
VS
APK B
```

At the file/archive level.

---

# E2 — Normalized Diff

Separate expected rebuild noise from meaningful differences.

Potential normalization categories:

```text
Signature changes
Zip alignment
Generated metadata
Resource serialization differences
Smali formatting differences
```

The exact normalization rules should be derived from real observed rebuild behavior rather than guessed in advance.

---

# E3 — Semantic Diff

Compare:

```text
Certificate
Manifest
Permissions
Components
DEX classes
DEX methods
Strings
Resources
Assets
Native libraries
Domains
URLs
Embedded files
```

The original project direction already identifies these comparison targets.

---

# E4 — Security-Relevant Diff

The output should eventually move beyond:

```text
+ 3 files
- 1 file
```

and report changes such as:

```text
PERMISSIONS

+ READ_PHONE_STATE

COMPONENTS

+ Background service

NATIVE LIBRARIES

+ lib/example.so

NETWORK

+ example-domain.com

CERTIFICATE

CHANGED
```

This is particularly important for comparing original APKs with modded APKs.

---

# E5 — Expected vs Actual

Every modification should produce:

```text
REQUESTED
EXPECTED
ACTUAL
UNEXPECTED
```

Example:

```text
REQUESTED
Remove READ_CONTACTS

EXPECTED
READ_CONTACTS absent

ACTUAL
READ_CONTACTS absent

UNEXPECTED
No security-relevant unexpected changes
```

If something unexpected occurs:

```text
WARNING
Additional component changed
```

---

# E6 — Verification

Verification should include:

```text
Structural validity
Signature validity
Requested modification
Expected changes
Unexpected changes
Security-relevant changes
```

Verification is not a one-time final feature.

It is part of the modification lifecycle.

---

# PHASE F — PRIVACY / TRACKER / AD ENGINE

## Objective

Turn APKForge's privacy analysis into actionable modification plans.

---

# F1 — Tracker Detection

Identify:

```text
Tracking libraries
Analytics SDKs
Telemetry
Advertising SDKs
Known tracking endpoints
```

---

# F2 — SDK Mapping

For each detected SDK:

```text
SDK
 ↓
Code references
 ↓
Components
 ↓
Network endpoints
 ↓
Resources
```

---

# F3 — Advertising Analysis

Do not simply say:

```text
ADS FOUND
```

Instead report:

```text
Advertising SDK:
XYZ

Affected components:
3

Observed endpoints:
5

Potential impact:
Advertising functionality may stop
```

---

# F4 — Modification Planning

Detection and modification remain separate.

The system produces:

```text
Potential modification
```

and the user approves it.

---

# F5 — Tracker Modification

The same workflow applies:

```text
Detect
 ↓
Explain
 ↓
Plan
 ↓
Approve
 ↓
Modify
 ↓
Rebuild
 ↓
Verify
 ↓
Diff
```

---

# PHASE G — SECURITY INTELLIGENCE

## Objective

Expand APKForge's security analysis after the modification infrastructure is proven.

This is where the original spyware/malware analysis goal becomes substantially more sophisticated.

---

# G1 — Suspicious Permissions

Identify suspicious combinations rather than treating individual permissions as malware proof.

---

# G2 — Suspicious API Usage

Analyze potentially sensitive APIs and their relationships with:

```text
Permissions
Components
Background execution
Network behavior
Data access
```

---

# G3 — Spyware Indicators

Potential indicators include combinations involving:

```text
Sensitive data access
Microphone
Camera
Location
Contacts
SMS
Accessibility
Background services
Network transmission
Dynamic loading
```

The result remains:

```text
Evidence
Severity
Confidence
Limitations
```

not an unsupported binary malware verdict.

---

# G4 — Dynamic Loading

Identify mechanisms such as:

```text
Dynamic code loading
Dex loading
Native library loading
Downloaded code
Reflection-heavy behavior
```

---

# G5 — Embedded Payloads

Inspect:

```text
Native libraries
Embedded archives
Executable content
Unusual assets
Suspicious payload files
```

---

# G6 — Obfuscation / Packing

Identify indicators of:

```text
Heavy obfuscation
Packing
Encrypted strings
Unusual class structures
```

These are indicators, not automatic malware conclusions.

---

# G7 — Rule Correlation

Eventually combine multiple observations:

```text
Permission
+
API
+
Component
+
Network endpoint
+
Behavioral indicator
```

to produce stronger evidence.

Example:

```text
RECORD_AUDIO
+
AudioRecord
+
background service
+
network transmission
```

is more meaningful than any one indicator individually.

---

# PHASE H — EXTERNAL TOOL BACKENDS

## Objective

Allow APKForge to orchestrate external modification and reverse-engineering tools without making them permanent core dependencies.

Potential integrations:

```text
ReVanced
JADX
smali/baksmali
APKTool
Other compatible tools
```

The project direction explicitly calls for external tools to be treated as integrations rather than making APKForge permanently dependent on their internals.

---

# H1 — Integration Interface

Each backend should expose metadata such as:

```text
Name
Version
License
Capabilities
Supported APKs
Dependencies
Input format
Output format
```

---

# H2 — ReVanced Integration

ReVanced should be treated as a backend.

Conceptually:

```text
APKForge
   ↓
Analyze
   ↓
Prepare
   ↓
ReVanced backend
   ↓
Modified APK
   ↓
APKForge verification
   ↓
APKForge diff
```

APKForge remains responsible for orchestration, analysis, reporting, and verification.

---

# H3 — Backend Isolation

A broken external backend must not corrupt the APKForge core.

Each backend should run through controlled interfaces and produce structured results.

---

# PHASE I — ADVANCED APK SANITIZATION

## Objective

Combine the individual modification capabilities into complete user-controlled sanitization workflows.

Example:

```text
APK
 ↓
Inspect
 ↓
Security analysis
 ↓
Privacy analysis
 ↓
Compare
 ↓
Modification plan
 ↓
User approval
 ↓
Permission modification
 ↓
Tracker modification
 ↓
Ad modification
 ↓
Other approved modifications
 ↓
Rebuild
 ↓
Sign
 ↓
Verify
 ↓
Re-analyze
 ↓
Final diff
```

The goal is not:

> Delete everything suspicious.

The goal is:

> Identify, explain, let the user choose, modify, and prove what changed.

---

# PHASE J — GUI

## Objective

Provide a graphical interface after the CLI workflow is stable.

The GUI should expose the same core operations:

```text
Inspect
Analyze
Compare
Plan
Modify
Verify
```

The GUI should not contain a separate implementation of the APK analysis engine.

Architecture:

```text
             APKForge Core
                  │
        ┌─────────┴─────────┐
        │                   │
       CLI                 GUI
```

---

# PHASE K — ADVANCED AUTOMATION

Only after the core system is stable.

Potential capabilities:

```text
Batch analysis
Batch modification
More APK formats
APKS
XAPK
Split APK workflows
Automated rule updates
External reputation
Advanced reports
Plugin system
Additional modification backends
```

External reputation should remain optional enrichment rather than becoming a requirement for APKForge's core functionality.

---

# 5. APK Format Expansion

Support should eventually include:

```text
APK
APKS
XAPK
Split APK packages
```

The architecture should avoid assuming that every Android application is represented by one standalone APK.

However, single-APK workflows should remain the initial implementation target because they simplify validation of the build pipeline.

---

# 6. Permission Minimization Model

Permission classification should remain:

```text
REQUIRED
LIKELY REQUIRED
OPTIONAL
POTENTIALLY UNNECESSARY
SUSPICIOUS
UNKNOWN
```

The workflow is:

```text
Permission analysis
        ↓
Code/component evidence
        ↓
Classification
        ↓
Modification recommendation
        ↓
User approval
        ↓
Permission modification
        ↓
Rebuild
        ↓
Verification
```

A particularly important limitation:

> Removing a permission from the manifest does not remove the code that uses that permission.

Therefore permission removal must never be presented as proof that the underlying functionality has been removed.

Static analysis also cannot reliably prove that a permission is unnecessary.

Consequently, classifications such as:

```text
POTENTIALLY UNNECESSARY
```

will often have lower confidence.

---

# 7. Reporting System

Reports should eventually have a consistent structure.

```text
APKForge Report

APK Identity
Certificate
Package
Version
SDK information

Analysis Summary

Permissions
Components
Libraries
Domains
Trackers
Advertising SDKs

Security Findings
Privacy Findings

Modification Plan

Requested Changes

Build Result

Verification Result

Expected Changes

Actual Changes

Unexpected Changes

Limitations
```

The report should distinguish:

```text
Observed fact
Inference
Risk assessment
Unknown
```

rather than presenting all findings with the same certainty.

---

# 8. Testing Strategy

Testing should exist at multiple levels.

## Unit tests

Test:

```text
Manifest parsing
Permission classification
DEX extraction
Certificate extraction
Diff normalization
Modifier planning
Report generation
```

## Integration tests

Test:

```text
Decode
Modify
Build
Align
Sign
Verify
Re-analyze
Diff
```

## Corpus tests

Maintain a collection of real APKs covering different structures.

Each corpus entry should record:

```text
APK
Expected behavior
Actual behavior
Known limitations
```

## Regression tests

Every discovered bug should eventually become a regression test.

Example:

```text
APK X
Previously failed resource rebuild
Fix applied
Test ensures it remains fixed
```

---

# 9. Phase Exit-Criteria System

Every phase should finish with evidence.

Example:

```text
Phase
    ↓
Implementation complete
    ↓
Tests complete
    ↓
Corpus validation
    ↓
Known failures documented
    ↓
Exit criteria satisfied
    ↓
VERIFIED
```

Not:

```text
Code exists
    ↓
COMPLETE
```

---

# 10. Final Roadmap

```text
┌───────────────────────────────────────────────────┐
│                 APKForge ROADMAP                  │
└───────────────────────────────────────────────────┘

A — Product Direction
        │
        ▼
B — Core Foundation
        │
        ▼
   Security Validation Gate
        │
        ▼
C — Build + First Modification
        │
        ├── Toolchain
        ├── BuildService
        ├── Real APK corpus
        ├── Harmless modifier
        ├── Build/sign/verify
        └── Minimal semantic diff
        │
        ▼
D — Modification Framework
        │
        ├── Manifest
        ├── Permission
        ├── Resource
        └── Component
        │
        ▼
E — Diff + Verification Hardening
        │
        ├── Normalization
        ├── Semantic diff
        ├── Security diff
        └── Expected vs actual
        │
        ▼
F — Privacy / Tracker / Ads
        │
        ▼
G — Security Intelligence
        │
        ├── Spyware indicators
        ├── Malware indicators
        ├── Dynamic loading
        ├── Obfuscation
        └── Payload analysis
        │
        ▼
H — External Tool Backends
        │
        ├── ReVanced
        ├── JADX
        ├── smali
        └── Other tools
        │
        ▼
I — Advanced Sanitization
        │
        ▼
J — GUI
        │
        ▼
K — Automation / Advanced Formats
```

---

# 11. Immediate Next Task

Do **not** start with:

```text
Malware detection
Tracker removal
Permission removal
ReVanced
GUI
```

The immediate task is:

## Phase C.1 — Establish and test the APK build toolchain

Then:

## Phase C.2 — Connect the toolchain to APKForge

Then:

## Phase C.3 — Implement one harmless modifier and complete:

```text
Decode
   ↓
Modify
   ↓
Rebuild
   ↓
Zipalign
   ↓
Sign
   ↓
Verify
   ↓
Re-analyze
   ↓
Minimal diff
   ↓
Expected-vs-actual check
```

Only after that pipeline is demonstrated reliably should APKForge move into serious permission, tracker, advertising, and external modification work.

That is the foundation on which the rest of APKForge depends.

