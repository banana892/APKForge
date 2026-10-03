# Controlled Privacy & Security Remediation (Phase G)

APKForge's Phase G introduces a dedicated, evidence-driven remediation layer that enables controlled, verifiable modification of an Android application to address specific static privacy or security findings.

> [!IMPORTANT]
> **Core Safety & Correctness Principle**:
> APKForge remediation is an evidence-driven transformation and verification pipeline. Successful rebuilding or removal of an indicator **does not establish** that an APK is "malware-free", "spyware-free", or "safe". The system distinguishes between:
> - Detected evidence
> - Remediation candidate
> - Planned change
> - Applied change
> - Verified result
> - Unresolved finding

---

## 1. Remediation Lifecycle

Phase G strictly enforces a multi-stage approval and verification pipeline:

```text
Finding (Phase F / Phase B)
  ↓
Evidence Inspection
  ↓
Remediation Candidate Selection
  ↓
Explicit Machine-Checkable Plan
  ↓
Explicit User Approval (--apply / approved=True)
  ↓
Controlled Modification (Phase D Modifier)
  ↓
Build, Align, Sign & Structural Verification (BuildService)
  ↓
Semantic Diff & Noise Baseline Check (Phase E Verification)
  ↓
Post-Remediation Privacy Re-Analysis (Phase F Engine)
  ↓
Before / After Evidence Report
```

Automatic, silent, or unapproved APK modification is strictly prohibited by architectural invariants.

---

## 2. Initial Remediation Catalog

Phase G implements a small, conservative, auditable built-in catalog of supported remediations:

| Remediation ID | Name | Target Categories | Risk | Status | Description |
|---|---|---|:---:|:---:|---|
| `G-REM-001` | **Disable Boot Receiver** | `persistence`, `boot_persistence` | `medium` | `supported` | Sets `android:enabled="false"` on the target boot receiver and removes `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED">`. |
| `G-REM-002` | **Remove Specific Permission** | `permission`, `location`, `camera`, `contacts`, `microphone`, `network`, etc. | `medium` | `supported` | Removes an exact `<uses-permission>` declaration from `AndroidManifest.xml`. If static DEX bytecode still references the associated API, post-remediation analysis reports `PARTIALLY_REMEDIATED`. |
| `G-REM-003` | **Disable Manifest Component** | `component`, `activity`, `service`, `receiver`, `provider` | `medium` | `supported` | Disables a specific manifest component by adding or updating `android:enabled="false"` on the component tag. |
| `G-REM-004` | **Remove Tracker/SDK Artifact** | `advertising`, `analytics`, `tracking`, `sdk` | `high` | `conditional` | Guards against unsafe whole-SDK deletions. Permits removal only when classes and assets are strictly isolated without cross-module dependencies; otherwise reports `UNSUPPORTED_REMEDIATION`. |

---

## 3. Explicit Outcome States

Phase G avoids collapsing distinct execution and verification states into generic binary results:

### Remediation Plan & Execution States
- `PLANNED`: Plan generated with all preconditions satisfied; waiting for explicit approval.
- `APPROVAL_REQUIRED`: Modification requested without `--apply` flag; blocked before executing any build or file edits.
- `APPLIED`: Manifest or file modifications applied to workspace.
- `VERIFIED`: Modification applied, APK rebuilt and signed, Phase E verification matrix passed, and target finding verified remediated.
- `PARTIALLY_REMEDIATED`: Rebuilt APK verified, manifest declaration removed, but underlying DEX bytecode references still remain.
- `FAILED`: Build, verification, or post-remediation analysis failed, or target finding remains unmodified.
- `SKIPPED`: Machine-checkable preconditions were not satisfied (e.g. target component or permission not declared).
- `REFUSED`: Modification requested is unsafe, conflicting, or unsupported without broader dependency refactoring.
- `UNDETERMINED`: Incomplete or indeterminate evidence prevents safe planning.
- `ROLLBACK_FAILED`: Critical failure during workspace rollback.

### Target Finding Resolution
- `REMEDIATED`: Finding is absent from post-remediation analysis and no remaining static code references were observed.
- `PARTIALLY_REMEDIATED`: Manifest declaration eliminated, but bytecode references remain in DEX.
- `STILL_PRESENT`: Finding is still observed post-remediation.
- `NO_LONGER_COMPARABLE`: Output APK structure prevents semantic comparison.
- `UNKNOWN`: Inconclusive post-remediation analysis.

---

## 4. CLI Usage

### Listing Available Remediations
```bash
apkforge remediations [--json]
```

### Dry-Run / Planning Mode (Default)
Generates and inspects the plan without touching the APK or creating output files:
```bash
apkforge remediate sample.apk --finding PRIV-REC-BOOT --dry-run
```

Output:
```text
# Remediation Plan: plan-a172422bd8ae
...
Preconditions Checked:
[✓] permission_declared: expected RECEIVE_BOOT_COMPLETED declared in manifest, found declared
[✓] boot_receiver_identified: expected boot receiver identified, found de.audioattack.openlink.conf.PackageChangeBroadcastReceiver
[✓] receiver_currently_enabled: expected receiver is currently enabled, found enabled

Planned Modifications:
- set android:enabled="false" on <receiver de.audioattack.openlink.conf.PackageChangeBroadcastReceiver>
- remove <uses-permission android:name=android.permission.RECEIVE_BOOT_COMPLETED>
```

### Applying Remediation with Explicit Approval
```bash
apkforge remediate sample.apk \
    --finding PRIV-REC-BOOT \
    --apply \
    --output remediated.apk \
    --report report.md
```

### Pure JSON Output
Guaranteed ANSI-free even when `FORCE_COLOR` is set:
```bash
FORCE_COLOR=3 apkforge remediate sample.apk --finding PRIV-REC-BOOT --dry-run --json
```

---

## 5. Programmatic Service API

Developers and automated pipelines can invoke remediation through [`RemediationService`](file:///home/naishring/APKForge/src/apkforge/remediation/service.py#L25):

```python
from apkforge.remediation import RemediationService

# 1. Generate plan
plan = RemediationService.plan(
    apk_path="sample.apk",
    finding_id="PRIV-REC-BOOT",
)

if plan.ready:
    # 2. Apply plan with explicit approval
    result = RemediationService.apply(
        plan=plan,
        approved=True,
        output_path="remediated.apk",
    )
    print(f"Outcome: {result.state}")
    print(f"Target Resolution: {result.comparison.target_finding.resolution}")
```

---

## 6. Architectural Guarantees & Boundaries

1. **Original Byte-Identical Integrity**: The source APK is never modified in-place; its SHA-256 is verified unchanged before, during, and after every run.
2. **Phase E Verification Integration**: Every rebuilt APK must pass apksigner verification, structural verification, noise baseline check, expected-change verification, and unexpected-change detection.
3. **Traceability**: Every applied change is traceable back to concrete pre-remediation finding evidence.
4. **No Arbitrary Execution**: APKForge never installs or executes application code or extracted native binaries during analysis or remediation.
