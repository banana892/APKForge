# APKForge Modification Planning & Change Proposal Engine (Phase 6)

The APKForge Modification Planning subsystem converts technical findings across inspection, privacy, security, and diff analysis engines into a **structured, reviewable, evidence-backed modification plan**.

> [!IMPORTANT]
> **Core Principle: Non-Destructive Static Planning**
>
> Modification planning does **NOT** modify APK files.
>
> Phase 6 builds a static proposal engine that answers:
> *"Given what APKForge discovered about this APK, what modifications could be made, why would they be made, what could they affect, and what would be required to apply them?"*
>
> Actual APK modification, smali editing, bytecode patching, resource replacement, rebuilding, and signing belong to Phase 7+.

---

## 1. Subsystem Workflow

```text
APK / Target
 │
 ├── Phase 1 — Intake
 ├── Phase 2 — Core Inspection
 ├── Phase 3 — APK Diff (optional baseline comparison)
 ├── Phase 4 — Privacy & Tracker Analysis
 └── Phase 5 — Security Analysis
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│                 Modification Planner                         │
│  (src/apkforge/modification/planner.py)                     │
│                                                             │
│  ├── Rule Evaluation (Registry & Rules)                     │
│  ├── Evidence Provenance Binding                            │
│  ├── Risk & Functional Impact Analysis                      │
│  ├── Companion Dependency Discovery                         │
│  ├── Conflict Detection (Target / Operation)                │
│  ├── Reversibility Assessment                               │
│  ├── Validation Recipe Generation                           │
│  └── Topological Change Ordering                            │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
   Modification Plan (DRAFT / REVIEW_REQUIRED)
          │
          ▼
   Human Review (Interactive / File-based)
          │
          ▼
   Approved Modification Plan (Ready for Phase 7 Execution)
```

---

## 2. Architecture & File Structure

The modification planning subsystem is located in `src/apkforge/modification/`:

```text
src/apkforge/modification/
├── __init__.py          # Public exports (models, planner, registry, serialization)
├── models.py            # ModificationPlan, PlannedChange, ChangeType, ModificationRisk,
│                        # PlanStatus, Reversibility, ImpactAssessment, ChangeDependency,
│                        # ChangeConflict
├── planner.py           # ModificationPlanner orchestration engine
├── rules.py             # ModificationRule protocol, ModificationContext, built-in rules
├── registry.py          # ModificationRuleRegistry for rule lifecycle & deduplication
├── impact.py            # ImpactAnalyzer (direct, functional, side-effects, risk rating)
├── dependencies.py      # DependencyAnalyzer (companion changes, topological ordering)
├── conflicts.py         # ConflictDetector (target/operation conflicts, resolution)
├── validation.py        # ValidationGenerator (post-modification verification steps)
└── serialization.py     # JSON and YAML lossless serialization / deserialization
```

---

## 3. Data Models

### 3.1 ModificationPlan

```python
class ModificationPlan(BaseModel):
    plan_id: str                      # Deterministic ID: PLAN-<hash>
    source_apk: str                   # Path or URI of target APK
    source_sha256: str                # SHA-256 hash of target APK for staleness checks
    created_at: str                   # UTC timestamp
    planner_version: str              # Semantic planner version (e.g. 0.1.0)
    analysis_references: dict[str, str] # Provenance to intake/inspection/privacy/sec/diff

    changes: list[PlannedChange]      # Ordered proposals (CHANGE-001, ...)
    dependencies: list[ChangeDependency] # Companion and required dependencies
    conflicts: list[ChangeConflict]   # Contradictions requiring human decision

    warnings: list[str]               # Diagnostic and partial analysis alerts
    limitations: list[str]            # Conservative static analysis boundaries
    status: PlanStatus                # Current review state
```

### 3.2 Plan Status Lifecycle

Plans maintain an explicit state machine rather than a simple boolean flag:

* `DRAFT`: Initial draft plan in construction.
* `REVIEW_REQUIRED`: Generated plan awaiting human review (**default for generated plans**).
* `APPROVED`: Human reviewer explicitly approved the plan or a subset of changes.
* `REJECTED`: Plan rejected by reviewer.
* `STALE`: The underlying APK file has been modified or its SHA-256 no longer matches.
* `INVALID`: Structural or prerequisite invalidity.

### 3.3 PlannedChange

Every change proposed by the engine answers 8 questions:

1. **What is being changed?** (`target`, `change_type`, `operation`)
2. **Why is it being changed?** (`reason`)
3. **What evidence caused this proposal?** (`evidence`, `rule_id`)
4. **What is the expected benefit?** (`expected_effects`, `tags`)
5. **What could break?** (`potential_impacts`, `impact`, `risk`, `risk_explanation`)
6. **What other APK elements depend on it?** (`dependencies`, `prerequisites`)
7. **Can the change be reversed?** (`reversibility`, `reversibility_explanation`)
8. **How should the result be verified?** (`validation_steps`)

---

## 4. Supported Change Types

The engine defines 15 distinct planning operation types (`ChangeType`):

| ChangeType | Purpose | Example |
| :--- | :--- | :--- |
| `REMOVE_PERMISSION` | Propose removing `<uses-permission>` | Unused `READ_CONTACTS` |
| `MODIFY_PERMISSION` | Alter permission protection level | Restrict custom permission |
| `DISABLE_COMPONENT` | Propose disabling manifest component | Disable tracking service |
| `REMOVE_COMPONENT` | Propose deleting component declaration | Remove unused activity |
| `MODIFY_COMPONENT` | Alter flags on existing component | Set `android:exported="false"` |
| `REMOVE_TRACKER` | Propose removing tracking/ad SDK | Strip AdMob or AppsFlyer |
| `REMOVE_AD_COMPONENT` | Target advertising providers or receivers | Strip ad-loading receiver |
| `REMOVE_RESOURCE` | Propose removing unused resource files | Remove unreferenced assets |
| `REMOVE_ASSET` | Propose removing asset files | Remove unreferenced asset |
| `REMOVE_EMBEDDED_PAYLOAD`| Strip embedded executable binaries | Remove dropped ELF or APK |
| `MODIFY_MANIFEST` | General manifest attribute hardening | Disable `debuggable` or `allowBackup` |
| `MODIFY_CONFIGURATION` | Update network security configs | Enforce cleartext traffic block |
| `DEX_MODIFICATION` | Bytecode / Smali method-level patch | Future ReVanced hook / no-op |
| `NATIVE_MODIFICATION` | Native `.so` patching or stripping | Strip unused native library |
| `EXTERNAL_TOOL_PATCH` | Recipe targeting an external modifier | Third-party patch descriptor |

---

## 5. Evidence-Driven Planning & Provenance

The planner never invents changes or reasons. Every proposed modification must be backed by concrete evidence produced by Phases 2–5.

Evidence retains full provenance:
* **Location**: Exact origin (e.g. `manifest:permission:RECORD_AUDIO`, `dex:classes.dex`, `diff:permission`).
* **Description**: Human-readable explanation of the finding.
* **Snippet**: Relevant code or declaration snippet.

---

## 6. Risk Assessment vs. Security Severity

**Security Severity** and **Modification Risk** are independent dimensions:

* **Security Severity**: The threat impact of an unaddressed vulnerability or malicious indicator in the APK.
* **Modification Risk**: The likelihood that applying a proposed modification will break application functionality, crash at runtime, or cause build/signature failures.

### Risk Levels & Rationale

* `LOW`: Unused permissions with high confidence, disabling debug flags, removing isolated standalone payloads.
* `MEDIUM`: Removing tracker SDKs (may cause `ClassNotFoundException` if initialization code remains), disabling exported components without permission (may block expected IPC).
* `HIGH`: Bytecode DEX modifications, core service modifications, changes where dynamic class loading or heavy reflection is detected.
* `CRITICAL`: Changes to core application logic, authentication routines, or native library exports with high breakage probability.

Every risk rating is paired with an explainable `risk_explanation` detailing why the rating was assigned.

---

## 7. Impact Analysis Layer

The `ImpactAnalyzer` assesses changes across multiple axes:
* **Direct Effects**: Immediate alteration (e.g. permission removed from manifest).
* **Potential Functional Effects**: Features that might cease functioning.
* **Side Effects**: Secondary consequences (e.g. crashes from missing classes).
* **Target Scopes**: Expected changes in Manifest, DEX, Resources, Assets, or Native files.
* **Rebuild & Re-sign Requirements**: Flags indicating whether APK recompilation or re-signing will be required in Phase 7.

---

## 8. Dependencies & Companions

Complex changes often have prerequisites or companion changes:
* **Required Dependency**: A change that must precede or accompany this one (e.g. removing SDK initialization ContentProvider before stripping SDK classes).
* **Recommended Companion**: A beneficial companion change (e.g. removing associated network security config domains when stripping an SDK).

The `DependencyAnalyzer` detects companion requirements and computes a valid topological execution order.

---

## 9. Conflict Detection

When multiple rules or analysis engines propose contradictory actions, the `ConflictDetector` identifies the contradiction structurally rather than silently guessing:
* `TARGET_CONFLICT`: Two changes alter the exact same component in conflicting ways (e.g. `REMOVE_COMPONENT` vs `MODIFY_COMPONENT`).
* `OPERATION_CONFLICT`: Contradictory modifications proposed on the same attribute.
* `DEPENDENCY_CONFLICT`: Cyclic or unsatisfied dependencies.

Every conflict includes a human-actionable `resolution_advice`.

---

## 10. Reversibility & Validation

Each planned change documents its reversibility:
* `REVERSIBLE`: Manifest toggles, attribute edits, resource deletions with backups.
* `PARTIALLY_REVERSIBLE`: Complex bytecode patches where exact original code state is lost.
* `NOT_REVERSIBLE`: Irreversible destructive operations.

Every planned change includes step-by-step verification instructions (`validation_steps`) instructing future Phase 7 testers and automated suites how to verify the modification.

---

## 11. Plan Staleness & Determinism

### Staleness Checks
Plans are permanently bound to the source APK's cryptographic hash (`source_sha256`). If the APK on disk changes, the plan evaluates to `is_stale() == True` and updates status to `PlanStatus.STALE`, preventing accidental modification of modified files.

### Determinism
For the same input APK, analysis results, and planner version:
* Change IDs are sequential (`CHANGE-001`, `CHANGE-002`, ...).
* Plan ID is a deterministic hash of sorted change keys.
* Changes are topologically and lexicographically sorted.

---

## 12. Serialization (JSON & YAML)

Plans serialize losslessly to both JSON and YAML formats:

```bash
# Save to JSON or YAML via CLI
apkforge plan app.apk --json > plan.json
apkforge plan app.apk --yaml > plan.yaml
apkforge plan app.apk --output plan.yaml
```

Python API:
```python
from apkforge.modification import (
    plan_to_json,
    plan_from_json,
    plan_to_yaml,
    plan_from_yaml,
    save_plan,
    load_plan,
)

# Convert to string
yaml_text = plan_to_yaml(plan)

# Save to disk
save_plan(plan, Path("mod_plan.yaml"), format="yaml")

# Load and verify
loaded_plan = load_plan(Path("mod_plan.yaml"))
assert not loaded_plan.is_stale(current_apk_sha256)
```

---

## 13. CLI Usage

### Basic Plan Generation
```bash
apkforge plan app.apk
```

### Filtering Proposals
```bash
apkforge plan app.apk --type permission
apkforge plan app.apk --type tracker
apkforge plan app.apk --risk high
```

### Incorporating Diff Analysis
```bash
apkforge plan modified.apk --diff original.apk
```

---

## 14. Safety & Invariants

* **No Code Execution**: APKForge never executes APK code, DEX bytecode, or native binaries.
* **No In-Place Modification**: The source APK is never opened for write access.
* **No Network Requests**: All planning decisions are made locally from static analysis.
* **No Implicit Approvals**: All generated plans require explicit review (`REVIEW_REQUIRED`).
