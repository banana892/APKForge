# Modification framework (Phase D)

Phase D generalises the C.5 controlled modification into a framework that any modifier
can use. It does not add new real-world modifications. It ships two modifiers: the C.5
boot-receiver modification and a test-only marker modifier. Tracker, ad, malware and
permission-minimisation work, ReVanced, smali editing and the GUI are later phases.

A `VERIFIED` result says that the planned change was made, that nothing else changed
beyond the noise this APK's no-op rebuild produces, and that the APK is aligned and
signed. It does **not** say that the APK is safe, free of malware or spyware, or that
it behaves correctly at runtime. Modified APKs are never installed or run.

| module | role |
|---|---|
| `apkforge/modification/contract.py` | modifier contract: `APKModifier`, `ModifierInfo`, `ModifierPlan`, `Precondition`, `PlanTarget`, `PlannedFileChange`, `ProjectContext`, `ApplyOutcome`, `VerificationOutcome` |
| `apkforge/modification/catalog.py` | `ModifierCatalog`: registry keyed by modifier id; `default_catalog()` |
| `apkforge/modification/pipeline.py` | `ModificationPipeline`: ordering, planning, conflicts, apply, source check, rollback, build, diff, verification, aggregate result |
| `apkforge/modification/edits.py` | structural manifest edits (`SourceEdit`, `manifest_edits`), shared with C.5 |
| `apkforge/modification/builtin/` | `BootReceiverModifier` (C.5 adapter), `MarkerAssetModifier` (test only) |
| `apkforge/modification/controlled.py` | `run_disable_boot_receiver`: the C.5 entry point, now a wrapper around the pipeline |

## Lifecycle

```
original APK (never written; SHA-256 checked at every checkpoint)
  -> baseline inspection (InspectionEngine, manifest)
  -> noise floor: this APK's entry in the semantic no-op baseline
  -> BuildService.prepare_workspace() -> decode()
  -> for each modifier, in request order:  inspect -> plan (+ preconditions)
  -> plan validation, conflict detection                 [checkpoint: planning]
  -> dry run stops here
  -> for each ready modifier:  re-plan -> apply -> source check   [checkpoint: apply <id>]
       on failure: roll back every applied modifier; later ones are not attempted
  -> BuildService.build() -> align() -> sign() -> verify()        [checkpoint: build pipeline]
  -> DiffEngine.diff(original, rebuilt)
  -> verify_expectations(diff, all expected changes, noise floor)
  -> per modifier: expected changes observed?  modifier.verify()   [checkpoint: diff]
  -> optional export of the rebuilt APK
  -> aggregate result
```

### Who does what

| component | responsible for | never does |
|---|---|---|
| modifier | what should change, how to edit the decoded files, how to check the result | run tools, touch the original, build, sign |
| `ModificationPipeline` | which modifiers run and in what order, conflicts, source checks, rollback, aggregation | edit files itself, run subprocesses |
| `BuildService` | workspace, decode, build, align, sign, APK verification | decide what changes |
| `InspectionEngine` / DiffEngine | what is present; what differs | judge whether a difference was intended |
| `verify_expectations` | whether each difference was expected, rebuild noise, unexpected or unknown | weaken a failure into a warning |

The pipeline module contains no subprocess call. Every tool runs through BuildService
with its controlled argument lists.

## Modifier contract

A modifier subclasses `APKModifier`:

```python
class MarkerAssetModifier(APKModifier):
    id = "test.marker_asset"          # stable, unique in a catalog
    name = "Add marker asset (test only)"
    description = "..."
    version = "1"
    risk = ModificationRisk.LOW         # existing planner risk model
    supported_conditions = [...]        # when it applies
    prerequisites = [...]
    parameters = {"name": "..."}        # accepted parameters; others are rejected
    test_only = True

    def inspect(self, project) -> dict: ...                 # read-only findings
    def plan(self, project, findings, parameters) -> ModifierPlan: ...
    def apply(self, plan, project) -> ApplyOutcome: ...     # edit decoded files only
    def verify(self, plan, evidence) -> VerificationOutcome: ...   # optional
```

`ModifierInfo` (`modifier.info()`) carries the metadata. `verification_available` is
derived: it is true only when the class overrides `verify`.

`ProjectContext` is the modifier's only view of the APK: `decoded_dir` (inside the
BuildService workspace), `manifest_text()`, `package()`, the original's path and
SHA-256, and the baseline inspection summary. `project.path(rel)` resolves a relative
path and rejects absolute paths, `..`, empty components, backslashes, NUL bytes and
symlink escapes (`validate_relative_path`).

### Plans

`ModifierPlan` is machine-readable and is the source of truth for every later check:

| field | meaning | checked by |
|---|---|---|
| `target_apk`, `target_sha256`, `package` | which APK the plan is for | plan validation (SHA-256 must match) |
| `preconditions` | name, satisfied, expected, actual, reason | readiness |
| `readiness`, `refusal_code`, `problems` | `ready` or `precondition_failed`, with a modifier-specific code | step status `SKIPPED` |
| `targets` | `kind` + `identifier` + `access` (`add`/`modify`/`remove`/`read`) | conflict detection |
| `changes` | the intended changes in words | report |
| `file_changes` | decoded files to `add`/`modify`/`remove` | source check, rollback |
| `manifest_edits` | exact structural manifest edits | source check |
| `expected_changes` | DiffEngine observations the rebuilt APK must show | expected-vs-actual |
| `verification` | what `verify()` checks | report |
| `consequences`, `warnings`, `limitations` | declared side effects and limits | report |
| `details` | modifier-specific payload (C.5 stores its native `BootReceiverPlan`) | the modifier |

Example (OpenLink, C.5 modifier, abbreviated):

```
modifier_id: c5.disable_boot_receiver        readiness: ready
preconditions:
  permission_declared_once  expected: exactly one <uses-permission> for ...RECEIVE_BOOT_COMPLETED
                            actual:   ...declarations: ['uses-permission']
  boot_receiver_identified  expected: exactly one boot receiver, or the requested one
                            actual:   boot receivers: [...PackageChangeBroadcastReceiver]; ...
  receiver_currently_enabled expected: android:enabled is true or absent   actual: 'true'
targets:   remove permission RECEIVE_BOOT_COMPLETED
           modify component de.audioattack.openlink.conf.PackageChangeBroadcastReceiver
file_changes:     modify AndroidManifest.xml
manifest_edits:   remove_element manifest/uses-permission[name=...RECEIVE_BOOT_COMPLETED]
                  set_attribute  manifest/application[0]/receiver[name=...] android:enabled true -> false
expected_changes: uses_permission removed ...RECEIVE_BOOT_COMPLETED
                  component modified ...PackageChangeBroadcastReceiver {component_type: receiver, enabled: [True, False]}
consequences:     the receiver also handles MY_PACKAGE_REPLACED; disabling it stops those broadcasts too
```

### Preconditions

`plan.require(name, satisfied, expected=..., actual=..., reason=...)` records a
precondition. An unsatisfied one makes the plan `precondition_failed`, and the step
becomes `SKIPPED` with the refusal code and reasons. A skipped modifier never applies a
partial change. The marker modifier checks:

- `valid_name`: the parameter is a plain file name;
- `apktool_project`: `apktool.yml` is present;
- `marker_absent`: the marker does not already exist.

The C.5 modifier maps its existing preconditions and adds the expected state for each.

Toolchain availability is checked before the run (`BuildService.check_toolchain()` in
the CLI). A decode failure stops the run before any modifier is planned.

### Planning is non-destructive

Planning reads the decoded copy inside the BuildService workspace. The pipeline
hashes the whole decoded project before and after planning. A plan that wrote anything
fails the run (`planning modified the decoded project`). The original APK's SHA-256 is
checked after planning. A dry run never applies, builds or exports anything. Its
workspace is removed unless `keep_workspace` is set.

Plan validation rejects a plan that names another modifier, was made for another
SHA-256, lists an unsafe or duplicate path, declares manifest edits without declaring
`AndroidManifest.xml`, or is ready but declares no file. Such a step is `FAILED`
(`Invalid plan: ...`).

## Execution

### Apply and the source check

Ready modifiers run one at a time, in request order. For each:

1. **Re-plan.** The modifier plans again against the current project. Its targets, file
   changes, manifest edits and expected changes must equal the original plan.
   Otherwise an earlier modifier changed what this one would do, and the step fails
   (`Plan changed after earlier modifications were applied`).
2. **Backup.** The bytes of every declared file are recorded (or its absence).
3. **Apply.** An exception is a `FAILED` step that keeps the exception type.
   `applied=False` is also a `FAILED` step.
4. **Source check.** The framework hashes the decoded project again and compares the
   result with the plan. This is independent of the modifier's own claims:
   - the files that were actually added, modified or removed must equal `file_changes`
     exactly. Unplanned or missing changes fail the step;
   - a new symlink fails the step;
   - if the manifest changed, `manifest_edits(before, after)` must equal
     `plan.manifest_edits` exactly. This covers every element and attribute, including
     content that DiffEngine does not compare (`<queries>`, `<meta-data>`).
5. The original's SHA-256 is checked (`apply <id>`).

### Rollback

When a step fails, every modifier applied so far, including the failing one, is undone
in reverse order:

- declared files are restored from the backup, or deleted if they did not exist;
- unplanned new files are deleted;
- unplanned modifications or removals of existing files cannot be restored, because no
  backup exists. This is reported as a rollback failure.

After each undo the project is hashed again. `rolled_back=True` is set only when the
project equals its state before that modifier and the modifier had changed something.
`result.rollback` records `attempted`, `restored` (the whole project equals its pre-apply
state), the modifiers undone, and any errors. Later modifiers are `PENDING`
("Not attempted: execution stopped at <id>"). Nothing is built.

Rollback applies to the decoded project in the workspace. Discarding a workspace is
cleanup, not rollback, and is never reported as rollback. A failure in the build,
APK verification or diff does not roll back: the workspace is the evidence
(`keep_workspace=True` keeps it).

### Build (BuildService)

After every ready modifier is applied, BuildService builds, aligns, signs and verifies
the decoded project once. That is one build for the combined change. Each stage's
`StageResult` is summarised in `result.stages`. Any failure stops the run as `FAILED`:

- `build_passed=False` for a build, align or sign failure;
- `apk_verified=False` for a verify failure.

The failure is recorded as `<stage>: <category>: <cause>`. The modifier steps keep their
`SUCCESS` status, because their changes were applied to the source, but they stay
*not verified*. The overall result is never a success.

### APK verification vs modification verification

These are separate questions and are reported separately:

| question | answered by | recorded as |
|---|---|---|
| Is the rebuilt APK aligned, validly signed by the expected signer, and a sound ZIP? | BuildService `verify` | `apk_verified`, `verification` |
| Did the intended modification happen? | the modifier's `verify()` on the rebuilt APK and its re-analysis, plus its expected changes being observed | per step `verified`, `verification`, `expected_observed`/`expected_missing` |

A step's `verified` is:

- `True`: `verify()` ran and passed, and every expected change of that modifier was
  observed;
- `False`: `verify()` failed or raised, or an expected change is missing. The step
  becomes `VERIFICATION_FAILED`;
- `None` (*not verified*): the step was not executed, or the modifier has no `verify()`.
  A diff that shows the expected change does not replace modifier verification.

C.5 `verify()` checks the re-analysis of the rebuilt APK: `RECEIVE_BOOT_COMPLETED` was
removed, and the receiver's `enabled_after` is `False`. The marker `verify()` opens the
rebuilt APK and compares the asset's bytes.

### Expected vs actual

All expected changes of the executed modifiers are passed together to
`verify_expectations` (see `controlled-modification.md`). Each observation is classified
`expected_modification`, `rebuild_noise` (only the rules seen in this APK's no-op
baseline, plus its recorded residue), `unexpected` or `unknown`. Any `unexpected` or
`unknown` observation, a missing expected change, an incomplete diff, or a diff
limitation or error is a failure (`semantic: ...`). Nothing is downgraded. The diff
engine and the noise rules are unchanged by Phase D.

A missing noise floor (no usable baseline entry for this APK's SHA-256) is recorded as a
failure, exactly as in C.5. As in C.5, it does not change a `skipped` or `refused` result,
where nothing was built. For APKs outside the corpus, the CLI can measure the noise
floor first with one unmodified round trip (`--measure-noise-floor`, which uses
`measure_noise_floor()` and `run_semantic_noop`). Only an `EQUIVALENT` or
`EQUIVALENT_WITH_RESIDUE` result establishes a noise floor.

Limitation: a modifier can only state what DiffEngine can observe. Changes to
`resources.arsc` entries and recompiled resource content cannot be expressed as expected
changes; they are covered only by the source check before the build.

**Phase E** (see `verification.md`): with a schema-2 baseline the classification is
content-aware (noise must be byte-identical to this APK's no-op rebuild with the same
toolchain), the manifest is compared as a full tree (so `<meta-data>`, `<queries>`,
`<activity-alias>` and every attribute can be declared as `manifest_element` expected
changes, and are unexpected when undeclared), the compiled entries a plan edits are
`planned_entry` observations, and every run gets a `VerificationMatrix` and a
`VerificationReport`. A baseline for another toolchain is `BASELINE_INCOMPATIBLE`
(failure: noise floor not established); a schema-1 baseline is legacy and the run cannot
be `verified`.

## Status semantics

Step status (`ModificationStepResult`, shared with the legacy framework):

| status | meaning |
|---|---|
| `PENDING` | not attempted: an earlier failure, a conflict, a refusal, or a failed stage |
| `DRY_RUN` | planned and ready; would be applied |
| `SKIPPED` | preconditions not met; nothing was changed. Never a success |
| `SUCCESS` | applied and passed the source check. Whether it is *verified* is a separate field |
| `FAILED` | planning, plan validation, re-planning, apply or the source check failed |
| `VERIFICATION_FAILED` | applied, but `verify()` failed or an expected change was not observed |

Overall status (`PipelineStatus`), in order of precedence:

| status | when | CLI exit |
|---|---|---|
| `failed` | any step failed or failed verification, any stage or check failed, a rollback failed, or the original changed | 1 |
| `refused` | ready plans conflict, or some modifier was skipped and `allow_partial` is off; nothing was applied | 3 |
| `skipped` | every modifier was skipped | 3 |
| `dry_run` | dry run, every modifier ready | 0 |
| `partial` | `allow_partial`: the ready modifiers completed, others were skipped | 3 |
| `unverified` | everything passed, but at least one modifier has no verification, or the Phase E verification matrix is `UNDETERMINED` (e.g. legacy baseline, partial comparator) | 3 |
| `verified` | every modifier applied and verified, APK verified, diff as planned, original unchanged | 0 |

`result.counts()` reports requested, planned, executed, dry_run, skipped, failed,
verified, verification_failed, not_verified, not_attempted and rolled_back.
`result.execution()` returns the steps as a legacy `ModificationResult`, so
`aggregate_status()` and its counters apply unchanged.

## Multiple modifiers, ordering and conflicts

**Order** is the request order (the order of `-m` options), recorded in `result.order`.
Nothing depends on filesystem, registration or dictionary order. The catalog lists
modifiers sorted by id. Requesting the same modifier twice is an error.

**Conflicts** are detected between ready plans before anything is applied. Each is
reported with its kind, both modifiers in request order, the subject and a reason. Any
conflict makes the run `refused`:

- `target`: both plans name the same `kind:identifier` and at least one writes it. For
  example, A modifies `component:X` and B removes `component:X`, or A reads `resource:Y`
  (expects it unchanged) and B modifies it;
- `file`: both touch the same file and not both only modify it. Two manifest modifiers
  may share `AndroidManifest.xml`; their targets decide;
- `expected_change`: both expect an observation for the same category and identifier,
  so the result could not be attributed to one of them.

There is no semantic conflict solver. Interactions that targets do not reveal are caught
when a later modifier is re-planned (see Apply), or by the source check.

**Partial execution** is off by default. If any modifier is skipped, the others are not
applied (`refused`). With `allow_partial` the ready ones run and the result is `partial`.

## The two built-in modifiers

**`c5.disable_boot_receiver`** is the C.5 modification, unchanged. `discover`,
`plan_disable_boot_receiver` and `apply_plan` in `boot_receiver.py` do the work. The
adapter maps them to the contract and adds the post-build `verify()`. Optional parameter:
`receiver` (required when several receivers handle boot actions). The legacy entry point
`run_disable_boot_receiver()` now runs this modifier through the pipeline. It maps the
result back to `ControlledModificationResult`, with `VERIFIED`, `REFUSED` (skipped or
refused) or `FAILED`. The C.5 unit and integration tests pass unchanged against it.

**`test.marker_asset`** (test only) adds a fixed 125-byte text file at
`assets/apkforge-test/marker.txt` (parameter `name` changes the file name). It exists to
show that the framework is generic: a new file instead of manifest edits, its own
preconditions, a `file added` expected change, and a `verify()` that reads the rebuilt
APK. The application does not reference or read the file. The text contains no URLs,
hosts or code. It has no security or privacy purpose.

On OpenLink, both modifiers together verify with 3 expected modifications. The 74 noise
observations are identical, by rule and count, to the C.5 single-modifier run.

## Writing a modifier

1. Subclass `APKModifier` and set `id`, `name`, `description`, `risk` and `parameters`.
2. `inspect()`: read what you need through `project`. Never write.
3. `plan()`: start from `self.new_plan(project, parameters)`, then:
   - call `plan.require(...)` for every precondition;
   - declare `targets`, `file_changes`, `manifest_edits` (if you edit the manifest) and
     `expected_changes` in DiffEngine terms;
   - record consequences and limitations.
4. `apply()`: edit exactly the declared files through `project.path()`. Return
   `ApplyOutcome(applied=False, errors=[...])` instead of raising when you can.
5. `verify()`: check the intended effect on `evidence.output_apk` / `evidence.diff`.
   Without it, the modifier is reported *not verified*.
6. Register it in a `ModifierCatalog`. Add it to `default_catalog()` for the CLI.

## CLI

```bash
source tools/env.sh
apkforge modifiers                      # id, name, description, verification, risk, parameters
apkforge modifiers --json

# plan / dry run: decode, plan, preconditions, conflicts; no modified APK
apkforge modify app.apk -m c5.disable_boot_receiver -m test.marker_asset --dry-run

# execute
apkforge modify app.apk -m c5.disable_boot_receiver \
    --noop-baseline tests/corpus/results/c5-semantic-noop-baseline.json \
    --output out/app-modified.apk --report out/report.json
apkforge modify other.apk -m test.marker_asset --measure-noise-floor   # APK not in the baseline
apkforge modify app.apk -m test.marker_asset --param test.marker_asset:name=m2.txt
apkforge modify app.apk -m A -m B --allow-partial                       # build even if one is skipped
```

Options used with `-m`/`--modifier`:

- `--dry-run`: plan only. It prints the plan: preconditions with expected/actual,
  targets, changes, expected changes and verification;
- `--param ID:KEY=VALUE`, `--allow-partial`, `--output`, `--noop-baseline`,
  `--measure-noise-floor`;
- `--report FILE`: write the full JSON result;
- `--json`: print the result plus `counts` on stdout. Logs go to stderr;
- `--workspace DIR`: the parent for BuildService workspaces;
- `--keep-workspace`: keep the BuildService workspace.

Exit codes: 0 `verified`/`dry_run`, 1 `failed`, 2 invalid request or toolchain
unavailable, 3 `unverified`/`partial`/`skipped`/`refused`. Without `-m`, `modify` keeps
its earlier planner-driven behaviour (`--plan`, `--approve-all`).

## Running the validation

```bash
source tools/env.sh
.venv-validation/bin/python -m pytest -q tests/unit/test_phase_d_*.py          # simulated toolchain
.venv-validation/bin/python -m pytest -q tests/integration/test_phase_d_pipeline.py
.venv-validation/bin/python build-tests/run_phase_d_validation.py [--write]
```

The integration tests and the runner use the real OpenLink APK and the real toolchain.
They cover six scenarios:

- **A**: C.5 alone;
- **B**: the marker alone;
- **C**: both, in one build;
- **D**: marker → failing test modifier → C.5. The marker is rolled back, C.5 is not
  attempted, nothing is built;
- **E**: dry run;
- **F**: a test modifier that adds an undeclared file, which shows as 1 unexpected change
  and fails the run.

`tests/integration/phase_d_modifiers.py` holds the two test-only modifiers used in D
and F.

## Relation to the earlier framework

`ModificationFramework`, the change-type `ModifierRegistry` and the `Modifier` protocol
(`modifiers/base.py`) remain unchanged for planner-driven `apkforge modify --plan`. That
framework applies `PlannedChange` objects to a working copy and never decodes, builds or
verifies an APK. Phase D does not route through it. It reuses that framework's
`StepStatus` and `ModificationStepResult`, so a skipped, unverified or not-attempted step
means the same in both.

## Security boundaries

- The original APK is opened only for hashing, inspection and decoding by BuildService
  (which copies it first). Its SHA-256 is compared after planning, after each apply,
  after the build and after the diff. A mismatch stops the run and makes it `failed`.
- `--output` may not be the original APK.
- Modifier paths go through `ProjectContext.path()`. New symlinks fail the source
  check. BuildService refuses decoded projects that contain symlinks.
- No application code is executed, nothing is installed, and no script embedded in an
  APK is run.
- Modifiers are trusted in-process Python code. The source check and the original's
  hash detect their effects on the decoded project and the original. They do not
  sandbox a modifier that writes elsewhere.
- Signing passwords never appear in results or reports. Results record the signing
  mode only.

## Limitations

- Expected changes cover only what DiffEngine observes. See *Expected vs actual*.
- Conflict detection is explicit and syntactic (targets, files, expected changes).
  Modifiers must name targets consistently (`permission`, `component`, `file`,
  `resource`, `manifest_attribute`).
- Rollback restores declared files and removes unplanned additions. It cannot restore
  unplanned edits to existing files; that is reported as a rollback failure.
- A noise floor exists for the 9 corpus APKs (current toolchain only). Other APKs need
  `--measure-noise-floor`, which costs one extra build.
- Dry runs still decode the APK, so they need the toolchain.
- One build per run. Modifiers cannot inspect the result of an intermediate build.
