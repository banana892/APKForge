# Phase H.7 — Third-Party ModKit Integration Framework

> **Scope of every claim below.** H.7 is infrastructure only: a generic, controlled
> boundary through which APKForge drives an external APK modification engine (a "ModKit").
> No third-party ModKit is integrated, bundled or executed. The only ModKit exercised is
> APKForge's own deterministic reference `test-modkit`. A SUCCESS result establishes that a
> ModKit's output passed APKForge's validation and was published with provenance. It does
> **not** establish that the ModKit's transformation is semantically safe.

Validation run: `20261006T185420Z` (`build-tests/run_phase_h7_validation.py all --write`).
Evidence is in `h7-framework-summary.json`, `h7-pipeline-summary.json`,
`h7-corpus-summary.json` and `h7-validation-summary.md`. The design is documented in
`docs/modkits.md`.

## 1. Objective

Create the generic integration framework that H.8 will use for the first real adapter
(Morphe Patcher). APKForge owns the lifecycle: input isolation, SHA-256 provenance,
workspace, process execution, failure handling, independent output validation, and the
hand-off to the existing diff, privacy/security, build/sign and H.4 verification
infrastructure. The ModKit only transforms.

## 2. Architecture

```text
ModKitManager  (registry, deterministic discovery, TOML configuration)
  -> ModKitExecutor
       availability (AVAILABLE only if executable + dependencies + supported version)
       -> request/input validation (operation, typed parameters, capabilities, APK)
       -> SHA-256/size/path of the original
       -> fresh ModKitWorkspace: input/ working/ output/ logs/ metadata/
       -> staged read-only copy, re-hashed (STAGING_MISMATCH on difference)
       -> adapter.prepare -> adapter.execute (exactly once; no retry)
            ExternalProcessAdapter -> ModKitProcessRunner: argv only, shell=False,
            scrubbed environment, own process group, timeout, bounded logs, masking
       -> original + staged input re-hashed (ORIGINAL_MUTATED / INPUT_MUTATED)
       -> adapter.collect_output (a claim) -> validate_output (independent)
       -> publish: copy + SHA verify + no-overwrite link, APKForge-chosen name
       -> ProvenanceRecord -> adapter.cleanup (always) -> retention
  -> ModKitPostAnalysis (existing engines only)
       DiffEngine (Phase E) | PrivacyAnalysisService + SecurityEngine before/after
       | BuildService (unchanged) | TransformationVerifier.verify_external (H.4)
```

The only change outside `apkforge.modkit` and the CLI is in H.4: the additive
`TransformationVerifier.verify_external` and a `mode` keyword on its private `_verify`.
Existing `verify` and `verify_noop` behaviour is unchanged.

## 3. Deliverables

| Requirement | Implementation |
|---|---|
| Package | `src/apkforge/modkit/` (models, contract, config, manager, executor, workspace, process, validation, masking, analysis, testing/) |
| Contract | `ModKitAdapter`: id, name, version, adapter_version, description, capabilities(), operations(), requirements(), availability(), validate_input(), prepare(), execute(), collect_output(), cleanup(), toolchain() |
| External CLI / library | `ExternalProcessAdapter` (argv builder); library adapters subclass `ModKitAdapter` (unit-tested in-process adapter) |
| Identity | `modkit_id` / `display_name` / `installed_version` / `adapter_version` kept separate |
| Capabilities | `ModKitCapability`; operation capabilities must be a subset of verified capabilities (enforced) |
| Availability | AVAILABLE, NOT_INSTALLED, VERSION_UNSUPPORTED, DEPENDENCY_MISSING, CONFIGURATION_INVALID, EXECUTION_UNAVAILABLE, UNKNOWN |
| Requirements | `Requirement` / `RequirementCheck` (EXECUTABLE, RUNTIME, MIN/MAX_VERSION, ANDROID_SDK, BUILD_TOOLS, ENVIRONMENT, FILESYSTEM, OTHER) |
| Installation | USER_MANAGED (reference), APKFORGE_MANAGED (reserved), BUNDLED (own test fixture only); nothing is downloaded |
| Configuration | TOML (`--config`, `$APKFORGE_MODKIT_CONFIG`, XDG); validated; structured `ConfigIssue`; secrets rejected |
| Discovery | `ModKitManager.discover()/list()/get()/info()`; sorted; config alone never makes a ModKit available |
| CLI | `apkforge modkits`, `apkforge modkit info`, `apkforge modkit run` (`--json` ANSI-free, `--verbose`), trust shown separately from status |
| Results | `ModKitResultStatus` (12 states) + `FailureCategory` (28 categories) |
| Provenance | `ProvenanceRecord` + masked `CommandRecord`, written to `metadata/provenance.json` |
| Reference ModKit | `modkit/testing/tool.py` (standalone external process) + `TestModKitAdapter`, 24 scenarios, TEST_ONLY |
| Docs | `docs/modkits.md` (new), `docs/transformation.md`, `docs/architecture.md` |

## 4. Reference ModKit scenario matrix (framework run)

Each scenario is a real external process run on a synthetic APK. For every scenario the
original APK's SHA-256 is unchanged, and an APK is published only on SUCCESS.

| Scenario | Status | Failure |
|---|---|---|
| success | SUCCESS | - |
| noop (declared) | NO_OP | - |
| noop-empty (declared, no file) | NO_OP | - |
| noop-undeclared (identical output, change expected) | OUTPUT_INVALID | OUTPUT_UNCHANGED |
| missing-output | OUTPUT_MISSING | OUTPUT_MISSING |
| no-declaration | OUTPUT_INVALID | UNEXPECTED_ARTIFACT |
| invalid-apk (exit 0, not a ZIP) | OUTPUT_INVALID | OUTPUT_MALFORMED |
| truncated-apk | OUTPUT_INVALID | OUTPUT_MALFORMED |
| nonzero-exit | EXECUTION_FAILED | NON_ZERO_EXIT |
| timeout (2 s) | TIMEOUT | TIMEOUT |
| crash (SIGSEGV) | EXECUTION_FAILED | PROCESS_CRASH |
| multiple-outputs | OUTPUT_INVALID | OUTPUT_AMBIGUOUS |
| extra-artifact | OUTPUT_INVALID | UNEXPECTED_ARTIFACT |
| outside-workspace (`../escaped.apk`) | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE |
| outside-undeclared | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE |
| symlink-escape | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE |
| malicious-filename (`evil;$(touch pwned)\n.apk`) | OUTPUT_INVALID | UNSAFE_FILENAME |
| traversal-entry (zip-slip entry) | OUTPUT_INVALID | OUTPUT_MALFORMED |
| directory-output | OUTPUT_INVALID | OUTPUT_NOT_REGULAR_FILE |
| mutate-input (chmod + append to staged input) | EXECUTION_FAILED | INPUT_MUTATED |
| noisy (4000 ANSI lines) | SUCCESS | - |
| echo-env | SUCCESS | - |
| echo-args | SUCCESS | - |
| replace-output-dir (output/ → symlink) | OUTPUT_INVALID | OUTPUT_OUTSIDE_WORKSPACE |

Unit tests additionally cover:

- **Request and input validation:** unknown operation or parameter, a bad choice, shell
  metacharacters and newlines in a pattern-checked parameter, an unoffered capability, an
  unsafe `output_name`, a non-APK input, an APK without a manifest, a missing input, a
  directory input, and refusal to overwrite.
- **Availability gating:** dependency missing gives DEPENDENCY_ERROR; a configuration issue
  gives CONFIGURATION_ERROR; not installed, disabled or version mismatch gives
  NOT_AVAILABLE. No workspace is created in any of these cases.
- **Adapter faults (library adapter):** an exception in `execute` gives
  EXECUTION_FAILED/ADAPTER_ERROR; in `collect_output` it gives OUTPUT_INVALID/ADAPTER_ERROR;
  in `cleanup` it is recorded and does not change the result. An adapter that writes to
  the original gives ORIGINAL_MUTATED. `cleanup` runs exactly once in every case.
- **Resource limit:** a stdout/stderr overflow gives RESOURCE_LIMIT.
- **No retry:** three failing executions give exactly three `execute` calls.

## 5. Security and path tests

| Check | Result |
|---|---|
| Shell injection: `$(touch PWNED_A); \`touch PWNED_B\` && touch PWNED_C` passed as a parameter | passed literally as one argv element; no `PWNED*` file anywhere |
| Malicious output filename | rejected (UNSAFE_FILENAME); no `pwned` file created |
| Path traversal: declared `../escaped.apk`, undeclared write to the workspace root, zip-slip entry, workspace ids `../x`, `a/b`, `subpath("..")` | all rejected |
| Symlink escape: output symlink to outside, `output/` replaced by a symlink | rejected (OUTPUT_OUTSIDE_WORKSPACE) |
| Environment leakage: parent `APKFORGE_KEYSTORE_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `H7_PARENT_TOKEN`, unrelated variables | none reach the child; child env keys = `HOME, LANG, PATH, TMPDIR` (+ configured non-secret variables) |
| Secret masking: sensitive parameter echoed by the tool to stdout and stderr | 0 occurrences in logs, metadata, provenance or result JSON; `masked_arguments=1`; logs contain `********` |
| `SecretMasker`: `--password X`, `--ks-pass=X`, `token=X`, embedded known secret, sensitive env names | masked |
| Malformed configuration: relative path, secret-looking env/option names, reserved env (`PATH`, `LD_PRELOAD`), control characters, unknown keys, bad ids, bad types, TOML syntax error, symlinked config file, missing explicit file | structured `ConfigIssue`s; the ModKit is CONFIGURATION_INVALID and is never probed |
| Input mutation (tool chmods and appends to its staged input) | INPUT_MUTATED; the original is untouched (it is never handed to the tool) |
| Unexpected extra artifacts | UNEXPECTED_ARTIFACT |
| `shell=True` | never used (`grep -rn "shell=True" src/apkforge/modkit` gives nothing) |

## 6. Workspace isolation, output validation, provenance

**Workspace isolation**

- Each execution gets a fresh `mk-<UTC>-<random>` directory, created with
  `exist_ok=False` and never reused.
- The layout is `input/ working/ output/ logs/ metadata/`.
- The staged input is mode `0444` and is re-hashed after staging.
- The ModKit's cwd is `working/`; `HOME` and `TMPDIR` point inside `working/`.
- Retention: a failure keeps the workspace whole (`keep_on_failure`). Otherwise only
  `logs/` and `metadata/` remain. `--keep-workspace` keeps everything.

**Output validation**

- The checks in `docs/modkits.md` § Output validation are applied independently of the
  adapter's claim.
- The published name is chosen by APKForge (`<input stem>.<modkit_id>.apk`).
- The published copy is re-hashed and linked without overwrite.
- Nothing is published unless the status is SUCCESS.

**Provenance**

- Recorded fields: modkit id/version, adapter version, APKForge version, execution id,
  operation, capabilities, masked parameters, input/output SHA-256 and size, start/end
  time, exit code, toolchain (Python, platform, adapter dependencies), workspace id/path,
  and the masked command (executable, argv, cwd, child environment, masked names/count).

**Reproducibility**

- Two runs with identical input, configuration, tool version and parameters give
  byte-identical output APKs (`f855557d…`).
- Their provenance is identical except for the execution id, timestamps and workspace
  paths.

## 7. Pipeline integration (real toolchain)

The input A is the published `h3_isolated` fixture: signed v2/v3-only with a publisher key
and round-tripped once.

| Step | Result |
|---|---|
| test-modkit on A | SUCCESS; `assets/test-modkit/marker.txt` added |
| Phase E DiffEngine A → output | `files_added = 1`, nothing else |
| Phase F privacy before/after | +0 introduced, −0 removed |
| Phase B security before/after | +0 introduced, −0 removed |
| BuildService no-op rebuild of the ModKit output (C) and of A (control B) | both build and sign; output fed in as an ordinary APK, no ModKit-specific signing |
| H.4 `verify_external(A, B, C)`, change undeclared | **FAILED**: exactly one UNEXPECTED_CHANGE (`assets/test-modkit/marker.txt`) |
| H.4 `verify_external(A, B, C)`, marker declared | **VERIFIED**: 1 expected change, 7 noise differences reproduced by the control |
| Original A | SHA-256 unchanged |

Corpus (test-modkit `success` on the 9 corpus APKs, including Fennec, NewPipe and
AppManager): all 9 are SUCCESS, the marker is present, output validation passes on real
multi-DEX/native APKs, and every corpus SHA-256 is unchanged.

## 8. Tests

| Suite | Tests |
|---|---|
| `tests/unit/test_modkit_framework.py` | 126 |
| `tests/integration/test_phase_h7_modkit.py` | 6 (3 need the build toolchain) |

Breakdown of the 126 unit tests:

| Area | Tests |
|---|---|
| Models and contract | 11 |
| Configuration | 14 |
| Availability | 12 |
| Discovery | 6 |
| Scenarios (23 + matrix completeness) | 24 |
| Success/no-op/timeout/no-retry/noise/limits | 8 |
| Request/input/availability gating | 15 |
| Workspace | 6 |
| Library adapters | 5 |
| Security | 17 |
| Reproducibility, provenance, independent ModKits | 3 |
| Finding comparison | 1 |
| CLI | 4 |

## 9. Regression

Regression was run in three lanes (`work/h7-regression/lanes.sh`). Output went to `work/`;
no committed artifact was rewritten. Every run exited 0.

| Suite | Result | Compared with the H.6 regression run |
|---|---|---|
| Full pytest | **1487 passed, 10 skipped** (14 min 18 s) | 1353 (H.6) + 2 (`732d134` fix) + 132 (H.7) |
| Phase D (`run_phase_d_validation.py`) | A–C verified, D/F failed, E dry_run: all as expected | identical |
| Phase E baseline (9 corpus APKs) | all VERIFIED | identical |
| Phase E OpenLink scenarios (A–K3) | PASS | scenario table identical line for line |
| Phase F corpus (`--output-dir` under `work/`) | completed | findings identical; summary identical except timings and commit; per-APK JSON equal order-insensitively (known Androguard ordering noise) |
| Phase G (artifact dirs redirected under `work/`) | completed | identical except timings |
| H.1 `all` | PASS | identical |
| H.2 `all` | PASS (corpus: 0 plans, by design) | identical |
| H.3 `all` | PASS (corpus: 0 applied) | identical |
| H.4 `all` | PASS (synthetic matrix; corpus VERIFIED_WITH_LIMITATIONS, Fennec UNKNOWN) | identical |
| H.5 `all` | PASS (corpus: 0 eligible) | identical |
| H.6 `all` | PASS | identical |
| H.7 `all` | PASS | new |

| Check | Result |
|---|---|
| ruff, touched files | All checks passed (new package, tests, runner, `cli/main.py`, `verifier.py`) |
| ruff, repository | 517 pre-existing errors; none in H.7 files |
| ruff format, touched files | Clean |
| ruff format, repository | 56 pre-existing files; none of them H.7 files |
| mypy `src/apkforge` | 102 errors in 9 files, identical to the baseline (per file: `cli/main.py` 20, `inspection/manifest.py` 62, …); 0 in `apkforge.modkit` |

## 10. Files changed

New:

- `src/apkforge/modkit/{__init__,models,contract,config,manager,executor,workspace,process,validation,masking,analysis}.py`
- `src/apkforge/modkit/testing/{__init__,adapter,tool}.py`
- `tests/unit/test_modkit_framework.py`
- `tests/integration/test_phase_h7_modkit.py`
- `build-tests/run_phase_h7_validation.py`
- `docs/modkits.md`
- `artifacts/phase-h/H7-MODKIT-FRAMEWORK.md`
- `artifacts/phase-h/h7-{framework,pipeline,corpus}-summary.json`
- `artifacts/phase-h/h7-validation-summary.md`

Modified:

- `src/apkforge/cli/main.py` — `modkits`, `modkit info|run`; additive only.
- `src/apkforge/transformation/verifier.py` — `verify_external`, and a `mode` keyword on
  `_verify`.
- `src/apkforge/transformation/verification.py` — comment on `mode` values.
- `docs/transformation.md` and `docs/architecture.md` — H.7 sections.

No historical artifact was modified.

## 11. Known limitations

- **No OS-level sandbox.** A ModKit runs with the user's privileges. Writes outside the
  workspace through absolute paths (for example `/tmp`, `$HOME`) and network access are
  neither observed nor prevented. Validation catches writes into the workspace root and
  `input/`. Container or namespace isolation is future work.
- A process that leaves its process group (double fork plus `setsid`) can outlive the
  timeout kill.
- Publishing relies on hard links (atomic and no-overwrite). On a filesystem without hard
  links it fails as PUBLISH_FAILED instead of falling back.
- Masking covers values the adapter declares sensitive, credential-like names and inline
  `name=value` forms. A secret the adapter does not declare, passed under an innocuous
  option name, cannot be recognised.
- Output validation is structural (archive, boundaries, declarations). Semantic assessment
  is the job of the post-analysis hooks (diff, Phase F/B, H.4). The ModKit's expected
  changes must be declared by the caller, because there is no H.2 plan for a ModKit.
- Only USER_MANAGED installation is implemented. APKFORGE_MANAGED is reserved.
- Composition, ordering and conflict resolution between ModKits are not implemented
  (H.9/H.10). Results are independent by construction.

## 12. Boundaries confirmed

- No third-party ModKit is bundled or redistributed: no binaries, JARs, patches or
  third-party source are in the repository.
- No Morphe dependency, invocation, arguments, patch names or classes exist. Morphe
  integration remains H.8. The only Morphe mentions are documentation of that plan and a
  test asserting that no `morphe` adapter is registered.
- Nothing is downloaded or installed automatically, and failed ModKits are never retried.
