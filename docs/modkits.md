# Phase H.7/H.8 — Third-Party ModKit Integration Framework

A **ModKit** is an external APK modification engine — a separately installed command-line
tool or, in future, a library — that APKForge drives through a controlled adapter contract.
H.7 is the generic framework; the only adapter it ships is APKForge's own deterministic
reference `test-modkit`. H.8.1 adds the first real adapter, `morphe` (Morphe Desktop):
discovery and compatibility checking. H.8.2 adds read-only patch bundle discovery
(`apkforge modkit patches morphe --patches ...`). H.8.3 adds the `patch` operation itself
(`apkforge modkit run morphe ... --operation patch -p patches=...`): patch selection and
execution through the normal adapter contract. H.8.4 adds optional keystore-based signing
to that same operation. H.8.5 adds per-patch option pass-through (`-O key=value`).
H.8.6 adds `--with-options` to `apkforge modkit patches` so those per-patch option
keys/types/defaults can be discovered without running Morphe's own CLI directly.
H.8.7 adds the remaining build-tuning flags (`striplibs`/`bytecode_mode`/
`continue_on_error`/`validate`) to the `patch` operation. APKForge never bundles or
downloads Morphe; see "Morphe (H.8)" below.

The rule behind every design decision is that **APKForge owns the lifecycle**. A ModKit is a
transformation provider: it gets a staged copy of the input, an empty output directory and
a deadline. Its output is untrusted until APKForge validates it, and it never touches
APKForge's project state.

```
APKForge
   │  controlled adapter contract (apkforge.modkit.contract)
   ▼
Third-party ModKit  ── reads input/input.apk, writes output/ ──┐
                                                               ▼
                          APKForge validation (apkforge.modkit.validation)
                                                               │  publish (copy + SHA verify)
                                                               ▼
   ├── Diff (Phase E DiffEngine)
   ├── Privacy / security analysis (Phase F / B engines)
   ├── Build / sign (BuildService, unchanged)
   └── H.4 verification (TransformationVerifier.verify_external)
```

## Using it

```bash
apkforge modkits [--json] [--verbose] [--config FILE]       # discovery
apkforge modkit info MODKIT_ID [--json] [--verbose]         # one ModKit in detail
apkforge modkit patches MODKIT_ID --patches BUNDLE \         # H.8.2: list a bundle's patches
    [--package PKG] [--prerelease] [--timeout S] [--json] [--config FILE]
apkforge modkit run MODKIT_ID APP.apk -o OUT_DIR \
    [--operation OP] [-p NAME=VALUE ...] [--timeout S] [--allow-noop] \
    [--work-dir DIR] [--keep-workspace] [--analyze] [--json] [--report FILE]
```

```text
ID              NAME              VERSION       STATUS          TRUST
example-kit     example-kit       --            CONFIGURATION_INVALID  EXTERNAL / UNVERIFIED
test-modkit     Test ModKit       1.0.0         AVAILABLE       TEST ONLY
```

`AVAILABLE` means installed and runnable, **not trusted**. Every view shows a separate trust
label: `EXTERNAL / UNVERIFIED` for third-party ModKits and `TEST ONLY` for the reference
ModKit. APKForge validates outputs, but it cannot guarantee that an arbitrary third-party
transformation is semantically safe, and it reports no "security score".

`--json` output is plain JSON with no ANSI codes. `modkit run` exit codes are 0 for
SUCCESS/NO_OP, 2 for NOT_AVAILABLE, INVALID_INPUT, CONFIGURATION_ERROR or DEPENDENCY_ERROR,
3 for OUTPUT_INVALID/OUTPUT_MISSING, and 1 for EXECUTION_FAILED, TIMEOUT, CANCELLED or
UNKNOWN.

Programmatic use:

```python
from pathlib import Path

from apkforge.modkit import ExecutionRequest, ModKitPostAnalysis, default_manager

manager = default_manager()  # configuration from disk + built-in adapters
for info in manager.discover():  # deterministic, sorted by id
    print(info.identity.modkit_id, info.availability.status)

result = manager.execute(
    "test-modkit",
    ExecutionRequest(
        input_apk=Path("app.apk"),
        output_dir=Path("out"),
        operation="transform",
        parameters={"marker": "hello"},
    ),
)
if result.status == "SUCCESS":
    report = ModKitPostAnalysis().run(result)  # diff + privacy + security before/after
```

## Package layout

| Module | Role |
|---|---|
| `modkit/models.py` | Immutable typed models and enums (schema 1) |
| `modkit/contract.py` | `ModKitAdapter` (the public contract), `ExternalProcessAdapter`, `ExecutionContext` |
| `modkit/config.py` | TOML configuration, validation, structured `ConfigIssue`s |
| `modkit/manager.py` | `ModKitManager`: registry, discovery, `execute` |
| `modkit/executor.py` | `ModKitExecutor`: the lifecycle |
| `modkit/workspace.py` | `ModKitWorkspace`: isolated per-execution directory |
| `modkit/process.py` | `ModKitProcessRunner`: argv-only, scrubbed-environment process execution |
| `modkit/validation.py` | Independent output validation |
| `modkit/masking.py` | Secret masking for arguments, environment and logs |
| `modkit/analysis.py` | Post-ModKit hooks into DiffEngine, Phase F/B and H.4 |
| `modkit/testing/` | Reference `test-modkit` (tool + adapter), test-only |

## The ModKit contract

`ModKitAdapter` is the extension point. Identity is held in class attributes. Everything
else is a method returning typed models:

| Member | Meaning |
|---|---|
| `modkit_id` / `id` | Stable lowercase slug (`test-modkit`; `morphe` in H.8) |
| `display_name` / `name` | Human-readable name |
| `version` | Version the **installed tool** reports (`None` if unknown) |
| `adapter_version` | Version of the **APKForge adapter code** |
| `description`, `installation`, `trust`, `license_note` | Descriptive metadata |
| `capabilities()` | Verified capabilities (see below) |
| `operations()` | Requestable operations: id, capabilities, parameters, input/output types, `may_be_noop` |
| `requirements()` | Declared prerequisites |
| `availability()` | Cached `check_availability()` → `AvailabilityReport` |
| `validate_input(request, op)` | Adapter-specific request checks (the generic ones are done already) |
| `prepare(ctx)` | Optional: write files into `working/` |
| `execute(ctx)` | Run exactly once → `ExecutionOutcome` |
| `collect_output(ctx)` | **Claim** which files in `output/` are the result → `OutputDeclaration` |
| `cleanup(ctx)` | Optional; always called, even after a failure |
| `toolchain()` | Dependency versions for provenance |

The identity fields `modkit_id`, `display_name`, `installed_version` and `adapter_version`
are deliberately separate. One adapter can drive several tool versions, and upgrading the
tool does not change the adapter.

There are two adapter styles, both using the same contract:

- **External CLI** — subclass `ExternalProcessAdapter` and implement `version_argv`,
  `parse_version` and `build_command` (which returns a `CommandSpec` argument vector).
  Override `launcher` for a runtime-hosted tool (for example `[java, -jar, tool.jar]`) and
  `dependency_checks` for runtimes. Availability, version detection and execution come
  from the base class.
- **Library/API** — subclass `ModKitAdapter` directly and implement `execute` in-process,
  returning an `ExecutionOutcome` with `command=None`. The unit tests include such an
  adapter, so the contract does not depend on subprocesses.

The contract is versioned and additive: models are frozen pydantic models, enums are
`StrEnum`s, and new members or optional fields may be added, but existing meanings never
change. Nothing in it is specific to any particular ModKit.

## Capability model

`ModKitCapability`: `DEX_TRANSFORMATION`, `RESOURCE_TRANSFORMATION`,
`MANIFEST_TRANSFORMATION`, `APK_TRANSFORMATION`, `PATCH_SELECTION`, `MULTI_PATCH`.

An adapter reports only capabilities it has **verified**, never what the underlying tool
might be able to do. The manager enforces two rules:

- Every operation's capabilities must be a subset of `capabilities()`. An adapter that
  breaks this is rejected as a contract violation and reported as `EXECUTION_UNAVAILABLE`.
- A request's selected capabilities must be a subset of its operation's capabilities.

`test-modkit` reports `APK_TRANSFORMATION` only.

## Availability model

| Status | Meaning |
|---|---|
| `AVAILABLE` | Executable present, dependencies present, version reported and supported |
| `NOT_INSTALLED` | No executable configured, or the configured path does not exist |
| `VERSION_UNSUPPORTED` | Reported version outside `[min_version, max_version)` |
| `DEPENDENCY_MISSING` | Tool installed, but a runtime/dependency is missing (e.g. Java) |
| `CONFIGURATION_INVALID` | The configuration entry has issues, or no adapter exists for it |
| `EXECUTION_UNAVAILABLE` | Disabled, not executable/readable, cannot report its version, or adapter contract violation |
| `UNKNOWN` | Not determinable |

"Installed but Java missing" is `DEPENDENCY_MISSING`, never `NOT_INSTALLED`. A
configuration entry by itself never makes a ModKit available. The adapter must confirm
that the executable exists **and** reports a supported version, by running its version
command in a throwaway directory with a scrubbed environment and a 30 s timeout.

## Requirements model

A `Requirement` has `kind` (`EXECUTABLE`, `RUNTIME`, `MIN_VERSION`, `MAX_VERSION`,
`ANDROID_SDK`, `BUILD_TOOLS`, `ENVIRONMENT`, `FILESYSTEM`, `OTHER`), `name`, `description`,
an optional `constraint` and an `optional` flag. Each check produces a `RequirementCheck`
(`satisfied`: true, false or unknown, plus the observed value) inside the availability
report. The framework hard-codes no tool's requirements; H.8 declares Morphe's.

## Installation model

`USER_MANAGED` (the H.7 model for third-party tools), `APKFORGE_MANAGED` (reserved, not
implemented) and `BUNDLED`, which is used only for APKForge's own `test-modkit`. APKForge
**never downloads, installs or bundles** a third-party ModKit or its dependencies. It only
detects a tool the user installed and configured.

## Configuration

Lookup order: `--config FILE`, then `$APKFORGE_MODKIT_CONFIG`, then
`$XDG_CONFIG_HOME/apkforge/modkits.toml` (default `~/.config/apkforge/modkits.toml`). Having
no file is valid.

```toml
[modkits.example-kit]
enabled = true
executable_path = "/opt/example-kit/bin/example-kit"   # absolute; ~ expanded
working_directory = "/var/tmp/apkforge-modkits"        # base for execution workspaces
timeout_seconds = 1800                                  # 1 .. 86400

[modkits.example-kit.environment]                       # non-secret variables only
EXAMPLE_KIT_LOG_LEVEL = "info"

[modkits.example-kit.options]                           # adapter-specific, validated by it
some_option = "value"
```

Validation rejects the following as structured `ConfigIssue`s (modkit id, field, message).
A bad entry never aborts discovery of the others; it makes that ModKit
`CONFIGURATION_INVALID`, and APKForge does not probe it.

- unknown keys or ids that are not slugs
- relative paths
- control characters
- environment names APKForge controls (`PATH`, `HOME`, `TMPDIR`, `LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `PYTHONPATH`)
- any environment variable or option whose name looks like a secret (`*TOKEN*`,
  `*PASSWORD*`, `*SECRET*`, `*KEY*` …) — H.7 has no credential model, and secrets are never
  stored in plain text

`morphe` (H.8.1) is always registered, so `apkforge modkits` always lists it — as
`NOT_INSTALLED` until `[modkits.morphe].executable_path` is configured; APKForge never
installs or downloads it. The reference `test-modkit` is registered only when
`APKFORGE_ENABLE_TEST_MODKIT=1` is set or a `[modkits.test-modkit]` entry exists, and never
ships in production use.

## Execution lifecycle

`ModKitExecutor.run(adapter, request)`:

1. **Availability.** If the ModKit is not `AVAILABLE`, the result is `NOT_AVAILABLE`,
   `CONFIGURATION_ERROR` or `DEPENDENCY_ERROR`, and no workspace is created.
2. **Request validation.** Checks the operation, parameter names, required parameters,
   choices and regex patterns, capability subset, and that `output_name` is a plain
   `<name>.apk`. The input must be a regular file that is a well-formed APK. The adapter's
   `validate_input` runs next. APKForge refuses to overwrite an existing destination or
   the input itself.
3. **Original provenance.** Records the SHA-256, size and path.
4. **Fresh workspace.** A new directory per execution, never reused.
5. **Staging.** Copies the input to `input/input.apk` (read-only, `0444`) and re-hashes the
   copy. Any mismatch aborts with `STAGING_MISMATCH`.
6. **`prepare` then `execute`, exactly once.** No automatic retry: a failed third-party run
   can have side effects or be nondeterministic. A retry would be a future feature with
   its own safety model.
7. **Integrity.** The original and the staged input are re-hashed. A change gives
   `ORIGINAL_MUTATED` or `INPUT_MUTATED` (`EXECUTION_FAILED`).
8. **Process outcome.** Timeout, cancellation, non-zero exit, crash (signal), missing
   executable, permission denied, resource limit and adapter exceptions each map to a
   status and failure category.
9. **`collect_output` then independent validation** (below).
10. **Publish.** Only on `SUCCESS`: the candidate is copied to
    `OUT_DIR/<input stem>.<modkit_id>.apk` (or `output_name`) through a temporary file. The
    copy is re-hashed and hard-linked into place, so an existing file is never replaced.
    The ModKit's own file name is never used. `NO_OP` publishes nothing.
11. **`cleanup`.** Always called. A failure is recorded in `messages` and never masks the
    result.
12. **Retention** (`WorkspaceSettings`). A failure keeps the whole workspace by default
    (`keep_on_failure`). Otherwise `input/`, `working/` and `output/` are removed, and
    `logs/` and `metadata/` are kept. `--keep-workspace` keeps everything.

### Workspace isolation

```
<base>/<execution-id>/            base: --work-dir | config working_directory | <tmp>/apkforge/modkits
    input/input.apk               read-only staged copy (the ModKit never sees the original)
    working/                      the ModKit's cwd; working/.home = HOME, working/.tmp = TMPDIR
    output/                       the only place an output is accepted from
    logs/                         stdout.log, stderr.log, execution.log (masked)
    metadata/                     request.json, result.json, provenance.json
```

APKForge generates execution ids (`mk-<UTC>-<random>`). Caller-supplied ids must be one
plain path component, and `subpath()` rejects traversal. No path is ever derived from APK
contents or from names the ModKit supplies.

### Process execution

`ModKitProcessRunner` executes an **argument vector only**: `shell=False`, `argv[0]` an
absolute path, no NUL bytes. Parameters are typed values that the adapter places in the
argv; a value like `$(touch x); \`id\`` reaches the tool as one literal argument (tested).
Other protections:

- stdin is `/dev/null`, and the child runs in its own session so a timeout kills the whole
  process group.
- The environment is built from scratch: `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE` and `TZ` from
  the parent, plus adapter-declared non-secret variables, the configuration's environment,
  and `HOME`/`TMPDIR` inside the workspace. No other parent variable (tokens, keystore
  passwords, cloud credentials) reaches the ModKit (tested).
- stdout/stderr are streamed to files rather than memory. A child that exceeds
  `max_log_bytes` (64 MiB by default) is killed, or flagged if it already exited:
  `RESOURCE_LIMIT`.
- The result keeps the last 4 KiB of each stream with ANSI escapes stripped.

## Output validation

A zero exit code proves nothing. `validate_output` checks, independently of the adapter's
claim:

| Check | Failure |
|---|---|
| `output/` is still a real directory inside the workspace | `OUTPUT_OUTSIDE_WORKSPACE` |
| Nothing new appeared in the workspace root or `input/` (writes outside `output/`) | `OUTPUT_OUTSIDE_WORKSPACE` |
| Declared names are safe relative paths (no `..`, absolute, hidden, control or shell characters) | `OUTPUT_OUTSIDE_WORKSPACE` / `UNSAFE_FILENAME` |
| Every entry in `output/` is a regular file (no symlinks, devices, FIFOs), with a safe name | `OUTPUT_NOT_REGULAR_FILE` / `OUTPUT_OUTSIDE_WORKSPACE` / `UNSAFE_FILENAME` |
| At most one primary output | `OUTPUT_AMBIGUOUS` |
| No undeclared files (no unexpected extra artifacts) | `UNEXPECTED_ARTIFACT` |
| The primary output exists and is not a directory | `OUTPUT_MISSING` / `OUTPUT_NOT_REGULAR_FILE` |
| Well-formed APK: ZIP, CRCs, `AndroidManifest.xml`, no `..`/absolute/duplicate entries, within `ExtractionLimits` | `OUTPUT_MALFORMED` |
| Byte-identical to the input only if the operation allows no-op and the adapter declared it, or the request does not expect a change (`--allow-noop`) | `OUTPUT_UNCHANGED` |
| A declared no-op whose output differs | `OUTPUT_UNCHANGED` |

A ModKit process that exits 0 with an invalid APK is `OUTPUT_INVALID`, never `SUCCESS`.

## Result model

`ModKitExecutionResult` (schema 1) contains:

- `status` and `failure`, with a reason
- the `ModKitIdentity`
- artifact records (`original`, `staged_input`, `candidate`, `published`), each with role,
  path, SHA-256 and size
- the `ExecutionOutcome` (exit code, signal, timing, command record, log paths/sizes/tails)
- the adapter's `OutputDeclaration`
- every `ValidationCheck`
- the `ProvenanceRecord`
- `original_unchanged`, the workspace path and its retention, messages and limitations

| Status | When |
|---|---|
| `SUCCESS` | Validated output published |
| `NO_OP` | Accepted unchanged / declared no-op; nothing published |
| `NOT_AVAILABLE` | Not installed, unsupported version, unavailable, unknown id |
| `INVALID_INPUT` | Bad request (`INVALID_REQUEST`) or bad input APK (`INVALID_INPUT`) |
| `EXECUTION_FAILED` | Non-zero exit, crash, missing executable, permission denied, resource limit, adapter error, workspace/staging failure, input/original mutated |
| `TIMEOUT` | Deadline reached; process group killed |
| `OUTPUT_INVALID` | Any validation failure except a missing output; publish failure |
| `OUTPUT_MISSING` | Nothing (or a non-existent file) declared |
| `CONFIGURATION_ERROR` | Configuration issues for this ModKit |
| `DEPENDENCY_ERROR` | Dependency missing |
| `CANCELLED` | Interrupted (process group killed) |
| `UNKNOWN` | Reserved |

## Provenance and command logging

`ProvenanceRecord` holds:

- `execution_id`, `modkit_id`, `modkit_version`, `adapter_version`, `apkforge_version`
- `requested_operation`, `capabilities`, and masked `parameters`
- input SHA-256, size and path; output SHA-256 and size
- start and end time, exit code
- `toolchain`: Python, platform, and adapter-reported dependency versions
- workspace id and path
- the `CommandRecord`: executable, argv, cwd, the environment the child received, the
  names of masked variables, and the count of masked arguments

The record is written to `metadata/provenance.json`. The invocation is reproducible from
it, except for masked values.

Masking (`SecretMasker`) is layered:

1. Values the adapter marks sensitive (parameters with `sensitive=True`,
   `CommandSpec.sensitive_values`) are replaced everywhere, including in the ModKit's own
   stdout/stderr logs.
2. Any environment variable or `--option` whose name looks like a credential has its value
   masked.
3. Inline `name=value` forms are masked the same way.

Passwords, tokens, private keys and secret environment variables are never logged
(tested by scanning every log, metadata file and the result JSON).

## Post-ModKit analysis (existing infrastructure only)

`ModKitPostAnalysis` adds no engine:

- `diff(result)` — Phase E `DiffEngine` on `original → published output`.
- `privacy(result)` / `security(result)` — Phase F `PrivacyAnalysisService` and
  `SecurityEngine` on both APKs. `compare_findings` returns a `FindingDelta` with
  `findings_before`, `findings_after`, `introduced`, `removed`, `retained`, `changed` and
  `complete`. When either analysis is not COMPLETE, the delta is flagged partial or unknown.
- `verify(result, control, expected=...)` — H.4 through the additive
  `TransformationVerifier.verify_external(original, control, candidate, expected=...,
  toolchain=...)` (result `mode="external"`). There is no H.2 plan, so the caller declares
  the expected changes. Undeclared ModKit changes are `UNEXPECTED_CHANGE`, so the result is
  never VERIFIED. The toolchain defaults to unknown, because a third-party tool did not
  build the candidate.
- `run(result, ...)` — the combined `ModKitAnalysisReport` (`apkforge modkit run --analyze`).

**Build/sign stays separate.** A ModKit transformation is not the APKForge build/sign
pipeline. The framework adds no ModKit-specific signing. `result.published.path` is an
ordinary APK for `BuildService` (align, sign, verify). The integration test feeds the
reference output through a BuildService rebuild, then through H.4 with a control rebuild of
the original:

- undeclared marker asset → `FAILED` (one `UNEXPECTED_CHANGE`)
- declared marker asset → `VERIFIED`

## Composition and conflicts (foundation only)

Each ModKit execution is an independent transformation with its own provenance, input
SHA-256 and workspace. The framework never runs two ModKits automatically, never chains one
ModKit's output into another, and never resolves conflicts. Results are comparable
side by side (tested: two ModKits on the same original). Composition, ordering and conflict
handling are H.9/H.10.

## Security boundary

APKForge enforces:

- input immutability and staging verification
- per-execution isolation
- argv-only execution
- scrubbed environment
- timeouts and log limits
- untrusted-output validation
- safe publishing
- secret masking

APKForge does **not** sandbox the ModKit at the OS level. The ModKit runs with the user's
privileges, so writes outside the workspace (for example into `/tmp` or `$HOME` via
absolute paths) cannot be observed or prevented. Validation catches writes into the
workspace root and `input/`. A process that re-parents itself out of the process group
(double fork plus `setsid`) can outlive a timeout. Install only ModKits you would run by
hand. Container or namespace sandboxing is a possible later phase.

## Licensing and distribution boundary

- Each ModKit has its own license. APKForge does not bundle, redistribute or download any
  third-party ModKit: no binaries, JARs, patches or source are in this repository.
- Integrating a ModKit through an adapter does not grant redistribution rights.
- Adapter code must respect the third-party project's license, and must not copy
  third-party code into APKForge.
- Bundling or redistribution is a separate, later decision. H.8 performs the
  Morphe-specific license and integration review.

## Reference ModKit (`test-modkit`)

`apkforge/modkit/testing/tool.py` is a standalone script that imports nothing from
APKForge. It is run as an external process through `TestModKitAdapter` (`[python, tool.py,
...]`). It reports version `1.0.0`, supports `>=1.0.0,<2.0.0`, and has one operation,
`transform`, with these parameters:

- `scenario` — a choice from the scenarios below
- `marker` — `[A-Za-z0-9 ._-]{1,64}`
- `api_token` — sensitive, used to exercise masking

`success` deterministically rewrites the APK: entries are copied in order with a fixed
timestamp, and `assets/test-modkit/marker.txt` is added. Two runs give byte-identical
outputs. The other scenarios each simulate one failure mode:

`noop`, `noop-undeclared`, `noop-empty`, `missing-output`, `no-declaration`, `invalid-apk`,
`truncated-apk`, `nonzero-exit`, `timeout`, `crash`, `multiple-outputs`, `extra-artifact`,
`outside-workspace`, `outside-undeclared`, `symlink-escape`, `malicious-filename`,
`traversal-entry`, `directory-output`, `mutate-input`, `noisy`, `echo-env`, `echo-args`,
`replace-output-dir`.

The tool's own claim about its outputs (`working/result.json`) is read with size and type
limits and is never trusted.

## Morphe (H.8)

`apkforge.modkit.morphe.MorpheAdapter` drives Morphe Desktop
(https://github.com/MorpheApp/morphe-desktop), a Java CLI for the Morphe Patcher engine,
as `java -jar <configured executable_path> ...`. APKForge never bundles, downloads or
redistributes it (Morphe Patcher/Desktop is GPL-3.0 with additional branding restrictions);
the user configures `[modkits.morphe].executable_path` to point at their own copy.

H.8.1 implements discovery and compatibility only:

- the Java runtime requirement (21+; override with `modkits.morphe.options.java_executable`,
  otherwise `java` is looked up on `PATH`) is reported as a `RequirementCheck` alongside the
  executable check
- `--version` is probed the same way as any other `ExternalProcessAdapter`
- the supported version range is pinned to 1.20.x (`min_version="1.20.0"`,
  `max_version="1.21.0"` exclusive) — 1.20.0 is the only version verified so far (CLI,
  `list-patches` against the real `MorpheApp/morphe-patches` bundle, and a live patch run);
  anything outside that range comes back `VERSION_UNSUPPORTED`
- `capabilities()` and `operations()` are both empty — nothing is verified yet, so the
  framework can never call `build_command`/`execute`/`collect_output` for it

H.8.2 adds `MorpheAdapter.list_patches(patches, *, package=None, prerelease=False,
timeout=None)`, a read-only query of a patch bundle's contents via Morphe's own
`list-patches --with-packages --with-versions`. It runs directly (own subprocess call,
own timeout, scrubbed `HOME`/`TMPDIR`) rather than through the operation contract: it
needs no input APK and produces no APK output, so it does not fit the
`ExecutionRequest`/`ModKitExecutor` transformation pipeline. `capabilities()` and
`operations()` stay empty — `apkforge modkit run morphe ...` still fails with "unknown
operation". `patches` is a local `.mpp` file path or a GitHub/GitLab repo URL (e.g.
`https://github.com/MorpheApp/morphe-patches`), which Morphe resolves, downloads and
caches itself; the result is a `PatchBundleListing` (`apkforge.modkit.morphe.patches`) —
one `PatchInfo` per patch (index, name, description, enabled-by-default, and the packages
plus versions it's compatible with, or none for a "universal" patch). Exposed as
`apkforge modkit patches MODKIT_ID --patches BUNDLE [--package PKG] [--json]`. Morphe has
no JSON output for `list-patches` (checked: only `--out FILE`, still plain text), so the
adapter parses the real text format — including one real quirk, verified against the live
bundle: the first `Index: 0` line of a run comes out as `INFO: Index: 0` because Morphe's
last startup log line never gets its own trailing newline.

H.8.3 adds the `patch` operation itself, so `capabilities()` now declares
`APK_TRANSFORMATION`, `PATCH_SELECTION` and `MULTI_PATCH` (verified: a live "Clone app" run
changed the package name in the manifest) and `operations()` declares one `OperationSpec`
(`id="patch"`) with parameters `patches` (required), `enable`/`disable` (comma-separated
patch names), `exclusive`, `force`, `prerelease`, (H.8.4) `keystore`,
`keystore_entry_alias`, `keystore_entry_password`, `keystore_password`, (H.8.5)
`options` (comma-separated `key=value` pairs), and (H.8.7) `striplibs`,
`bytecode_mode`, `continue_on_error`, `validate`. `build_command` runs Morphe's own
`patch <staged-apk> --patches ... [--enable NAME]... [--disable NAME]... [-O key=value]...
[--exclusive] [--force] [--prerelease] [--striplibs ...] [--bytecode-mode ...]
[--continue-on-error] [--validate] (--unsigned | --keystore ... [--keystore-entry-alias
...] [--keystore-entry-password ...] [--keystore-password ...]) -o <output>/patched.apk
-r <working>/result.json`. `striplibs`/`bytecode_mode`/`continue_on_error`/`validate`
are passed straight through to Morphe's own same-named flags with no adapter-side
validation beyond `bytecode_mode`'s choice set (`FULL`/`STRIP_SAFE`/`STRIP_FAST`) —
verified live: `--striplibs arm64-v8a,x86 --bytecode-mode STRIP_SAFE` actually changed
Morphe's own logged stripping/compilation behavior. `-O`/`--options` is Morphe's own
per-patch option mechanism
(verified live: `-O packageName=com.example.clone` with "Clone app" enabled actually
changed the cloned package name) — option keys are specific to each patch, discovered via
Morphe's own `list-patches --with-options`; entries without `=` are dropped rather than
failing the run. No `sensitive=True` on `options` itself: an arbitrary option key that
happens to look like a credential (e.g. `proxyPassword=...`) is still masked, because the
framework's generic inline `key=value` masking (`masking.py`) checks every argument's key
by name regardless of declaration. Without `keystore`, `--unsigned` is always passed: signing is
APKForge's own `BuildService`'s job downstream, and Morphe's self-signed output is never
trusted regardless of which path is used. `keystore_entry_password`/`keystore_password`
are declared `sensitive=True` (masked in command records/logs via `CommandSpec.
sensitive_values`); the `--keystore*` flag names themselves also trip the framework's
name-based masking (anything matching `KEYSTORE`/`PASS...`), so `keystore_entry_alias`'s
value is masked too, as a side effect of that shared heuristic. `MORPHE_DATA_DIR` is set
to a directory inside the workspace (`modkits.morphe.options.data_dir`, an absolute path,
opts into a persistent cache across runs instead) so a patch bundle fetched by URL is
cached inside the workspace rather than next to the configured JAR, honoring the "never
write outside the workspace" rule. `collect_output` declares `patched.apk` as the sole
output if Morphe produced it; `result.json`'s `appliedPatches`/`failedPatches` are read
(size-limited, never trusted) only to add informational notes — pass/fail always comes
from APKForge's own independent validation of the output file, exactly like `test-modkit`.

H.8.6 (current) adds `with_options` to `list_patches` (and `--with-options` to the CLI
command), appending Morphe's own `--with-options` flag and parsing each patch's
`Options:` sub-section into `PatchInfo.options: tuple[PatchOption, ...]` (`key`, `title`,
`description`, `required`, `default`, `type`, `possible_values`) — closing the gap H.8.5
left open (option keys were previously only discoverable by running Morphe's own CLI
directly). Unlike every other field here, an option's `Description` is **not** parsed
line-by-line: it is genuinely multi-line free text straight from the patch's own source,
with arbitrary/inconsistent indentation (including lines with no leading whitespace at
all, mid-description) — verified against the real bundle's `Custom branding`/
`Change header` patches. Every other option field (`Title`/`Required`/`Key`/`Default`/
`Possible values`/`Type`) is reliably single-line and in a fixed order, so each option is
instead parsed by locating those fixed anchor lines and slicing the raw text between them
for `Description` (bounded by `Description:`/`Required:`) and `Possible values` (bounded
by its own header and `Type:`) — the same reason the parser locates fields this way
rather than by indentation, extended one level deeper. Verified end-to-end against the
real `MorpheApp/morphe-patches` v2.0.0 bundle (e.g. `Clone app`'s `packageName`/
`updatePermissions`/`updateProviders`, `Custom branding`'s multi-line `appIcon`
description with its `possible_values` list) and that a trailing `Compatible packages:`
section after `Options:` still parses correctly.

The H.7 framework needed no changes for H.8.1 through H.8.7: `MorpheAdapter` is
ordinary third-party-facing code behind the same contract, plus (for H.8.2) one method
the contract doesn't require.

## Non-goals (H.7)

H.7 does not include:

- ReVanced or Lucky Patcher integration
- arbitrary APK/smali patching
- automatic patch selection
- automatic malware or spyware removal
- ModKit-specific behaviour
- patch composition or ModKit chaining
- runtime instrumentation
- automatic download, installation or bundling
- automatic retry
- OS-level sandboxing

## Verification (H.7)

- `tests/unit/test_modkit_framework.py` covers models and contract, configuration,
  availability, discovery, every reference scenario, timeout, no retry, output limits,
  request/input validation, availability gating, workspace isolation and retention,
  library adapters and adapter faults, security (shell injection, environment leakage,
  secret masking, safe names, archive validation, process failures), reproducibility,
  provenance, finding comparison and the CLI.
- `tests/integration/test_phase_h7_modkit.py` covers DiffEngine, Phase F/B before/after,
  the BuildService hand-off, and H.4 `verify_external` (undeclared change `FAILED`,
  declared change `VERIFIED`).
- `build-tests/run_phase_h7_validation.py all --write` runs the scenario matrix,
  reproducibility and the pipeline hooks. Evidence is in
  `artifacts/phase-h/H7-MODKIT-FRAMEWORK.md`.
