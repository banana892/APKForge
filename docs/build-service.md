# BuildService (Phases C.2 / C.3)

`apkforge.builders.BuildService` is the single APK rebuild abstraction in APKForge.
No other module invokes Apktool, zipalign or apksigner. It performs a
**no-op rebuild** only — nothing is modified between decode and build. The
modification engine will plug in between those stages in a later phase.

Phase C.2 introduced the pipeline; Phase C.3 made every stage an individually
callable public method (`prepare_workspace`, `decode`, `build`, `align`, `sign`,
`verify`) that `build_pipeline` composes, and added the `TOOL_UNAVAILABLE`,
`WORKSPACE_FAILURE`, `OUTPUT_MISSING` and `UNEXPECTED_FAILURE` categories, explicit
signing modes and structured `[STAGE]` logs.

Evidence and corpus results: [`build-tests/phase-c2-report.md`](../build-tests/phase-c2-report.md).
Toolchain decisions come from Phase C.1/C.1b
([`build-tests/phase-c1b-report.md`](../build-tests/phase-c1b-report.md)).

---

## 1. Purpose

Turn the experimentally validated pipeline (Apktool 3.0.3 + Android 35 framework +
build-tools 35.0.0) into a small, deterministic, testable service that:

- encapsulates every external tool behind one API,
- isolates every build in its own workspace and never touches the input APK,
- reports a structured `BuildResult` with per-stage results, logs and a failure category,
- verifies its output independently (alignment, signature, *expected* signer, ZIP integrity).

## 2. Architecture

```
apkforge/builders/
  service.py        BuildService: pipeline orchestration and stages
  toolchain.py      ToolchainConfig, discovery, validate_toolchain(), framework provisioning
  signing.py        SigningConfig, development key, certificate digest
  runner.py         CommandRunner: the only place subprocesses are spawned
  workspace.py      BuildWorkspace: per-build directory layout and retention
  classify.py       failure classification (stage + tool output -> category)
  models.py         BuildResult, StageResult, BuildOptions, enums
  noop_integrity.py original-vs-rebuilt baseline comparison (corpus/QA use)
```

```python
from apkforge.builders import BuildOptions, BuildService, SigningConfig, ToolchainConfig, ensure_dev_keystore

toolchain = ToolchainConfig.discover()
signing = SigningConfig.from_env() or ensure_dev_keystore(toolchain.keytool)
service = BuildService(toolchain, signing)

check = service.check_toolchain()          # structured diagnostics, cached per service
result = service.build_pipeline("app.apk", BuildOptions(output_apk=Path("app.rebuilt.apk")))
result.success, result.failure_stage, result.failure_category, result.failure_command
result.logs, result.signing_mode, result.verification, result.log_file
```

Individual stages (each returns a `StageResult`; `output_path` is the artifact it produced):

```python
ws, prep = service.prepare_workspace()                        # fresh unique workspace
dec = service.decode("app.apk", ws)                           # -> ws.decoded_dir
blt = service.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws)
aln = service.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws)
sgn = service.sign(ws.aligned_apk, ws.signed_apk, workspace=ws)   # optional SigningConfig override
ver = service.verify(ws.signed_apk, expected_certificate_sha256=sgn.certificate_sha256)
ver.verification.valid, ver.verification.certificate, ver.verification.apksigner_output
```

`build`, `align`, `sign` and `verify` also work on arbitrary paths without a workspace
(no log files are written then; events and tool output are still in the `StageResult`).
They refuse to write over their input, refuse an existing output unless
`overwrite=True`, and with `overwrite=True` delete the old file *before* the tool runs
so stale output can never pass as new output.

No stage method or `build_pipeline` raises for tool or internal failures; every outcome
is a `StageResult` / `BuildResult` (internal exceptions become `UNEXPECTED_FAILURE` with
the original type and message, and the traceback in the stage log). `KeyboardInterrupt`
still propagates. Signing is optional at construction for decode/build/align/verify-only
use, but `sign()` and `build_pipeline()` then fail with `CONFIGURATION_FAILURE` — the
service never silently picks a key.

CLI:

```bash
apkforge build app.apk -o app.rebuilt.apk [--force] [--work-dir DIR] [--keep-workspace] \
    [--show-toolchain] [--json]
```

The CLI prints the toolchain table when validation fails, the stage table, the output
path, and on failure the stage, category, cause, evidence line, retained workspace and log.
Exit code: 0 success, 1 build failure, 2 signing setup failure.

## 3. Toolchain configuration

Precedence: explicit argument > `APKFORGE_*` variable > standard variable > SDK layout > `PATH`.
No machine-specific path is hard-coded. A commented example covering every variable:
[`docs/examples/build-service.env.example`](examples/build-service.env.example).

| Component | Variables / discovery | Validated version |
|---|---|---|
| Java | `APKFORGE_JAVA`, `JAVA_HOME/bin/java`, `PATH` | OpenJDK 25.0.4.1 |
| keytool | `APKFORGE_KEYTOOL`, next to `java`, `PATH` | (JDK) |
| Apktool | `APKFORGE_APKTOOL` (.jar or executable), `<checkout>/tools/apktool.jar`, `PATH` | **3.0.3** (minimum; 2.x rejected) |
| Android SDK | `APKFORGE_ANDROID_SDK`, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `~/Android/Sdk` | — |
| build-tools | `APKFORGE_BUILD_TOOLS_VERSION`, else highest installed | 35.0.0 |
| Platform | `APKFORGE_ANDROID_PLATFORM` (e.g. `android-35`), else highest installed | android-35 |
| zipalign / apksigner | `APKFORGE_ZIPALIGN` / `APKFORGE_APKSIGNER`, else from build-tools, else `PATH` | 35.0.0 / 0.9 |
| Framework dir | `APKFORGE_APKTOOL_FRAMEWORK_DIR`, else `$XDG_DATA_HOME/apkforge/apktool-framework/<platform>` | — |

`validate_toolchain()` runs each tool (`java -version`, `apktool --version`,
`zipalign` banner, `apksigner --version`) and returns a `ToolchainCheckResult` with a
`ToolDiagnostic` (path, version, status, notes) per component. It detects missing
tools, broken tools, Apktool below 3.0.3 (`UNSUPPORTED`), missing SDK/build-tools/
platform, and warns on platforms older than android-35. Errors that concern only the
platform map to `FRAMEWORK_FAILURE`, all others to `TOOLCHAIN_FAILURE`.

### Apktool framework

C.1b showed Apktool's bundled framework lacks API 35 attributes (`android:allow`,
`windowOptOutEdgeToEdgeEnforcement`, …). Rather than depending on whatever is in
Apktool's global framework directory, BuildService installs the configured platform's
`android.jar` (`apktool if -p <framework_dir>`) into an APKForge-managed directory on
first use, atomically, and writes `apkforge-framework.json` recording the source path
and SHA-256. It is reinstalled whenever the platform jar changes. Decode and build both
pass `-p <framework_dir>`.

## 4. Workspace model

```
<work_dir>/<build-id>/            build-id = <UTC timestamp>-<8 hex>, created exist_ok=False
  input/original.apk              read-only private copy; tools never receive the original path
  decoded/                        apktool d output (untrusted content)
  build/unaligned.apk             apktool b output
  aligned/aligned.apk             zipalign output
  signed/signed.apk               final APK
  logs/build.log                  pipeline summary (toolchain, signer, stage lines)
  logs/stage-<stage>.log          full command, cwd, env-override names, exit code, timing, stdout, stderr
  metadata/result.json            the serialized BuildResult
```

Default `work_dir`: `<tmp>/apkforge/builds` (from the existing `WorkspaceSettings`).

Retention: failures keep everything (`keep_workspace_on_failure=True`). Successful builds
remove `input/ decoded/ build/ aligned/` unless `keep_workspace_on_success=True`; `logs/`
and `metadata/` are always kept; `signed/` is removed only when the APK was exported to
`output_apk`.

Path safety: caller-supplied build ids must be a single plain path component
(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, no `..`), otherwise `WorkspaceError` /
`WORKSPACE_FAILURE`. No path is derived from APK contents; the input copy is always
`input/original.apk`. `decode()` refuses a workspace that already has `decoded/`
(stale output) and rejects a decoded tree containing any symlink.

The input APK is hashed before and after the build; `BuildResult.input_unchanged`
must be true for success. `output_apk` equal to the input is rejected, and an existing
`output_apk` is only replaced with `overwrite_output=True`.

## 5. Pipeline stages

| Stage | Commands | Pass condition |
|---|---|---|
| prepare | — / `apktool if` | input exists and is a ZIP; output path safe; toolchain valid; signing config valid; workspace created and usable; framework current |
| decode | `apktool d -o decoded -p <fw> input/original.apk` | exit 0, `decoded/AndroidManifest.xml` + `apktool.yml` exist, no symlinks in `decoded/` |
| build | `apktool b -o build/unaligned.apk -p <fw> decoded` | exit 0, output exists, is non-empty and is a ZIP |
| align | `zipalign -f -p 4 …`, then `zipalign -c -v -p 4 …` | output non-empty and `Verification succesful` printed (zipalign exits 0 even on `Verification FAILED`) |
| sign | `keytool -exportcert` (expected digest), `apksigner sign --ks-pass env:… --key-pass env:…` | exit 0 and output exists and is non-empty |
| verify | `zipalign -c -v -p 4`, `apksigner verify --verbose --print-certs`, ZIP `testzip` | all of: aligned, `Verifies`, exactly one signer whose SHA-256 equals the configured certificate, ZIP intact, manifest present |

When a stage fails (including prepare), later stages are recorded as `SKIPPED` and no
later tool runs. Each `StageResult` carries the (masked) commands, exit code,
stdout/stderr, timestamps, duration, log file, `events`, `output_path`, and on failure
its category, cause, evidence line, `failed_command` and whether a known pattern matched.

Structured logs: every stage emits `[STAGE] starting`, then `[STAGE] completed (Ns)`
(`[PREPARE] workspace ready`, `[VERIFY] passed`) or `[STAGE] FAILED <CATEGORY>: <cause>`.
They are in `StageResult.events`, concatenated in `BuildResult.logs`, written to
`logs/build.log` and the stage log, and sent to the `apkforge.builders.service` logger at
DEBUG. No password, key material or environment dump is ever logged.
Default stage timeout: 900 s (`BuildOptions.stage_timeout_seconds`); on timeout the whole
process group is killed and partial output is kept.

## 6. Failure categories

| Category | Assigned when |
|---|---|
| `INPUT_FAILURE` | input missing / not a file / not a ZIP; not an Apktool project (`build()`); input changed during the build |
| `CONFIGURATION_FAILURE` | unsafe or existing output path, output equals input, no/invalid signing configuration |
| `TOOL_UNAVAILABLE` | a required tool is not configured or its path does not exist (only `MISSING` tools failed validation) |
| `TOOLCHAIN_FAILURE` | a tool is present but broken/unsupported; tool not executable; `UnsupportedClassVersionError`; aapt2 not executable |
| `WORKSPACE_FAILURE` | workspace not creatable or unusable, invalid build id, input copy failed, stale `decoded/` present |
| `OUTPUT_MISSING` | the tool exited 0 but its expected output is missing or empty |
| `UNEXPECTED_FAILURE` | internal exception inside a stage or the pipeline (type and message kept, traceback in stage log) |
| `FRAMEWORK_FAILURE` | platform missing; framework install failed; `attribute android:… not found`, `style attribute 'android:attr/…' not found` |
| `RESOURCE_FAILURE` | build: `error: attribute X not found` (non-android), `failed linking references/file resources`; decode: ARSC/AXML decoder exceptions |
| `DECODE_FAILURE` / `BUILD_FAILURE` | stage failed, no known pattern matched (`classified=False`) |
| `ALIGNMENT_FAILURE` / `SIGNING_FAILURE` / `VERIFICATION_FAILURE` | failure in that stage |
| `TIMEOUT` | stage exceeded its timeout |
| `UNSUPPORTED` | `Unsupported dex/apk/… version/format` |

Patterns are narrow and anchored on C.1/C.1b messages. The bare word "framework" is
never a signal (Apktool always prints the framework path). Unmatched failures keep the
stage's generic category with `classified=False`, and the evidence is the last
meaningful stderr line, with JVM `WARNING: A restricted method…` noise excluded.

## 7. Signing model

- `SigningConfig(keystore, alias, password_file | password_env)` names *where* the
  password is; it never holds it. There is no password anywhere in the source.
- The password is resolved at build time and passed to `apksigner`/`keytool` through the
  child-only variable `APKFORGE_INTERNAL_KEYSTORE_PASSWORD` (`--ks-pass env:…`,
  `-storepass:env …`), so it never appears in argv (`/proc/*/cmdline`), and the runner
  masks it in every captured output and log.
- Default: the **APKForge development key**, generated once by `ensure_dev_keystore()` in
  `$XDG_DATA_HOME/apkforge/dev-signing/` (dir `0700`): `apkforge-dev.p12` (RSA 3072,
  PKCS12) plus a random 256-bit password in `apkforge-dev.password` (`0600`). Subject:
  `CN=APKForge Development Key - NOT FOR RELEASE, O=APKForge`. It is outside the
  repository; `*.p12`/`*.jks` are also gitignored.
- Another key can be selected with `APKFORGE_SIGNING_KEYSTORE`/`_ALIAS`/`_PASSWORD_FILE`
  (or `_PASSWORD_ENV`), or passed to `sign(..., signing)`. Do not use production keys.
- Signing modes (`SigningMode`, `BuildResult.signing_mode`): `unsigned` (default; any
  pipeline that did not pass the sign stage, and the outputs of `build()`/`align()`),
  `development` (`SigningConfig.development_key=True`, the APKForge dev key) and
  `user_provided` (any other explicitly configured keystore).
- The old C.1 `tools/test-signing-key.jks` (fixed password) is no longer used.

## 8. Verification model

Verification is a separate stage on the final APK and does not trust earlier exit codes:

1. `zipalign -c -v -p 4` must print `Verification succesful` and not `Verification FAILED`.
2. `apksigner verify --verbose --print-certs` must exit 0, print `Verifies`, verify with
   at least one of v1/v2/v3, and report **exactly one signer whose certificate SHA-256
   equals the digest of the configured key** (read with `keytool -exportcert` before
   signing). A valid signature by any other key is a `VERIFICATION_FAILURE`.
3. The ZIP must pass `testzip()` and contain `AndroidManifest.xml`.

Standalone `verify(apk)` without `expected_certificate_sha256` skips the signer check
(`expected_signer_matched` is `None`, not `True`); all other checks still apply, so an
APK that is not `-p 4` aligned fails. The raw apksigner output is kept in
`verification.apksigner_output`.

apksigner `WARNING:` lines are kept in `verification.apksigner_warnings`; the common
"META-INF/… not protected by signature" family (non-signature files carried over from
the original APK) is summarized as one `BuildResult.warnings` entry.

## 9. Corpus testing

- Unit tests (`tests/unit/test_build_service.py`) use a fake tool runner and need no
  external tools. They cover every stage method on its own (input, tool-unavailable,
  command-failure, output-missing, stale-output and path-safety cases) and the pipeline.
- Integration tests (`tests/integration/test_build_service_corpus.py`) run the real
  toolchain on two small corpus APKs, provisioning framework and key in pytest temp dirs;
  skipped when the toolchain is unavailable. The full 9-APK test runs with
  `APKFORGE_CORPUS_BUILD=1`.
- `build-tests/run_c2_corpus.py` rebuilds all corpus APKs, computes the no-op integrity
  baseline (`noop_integrity.compare_noop_rebuild`), and writes
  `build-tests/c2_results.json`; stage logs are copied to `build-tests/logs/c2/<apk>/`.
  Outputs go to `work/c2/<run-id>/`; the corpus is never written.

## 10. Known limitations

- The `apkforge verify` CLI command is still the Phase 3 placeholder; its intended
  backend is `BuildService.verify()`.
- **Runtime install/launch validation is not part of C.2/C.3.** No emulator or device was
  available (`adb devices` empty during C.1b) and provisioning one is out of scope. A
  rebuilt APK that verifies is not proven to install or run.
- No semantic equivalence check: DEX and `resources.arsc` differ byte-wise after a round
  trip; only native libraries are byte-compared and the manifest is compared at the
  identity/component-count level.
- `zipalign -p` page-aligns native libraries to 4 KiB. 16 KiB page alignment
  (`zipalign -P 16`, Android 15+ devices with 16 KiB pages) is not applied.
- Rebuilt APKs carry only the new signature; original signer identity is gone by design.
  `META-INF` non-signature files from the original remain and are not covered by v1.
- A single keystore password is used for store and key (PKCS12 convention).
- Framework provisioning covers the Android platform framework only; apps needing
  vendor/OEM frameworks (`apktool if` of extra framework APKs) are not supported.
- The Apktool 3.0.3 AppManager build hang seen once in an earlier C.2 run (900 s timeout,
  no output captured) was not reproduced; see the report.
- No malware/spyware analysis or modification happens in this phase.
