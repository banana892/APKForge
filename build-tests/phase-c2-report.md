# Phase C.2 Report — BuildService

**Final status: READY**

BuildService is implemented, encapsulates the whole no-op rebuild pipeline, and rebuilt
**9/9** corpus APKs with every stage (decode, build, align, sign, verify) passing on the
final code. Machine-readable results: [`c2_results.json`](c2_results.json) (run
`20261002T153924Z`). Design documentation: [`docs/build-service.md`](../docs/build-service.md).

Runtime install/launch validation was **not** performed. It is outside C.2 scope, and no
device or emulator was attached (`adb devices` listed none). See §8.

---

## 1. Starting point

When C.2 started, the repository already held an earlier C.2 draft (`src/apkforge/builders/*`,
tests, `run_c2_corpus.py`, and a `c2_results.json` recording **8/9**). An audit against
the C.2 requirements found defects, so the package was reworked instead of extended.

| Defect in the earlier draft | Resolution |
|---|---|
| Signing password `apkforge-test-pass` hard-coded in source | No password in source; read from `0600` file or a named env var (§6) |
| Password passed on the command line (`--ks-pass pass:…`) | Passed via child-only env var (`--ks-pass env:…`); masked in all output |
| Any decode failure classified `FRAMEWORK_FAILURE`: Apktool always prints `…/framework/1.apk` | Narrow patterns anchored on C.1/C.1b messages; unmatched failures marked `classified=False` |
| A timeout (exit −999) reported as `BUILD_FAILURE`; partial output discarded | `TIMEOUT` category; process group killed; partial stdout/stderr kept |
| Subprocess inherited stdin | `stdin=/dev/null`, own process group |
| Verification accepted any valid signer | Requires exactly one signer whose SHA-256 equals the configured key's certificate |
| `.jar` Apktool handled in validation but not in decode/build | `ToolchainConfig.apktool_command()` used everywhere |
| Global `~/.local/share/apktool/framework` of unknown provenance | APKForge-managed framework installed from the configured `android.jar`, with a provenance marker |
| `output_path` could equal the input APK, so the input could be overwritten | Rejected; existing outputs need `overwrite_output=True` |
| Tool paths from repo wrapper scripts containing `/home/naishring/...` fallbacks | Discovery from env / SDK layout; hard-coded fallback removed from `tools/apktool` |
| Master `logs/build.log` overwritten by the build-stage log (same name) | Stage logs renamed `logs/stage-<stage>.log` |

The earlier 8/9 result came from AppManager: its `apktool b` step hit the 900 s timeout
with no output captured. **This was not reproduced:** the identical command with the same
framework flag took 15.1 s manually and 14.0 s inside BuildService, and AppManager passed
in all three BuildService corpus runs this phase. The cause is unknown; the earlier draft
inherited stdin and discarded partial output, so no evidence exists. Both gaps are now
closed, so a recurrence would be classified `TIMEOUT` and keep its output.

## 2. Toolchain

From `c2_results.json → toolchain` (all components validated by executing them):

| Component | Status | Version | Path |
|---|---|---|---|
| java | FOUND | OpenJDK 25.0.4.1 | `/usr/lib/jvm/java-25-openjdk/bin/java` |
| keytool | FOUND | (JDK 25) | `/usr/lib/jvm/java-25-openjdk/bin/keytool` |
| apktool | FOUND | **3.0.3** (smali/baksmali 3.0.9-dev) | `tools/apktool_3.0.3.jar` (run as `java -jar`) |
| android_sdk | FOUND | — | `~/Android/Sdk` |
| build_tools | FOUND | 35.0.0 | `~/Android/Sdk/build-tools/35.0.0` |
| android_platform | FOUND | android-35 | `~/Android/Sdk/platforms/android-35/android.jar` |
| apktool_framework | INSTALLED | android-35 | `~/.local/share/apkforge/apktool-framework/android-35` |
| zipalign | FOUND | build-tools 35.0.0 | `…/build-tools/35.0.0/zipalign` |
| apksigner | FOUND | 0.9 | `…/build-tools/35.0.0/apksigner` |

Host: Fedora Linux 44, kernel 7.2.7-200.fc44.x86_64; Python 3.14.7. Toolchain warnings: none.
Apktool below 3.0.3 is rejected as `UNSUPPORTED`; there is no automatic fallback to 2.x.

**Framework.** BuildService runs `apktool if -p <framework_dir> android-35/android.jar`
on first use and writes `apkforge-framework.json` (source path + SHA-256), reinstalling it
if the platform jar changes. Apktool's global framework directory is no longer used. The
marker is needed because an installed `1.apk` cannot be traced back to its source: two
installs of the same `android.jar` differ from byte 11, and `resources.arsc` differs from
the source jar's.

## 3. Architecture

```
BuildService.build(apk, BuildOptions) -> BuildResult       (never raises for tool/config failures)
  prepare  input is a ZIP; output path safe; toolchain valid (cached); signing valid;
           workspace created; input copied to input/original.apk; framework current
  decode   apktool d -o decoded -p <fw> input/original.apk
  build    apktool b -o build/unaligned.apk -p <fw> decoded
  align    zipalign -f -p 4  +  zipalign -c -v -p 4
  sign     keytool -exportcert (expected digest)  +  apksigner sign --ks-pass env:…
  verify   zipalign -c -v -p 4  +  apksigner verify --verbose --print-certs  +  zip testzip
```

Modules: `service.py` (stages), `toolchain.py` (config/discovery/validation/framework),
`signing.py`, `runner.py` (the only subprocess spawner), `workspace.py`, `classify.py`,
`models.py`, `noop_integrity.py`. When a stage fails, later stages are recorded as
`SKIPPED`. CLI: `apkforge build <apk> [-o OUT] [--force] [--work-dir] [--keep-workspace]
[--show-toolchain] [--json]`.

**Workspace:** `<work_dir>/<UTC-timestamp>-<8hex>/{input,decoded,build,aligned,signed,logs,metadata}`,
created with `exist_ok=False`. Every stage writes `logs/stage-<stage>.log` (command, cwd,
env-override *names*, exit code, start/end, duration, stdout, stderr). `logs/build.log`
holds the pipeline summary and `metadata/result.json` the serialized `BuildResult`.
Failures keep the whole workspace. Successful builds drop the intermediates unless asked
to keep them.

Two tool behaviours found during implementation shape the stage checks:
- `zipalign -c` **exits 0 even when it prints `Verification FAILED`**, and prints its
  verdict only with `-v`. Align and verify therefore require the `Verification succesful`
  line.
- `apksigner` writes JVM `WARNING: A restricted method…` noise to stderr. Real signature
  warnings appear on stdout and are collected; the noise is never used as failure evidence.

## 4. Corpus results

All 9 corpus APKs (`samples/` = `tests/corpus/`, identical SHA-256), final code, 146.9 s total:

| APK | Decode | Build | Align | Sign | Verify | Overall | Failure | Time |
|---|---|---|---|---|---|---|---|---|
| `com.emanuelef.remote_capture_95.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 10.5s |
| `com.oF2pks.applicationsinfo_19.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 2.4s |
| `de.audioattack.openlink_28.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 2.5s |
| `de.danoeh.antennapod_3120295.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 14.3s |
| `eu.siacs.conversations_4218104.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 14.5s |
| `godau.fynn.usagedirect_10.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 9.6s |
| `io.github.muntashirakon.AppManager_451.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 23.2s |
| `org.mozilla.fennec_fdroid_1560020.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 45.2s |
| `org.schabi.newpipe_1015_cb84069.apk` | PASS | PASS | PASS | PASS | PASS | **PASS** | — | 18.7s |

The two C.1 failures (Conversations, NewPipe) now pass, as C.1b predicted for Apktool 3.0.3
with the android-35 framework. The same 9/9 result also came from an earlier BuildService run
this phase (153.2 s, before the final hardening edits) and from the opt-in pytest corpus test
(§7). The original APK was byte-identical after every build (`original_unchanged_after_build:
true` ×9), and all 18 corpus files (both directories) passed `sha256sum -c` after the runs.
Stage logs: `build-tests/logs/c2/<apk>/`; rebuilt APKs: `work/c2/20261002T153924Z/outputs/`.

## 5. No-op integrity baseline

From `c2_results.json → results[].integrity`, computed by `noop_integrity.compare_noop_rebuild`:

| APK | .so identical | DEX files | DEX bytes orig → rebuilt | arsc bytes orig → rebuilt | Manifest parses | Identity + component counts match |
|---|---|---|---|---|---|---|
| remote_capture | 20/20 | 2/2 | 4,009,712 → 4,655,688 | 2,103,772 → 2,155,300 | yes | yes |
| applicationsinfo | — (0) | 1/1 | 107,904 → 107,796 | 21,276 → 22,192 | yes | yes |
| openlink | — (0) | 1/1 | 79,648 → 90,696 | 67,536 → 69,556 | yes | yes |
| antennapod | 4/4 | 3/3 | 13,233,368 → 13,254,360 | 3,084,668 → 3,123,420 | yes | yes |
| conversations | 2/2 | 2/2 | 8,292,252 → 9,765,472 | 3,813,284 → 3,847,468 | yes | yes |
| usagedirect | — (0) | 2/2 | 7,343,744 → 7,359,992 | 345,204 → 361,156 | yes | yes |
| AppManager | 16/16 | 6/6 | 35,826,628 → 35,861,960 | 4,700,772 → 4,738,496 | yes | yes |
| fennec | 15/15 | 3/3 | 29,655,040 → 33,173,168 | 17,302,880 → 17,378,572 | yes | yes |
| newpipe | 4/4 | 3/3 | 11,376,836 → 13,517,316 | 5,258,564 → 5,291,652 | yes | yes |

- **Native libraries:** 61/61 `.so` files across 6 APKs are byte-identical, matching C.1b.
  This is the first byte comparison for Conversations' 2 libraries, since it failed in C.1.
- **DEX:** same file count everywhere; **0** DEX files are byte-identical (smali
  reassembly). Sizes changed between −0.1% and +18.8% (NewPipe, +2.1 MB); the largest
  increases are in Conversations, NewPipe, Fennec, openlink and remote_capture. Recorded
  as baseline only; DEX semantic equivalence is **not** established by C.2.
- **resources.arsc:** never byte-identical; it grows by 0.4–4.6% after AAPT2 regeneration.
- **AndroidManifest.xml:** never byte-identical. The rebuilt manifest parses for all 9.
  Package, versionCode, versionName, min/targetSdk, and the counts of `uses-permission`,
  `permission`, `activity`, `activity-alias`, `service`, `receiver` and `provider` match
  the original for all 9.
- **Entries:** the entry count is equal for all 9. 30–2,241 resource entries per APK were
  renamed: Apktool restores shortened resource paths (`res/a.xml` → `res/layout/…`), so the
  same number of entries is added and removed.
- **Signature:** the original `META-INF/*.RSA|.SF` files are replaced by `APKFORGE.RSA/.SF`.
  Every rebuilt APK verifies with exactly one signer, `CN=APKForge Development Key - NOT FOR
  RELEASE, O=APKForge`, whose SHA-256 `f769555534625181026172519a074c1c4eefc5f5318aa6913ebb80ca466e972b`
  equals the configured key's certificate. v2+v3 hold for all 9. v1 holds for 8; apksigner
  skips v1 for Fennec because of its minSdk. Non-signature `META-INF` files carried over from
  the originals are reported by apksigner as not covered by v1 (0–123 per APK); BuildService
  summarizes these as a warning.

## 6. Security

- **Input isolation:** tools receive only `input/original.apk`, a read-only copy inside
  the workspace. The original is hashed before and after; a change fails the build. Output
  equal to the input is refused.
- **Subprocesses:** every invocation goes through `CommandRunner` as an argument array,
  with no shell, `stdin=/dev/null`, a new process group (killed on timeout), and a per-stage
  timeout (default 900 s). APK-derived data reaches tools only as workspace file paths,
  and nothing from the APK is executed.
- **Untrusted decoded content** stays under `decoded/`; `BuildWorkspace.subpath()` rejects
  paths that would escape the workspace.
- **Secrets:** there is no password in the source. The password reaches `apksigner`/`keytool`
  through `APKFORGE_INTERNAL_KEYSTORE_PASSWORD` in the child environment only, never in
  argv, and the runner masks it in results and logs. Unit tests assert that the password
  appears in no log, `result.json`, BuildResult or argv.
- **Development key:** generated once in `~/.local/share/apkforge/dev-signing/` (dir `0700`):
  RSA-3072 PKCS12 key, random 256-bit password in a `0600` file. The key is outside the
  repository; `*.p12`/`*.jks` are gitignored. Production keys are never used. The legacy C.1
  `tools/test-signing-key.jks` (fixed password) is unused.

## 7. Tests

| Run | Result |
|---|---|
| Baseline before C.2 changes | 429 passed |
| Full suite, final code, `APKFORGE_CORPUS_BUILD=1` | **483 passed, 0 failed, 0 skipped** (163.6 s) |
| Full suite, default (corpus tests opt-in) | 474 passed, 9 skipped |

C.2 tests: 69 in total. `tests/unit/test_build_service.py` has 58 (runner: masking,
timeout with partial output, exec error, closed stdin; workspace: layout, uniqueness,
traversal, retention; toolchain: discovery, pins, missing/broken/unsupported tools, version
reporting, framework provisioning; signing: validation, env config, dev key with no secret
on argv; classification using the verbatim C.1/C.1b error lines; pipeline: stage order,
skipped stages, alignment `FAILED`-with-exit-0, signer mismatch, signing failure, timeout,
unsafe outputs, invalid input/toolchain/signing, internal errors not raised, concurrent
isolated builds). `tests/integration/test_build_service_corpus.py` has 2 real-toolchain
stage tests plus the 9-APK corpus test. `ruff check`, `ruff format --check` and `mypy` are
clean on `src/apkforge/builders`.

## 8. Limitations

- **Runtime install/launch: NOT RUN.** No device or emulator was attached (`adb devices` is
  empty), and provisioning one is out of scope. A verified rebuild is not proven to install
  or run.
- **No semantic modification validation:** C.2 rebuilds without modifying anything. DEX and
  resource equivalence is not checked beyond the baseline in §5.
- **No malware/spyware analysis or removal** happens in this phase.
- `.so` files are page-aligned to 4 KiB (`zipalign -p`); 16 KiB alignment (`-P 16`) is not applied.
- Only the Android platform framework is provisioned; vendor/OEM frameworks are not.
- The unexplained AppManager timeout from the earlier draft (§1) did not recur in 3 runs.
- Side observation, not caused by C.2: `/tmp/apkforge` holds ~1,770 leftover
  `apkforge_<id>_*` analysis-session workspaces (3.3 GB, dated before and during this phase)
  from the pre-existing core workspace code. During this phase `/tmp` (7.7 GB tmpfs) briefly
  hit its quota, which interrupted one run until temp space was freed.

## 9. Exit criteria

| Criterion | Status |
|---|---|
| BuildService exists; tools encapsulated; stages identifiable; paths configurable | ✅ |
| decode / build / zipalign / sign / verify work | ✅ 9/9 corpus, each stage PASS |
| Input never modified; isolated workspaces; safe argv; secrets not logged; dev key separate | ✅ (§6, tested) |
| Structured BuildResult; stage logs; failure categories; toolchain diagnostics | ✅ |
| Unit + integration tests pass; all 9 APKs attempted; results + integrity recorded | ✅ (§4, §5, §7) |
| C.2 docs, configuration example, known limitations | ✅ `docs/build-service.md`, `docs/examples/build-service.env.example`, `docs/known-limitations.md` |

C.2 stops here. No C.3 modification work was started.
