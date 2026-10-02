# Controlled modification (Phase C.5)

C.5 is the first real APK modification made by APKForge. It is deliberately narrow: one
modifier, one target APK, and a verification step that compares what was planned with
what actually changed. It is **not** the Phase D modifier framework.

```
original APK (never written)
  -> baseline inspection (InspectionEngine, manifest)
  -> BuildService.prepare_workspace() -> BuildService.decode()
  -> discover target in the decoded manifest
  -> plan (or structured refusal) - expected changes declared here
  -> apply: minimal edits to decoded AndroidManifest.xml + source-level self-check
  -> BuildService.build() -> align() -> sign() -> verify()
  -> DiffEngine.diff(original, modified)
  -> expected-vs-actual classification against the plan and the APK's no-op baseline
  -> original SHA-256 unchanged
```

| module | role |
|---|---|
| `apkforge/modification/boot_receiver.py` | the C.5 modifier: `discover` → `plan_disable_boot_receiver` → `apply_plan` |
| `apkforge/modification/controlled.py` | `run_disable_boot_receiver`: the pipeline above |
| `apkforge/diff/expectations.py` | classification of a `DiffResult` (small extension of the diff package) |
| `apkforge/builders/semantic_baseline.py` | the semantic no-op baseline |
| `build-tests/run_c5_validation.py` | `noop`, `compare-old`, `modify` evidence runs |

The modifier only edits files in the decoded project. Every tool runs through
BuildService. The C.5 code in `modification/` contains no subprocess calls.

## The modifier

**Operation:** remove `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>`
and set `android:enabled="false"` on the receiver that handles the boot broadcast.

**Target discovery** (`discover`). Nothing is hard-coded. A boot receiver is any
`<receiver>` whose intent filters contain `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` or a
`QUICKBOOT_POWERON` action. Receiver names are resolved to fully qualified names.

**Plan** (`plan_disable_boot_receiver`) is `READY` only if all of the following hold:

- the permission is declared exactly once, as `<uses-permission>`;
- exactly one boot receiver exists, or the caller named one explicitly and it is a boot receiver;
- that receiver's `android:enabled` is `true` or absent (not `false`, not a resource reference).

Otherwise the plan is a structured refusal:

- `TARGET_MISSING`: the permission or the receiver is absent;
- `AMBIGUOUS_TARGET`: several boot receivers and none named;
- `UNSUPPORTED`: already disabled, `@bool/...`, or `uses-permission-sdk-23`.

The first refusal determines the status, and every problem is recorded. A refused plan
has no edits, and the pipeline stops before the build (`REFUSED`).

A ready plan declares, before anything is applied:

- `source_edits`: the exact structural edits to the decoded manifest;
- `expected_changes`: the observations DiffEngine must report after the rebuild:
  - `uses_permission removed RECEIVE_BOOT_COMPLETED`;
  - `component modified <receiver> {component_type: receiver, enabled: [before, false]}`.
  The component detail pins *which* attributes change, so a receiver that is disabled
  *and* also loses `exported` does not match;
- `consequences`: other actions handled by the same receiver (disabling the component
  stops them too);
- `limitations`.

**Apply** (`apply_plan`) makes minimal text edits: one element removed, one attribute
value set. It then re-parses both manifests and computes their structural difference.
That difference covers every element and attribute, including intent filters, `<queries>`
and `<meta-data>`, and it must equal the planned edits exactly. If it does not, the
original text is restored and the step fails. A plan made from a different manifest
(hash mismatch) is refused as stale.

## Verification: expected vs actual

`verify_expectations(diff, expected, allowed_noise_rules=…, allowed_residue=…)` flattens
the whole `DiffResult` into observations. It covers identity, manifest attributes,
permissions, components, DEX files, classes and API references, strings, network,
native, embedded files, the certificate, and every file entry. Each observation is
classified as exactly one of:

| class | meaning |
|---|---|
| `expected_modification` | equals a declared `ExpectedChange` |
| `rebuild_noise` | matches a documented noise rule (below) |
| `unexpected` | anything else, including noise of a rule that did not occur in this APK's no-op baseline |
| `unknown` | the facts could not be established (truncated output) |

The verdict passes only if all of the following hold:

- the diff status is `complete`;
- there are no diff limitations or errors;
- every expected change was observed;
- there are zero `unexpected` and zero `unknown` observations.

Nothing is downgraded to a warning. `VERIFIED` additionally needs every BuildService
stage to pass, including `verify` (alignment, signature, expected signer, ZIP
integrity), and the original APK to be byte-identical.

### Noise rules (current toolchain only)

Derived from the semantic no-op baseline below (Apktool 3.0.3, build-tools 35.0.0):

| rule | what it accepts |
|---|---|
| `signature_replaced` | `META-INF/MANIFEST.MF`, `*.SF`, `*.RSA/DSA/EC` added/removed/modified. **Not** other `META-INF/` entries (e.g. `services/`), even though the inventory categorises them as "signature" |
| `certificate_replaced` | signing certificate differs (re-signed) |
| `dex_reencoded` | `classesN.dex` bytes differ. Class/method changes are separate observations and are never noise |
| `dex_compiler_marker_removed` | the R8/D8/L8 build-marker string `~~R8{…}` dropped by smali |
| `manifest_reencoded` | binary `AndroidManifest.xml` bytes differ. Its compared semantics are observed separately |
| `resource_table_reencoded` | `resources.arsc` regenerated (**not compared semantically**) |
| `resource_reencoded` | `res/` file recompiled at the same path (**not compared semantically**) |
| `resource_path_canonicalized` | `res/Xy.xml` → `res/<type>/<name>.xml`, paired by ARSC identity or content hash |
| `manifest_resource_path_canonicalized` | manifest attribute changes only by that canonicalization, and only when the file rename is paired |

Per APK, the C.5 run accepts only the rules that fired in **that APK's** no-op baseline,
plus that APK's recorded residue (exact paths).

## Semantic no-op baseline

`tests/corpus/results/c5-semantic-noop-baseline.{json,md}` is the **C.5 precondition
semantic no-op baseline**. It is separate from the C.4 build baseline
(`baseline.json`), which is unchanged. For each corpus APK it records:

- the identity (SHA-256), the toolchain, and the original and rebuilt SHA-256;
- observation counts, noise per rule, residue, unexpected and unknown observations;
- a result: `EQUIVALENT`, `EQUIVALENT_WITH_RESIDUE`, `NOT_EQUIVALENT`, `UNDETERMINED` or `BUILD_FAILED`.

`EQUIVALENT_WITH_RESIDUE` means unpaired resource renames remain (known-limitations §2).
They are accepted only when the multiset of removed sizes equals the multiset of added
sizes. They are then recorded by exact path and accepted for that APK alone.

Investigated no-op findings:

- **AppManager 451: one DEX method reported modified.** Instructions were identical.
  The original had two abutting try ranges with the same handler, and smali reassembled
  them as one range. This was an APKForge hashing false positive, fixed in commit
  `80e158a`: abutting ranges with identical handlers are merged before hashing.
- **Unpaired resource pairs** (PCAPdroid, applicationsinfo, AntennaPod, AppManager,
  Fennec): one resource file is referenced by several ARSC entries/configurations, so
  identity pairing is ambiguous by design, and recompilation changes the bytes. The ARSC
  mapping was checked to be the same before and after (applicationsinfo).
- **Fennec is `UNDETERMINED`:** the diff is `partial` because `libxul.so` exceeds the
  embedded-file scan threshold (known-limitations §1). Every observation is otherwise
  explained.

### Phase B noise floor vs Apktool 3

The Phase B noise categories were not carried over. The toolchain comparison
(`tests/corpus/results/c5-toolchain-comparison.{json,md}`) rebuilt OpenLink, AntennaPod
and AppManager with the pinned Phase B image (`apkforge-toolchain:pinned`, Apktool
2.10.0, build-tools 34.0.0, JDK 17) and classified both outputs with the same rules. See
that report for the per-APK result. The main recorded difference: Apktool 2.10.0 drops
non-signature `META-INF/` entries (library `.version` markers, licence files,
`app-metadata.properties`: 16 for OpenLink, 73 for AntennaPod, 4 for AppManager), while
Apktool 3.0.3 keeps them. Under the current rules those removals are `unexpected`, so all
three old-toolchain no-ops classify `NOT_EQUIVALENT`, against `EQUIVALENT` /
`EQUIVALENT_WITH_RESIDUE` with Apktool 3.0.3. Every other rule fired identically, with the
same counts, on both toolchains. The rules are therefore valid for the
current toolchain only.

## Running

```bash
source tools/env.sh
.venv-validation/bin/python build-tests/run_c5_validation.py noop --write        # ~10 min
.venv-validation/bin/python build-tests/run_c5_validation.py compare-old \
    --only de.audioattack.openlink@28 de.danoeh.antennapod@3120295 \
           io.github.muntashirakon.AppManager@451 --write                       # needs docker
.venv-validation/bin/python build-tests/run_c5_validation.py modify --write

.venv-validation/bin/python -m pytest -q tests/unit/test_c5_*.py tests/integration/test_c5_openlink.py
```

The integration test runs the real OpenLink APK through the real toolchain and checks:

- the plan, all six stages, and the verdict;
- the artifact's binary manifest, decoded independently with androguard (permission
  gone, target receiver `enabled=false`, the other receiver unchanged, intent-filter
  actions unchanged);
- that the original is preserved and the workspace removed.

It also reproduces OpenLink's no-op baseline entry.

## What C.5 does not show

- That the modified APK behaves the same apart from the intended change. Only the
  manifest changed; the receiver's code is still present.
- That the receiver cannot run anyway. OpenLink's DEX references
  `PackageManager.setComponentEnabledSetting`, so components can be re-enabled at
  runtime; which components it targets was not established.
- That boot-time or background work is gone (alarms, WorkManager, other receivers).
- That the APK is free of malware or spyware, safe to install, or runs on a device. It
  was never installed.
- Semantic equality of `resources.arsc` and recompiled resources, or of manifest content
  that DiffEngine does not compare (see known-limitations §16). For C.5 these are covered
  only by the source-level edit check before the build.
