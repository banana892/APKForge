# Phase E evidence — diff + verification hardening

Starting checkpoint: `fda2129` (Phase D). Toolchain for every run here: Apktool 3.0.3,
build-tools 35.0.0 (zipalign 35.0.0, apksigner 0.9), Java 25.0.4.1, android-35;
normalization schema 1, semantic schema 3. Cross-toolchain runs additionally used the
Phase B Docker image `apkforge-toolchain:pinned` (Apktool 2.10.0, build-tools 34, JDK 17).

Design and semantics: [`docs/verification.md`](../../docs/verification.md).
Runner: `build-tests/run_phase_e_validation.py {baseline,openlink} [--write]`.
Phase C and Phase D evidence (`artifacts/pre-phase-d/`, `artifacts/intent-filter-fix/`,
`tests/corpus/results/c5-*`, `tests/corpus/results/phase-d-*`) is not modified.

## Layout

| path | content |
|---|---|
| `normalization/determinism-experiment.{py,json}` | first observation: two no-op rebuilds of 3 APKs, per-entry content and ZIP metadata compared |
| `normalization/first-corpus-run/` | the first schema-2 corpus run, kept as found: AntennaPod `NOT_EQUIVALENT` (manifest-tree finding), Fennec `FAILED` (baseline unusable) — the evidence behind rule `manifest_reference_inlined` and status `BASELINE_PARTIAL` |
| `corpus/corpus-validation.{json,md}` | final corpus run: per APK result, fingerprint by rule/policy, rebuild determinism, fingerprint reproducibility, pair verification, comparator status, drift vs C.5 |
| `corpus/pair-reports/*.md` | verification report (all layers) of each APK's second no-op rebuild against its fingerprint |
| `openlink/openlink-scenarios.{json,md}` | OpenLink scenarios A–K (pipeline + pair verification, negative tests, cross-toolchain) |
| `openlink/reports/*.{json,md}` | full `VerificationReport` per scenario |
| `regression/phase-d-runner-with-phase-e-baseline.md` | `build-tests/run_phase_d_validation.py` (Phase D scenarios A–F) re-run on Phase E code with the schema-2 baseline: all six as expected; the committed Phase D result is not rewritten |

The baseline itself is published once: `tests/corpus/results/phase-e-noise-baseline.json`
(schema 2, SHA-256 `87d80130d76cd8f6f882ec11d2b25dd32a0d78543b85cd56066ec56e9eb48adb`).

## Normalization: from observation to rule

1. **Observation** (`normalization/determinism-experiment.json`): two no-op rebuilds of
   OpenLink, PCAPdroid and UsageDirect with the same toolchain and key have the same
   entry set and **byte-identical content for every entry**, including v1 signature
   files; only entry timestamps differ (ZIP metadata). The final corpus run confirms
   it for all 9 APKs (`rebuild #2 content diffs` = 0).
2. **Classification**: ZIP metadata (timestamps, compression, alignment padding) is
   never content; the raw diff compares content hashes and counts metadata-only
   differences separately. Rebuild noise is reproducible byte for byte, so it can be
   matched by content.
3. **Rule**: the C.5 path rules explain a no-op rebuild; the per-APK fingerprint
   records each explained difference *with its content*; later comparisons accept noise
   only on content identity (`exact`), certificate identity (`signer`), or — for v1
   signature files only — path (`path_only`, validity established by apksigner).
4. **Regression tests**: `tests/unit/test_phase_e_normalization.py`,
   `tests/unit/test_phase_e_archive.py`.
5. **Toolchain**: the fingerprint is bound to the toolchain identity above.

New evidence during Phase E (`normalization/first-corpus-run/`):

- **AntennaPod**: the full manifest tree (new in E3) showed that the rebuild replaces
  `FileProvider android:authorities="@7F130332"` by the literal
  `de.danoeh.antennapod.provider`. The reference has one value in every resource
  configuration, so the runtime value is unchanged. Rule `manifest_reference_inlined`
  accepts exactly this shape, only when the reference resolves to the same single
  value; the fingerprint stores the exact before/after. Drift vs C.5 is recorded with
  the reason "semantic extractor extension".
- **Fennec**: its no-op diff is incomplete (embedded inspector size threshold, known
  limitation §1), so its entry is `UNDETERMINED`. Using no baseline at all made its
  no-op rebuild FAILED (four unpaired resource renames looked unexpected). The entry's
  fingerprint is now used with status `BASELINE_PARTIAL`; the verification is
  UNDETERMINED, which is the truthful result.

## Corpus (Integration F)

| APK | no-op result | fingerprint exact / path_only / signer | rebuild #2 content diffs | reproducible | pair verification |
|---|---|---|---:|---|---|
| com.emanuelef.remote_capture@95 | EQUIVALENT_WITH_RESIDUE | 2236 / 5 / 1 | 0 | yes | VERIFIED |
| com.oF2pks.applicationsinfo@19 | EQUIVALENT_WITH_RESIDUE | 36 / 5 / 1 | 0 | yes | VERIFIED |
| de.audioattack.openlink@28 | EQUIVALENT | 68 / 5 / 1 | 0 | yes | VERIFIED |
| de.danoeh.antennapod@3120295 | EQUIVALENT_WITH_RESIDUE | 1409 / 5 / 1 | 0 | yes | VERIFIED |
| eu.siacs.conversations@4218104 | EQUIVALENT | 1234 / 5 / 1 | 0 | yes | VERIFIED |
| godau.fynn.usagedirect@10 | EQUIVALENT | 470 / 5 / 1 | 0 | yes | VERIFIED |
| io.github.muntashirakon.AppManager@451 | EQUIVALENT_WITH_RESIDUE | 1457 / 5 / 1 | 0 | yes | VERIFIED |
| org.mozilla.fennec_fdroid@1560020 | UNDETERMINED | 2512 / 5 / 1 | 0 | yes | UNDETERMINED (baseline partial, embedded partial) |
| org.schabi.newpipe@1015 | EQUIVALENT | 1086 / 5 / 1 | 0 | yes | VERIFIED |

No unexplained drift from the C.5 baseline: results, per-rule counts and residue are
identical except AntennaPod's one new `manifest_reference_inlined` observation.

## OpenLink (golden integration test)

| scenario | what | result |
|---|---|---|
| A | no-op rebuild vs fingerprint | VERIFIED — 74 noise (content), 0 unexpected |
| B | C.5 modification (pipeline) | VERIFIED — 2 expected, 1 planned entry (`AndroidManifest.xml`), 73 content noise, 0 unexpected/unknown; counts derived from the baseline (74 fingerprint entries − 1 planned) |
| C | undeclared `<meta-data>` | FAILED — `manifest_element added …/meta-data[name=apkforge.test.phase_e]` unexpected (invisible to Phase D) |
| C2 | the same change, declared | expected and unexpected checks pass; run `unverified` because the test modifier has no `verify()` |
| D | marker asset | VERIFIED (expected change pinned to the content SHA-256) |
| E | C.5 + marker | VERIFIED — combined security diff: permission removed, receiver modified, certificate (noise) |
| F | undeclared file | FAILED — unexpected file |
| G | expectation not applied | FAILED — `uses_permission removed android.permission.INTERNET` not observed |
| H | content-hash protection: one `res/` entry altered and re-signed | schema 2: FAILED (content differs from the no-op rebuild); schema 1 path rules: accepted as noise (UNDETERMINED only because legacy noise is path-rule assured) |
| I | truncated APK | FAILED — structural |
| J | entry altered without re-signing | FAILED — signature |
| K1 | baseline used with a declared other toolchain | UNDETERMINED — `BASELINE_INCOMPATIBLE`, 0 noise accepted, 74 unknown |
| K2 | real Apktool 2.10.0 rebuild, toolchain undeclared | FAILED — 65 byte-identical entries accepted, 9 rule-shaped mismatches unknown, 16 real removals unexpected |
| K3 | the same, old toolchain declared | FAILED — `BASELINE_INCOMPATIBLE`, 0 noise accepted |

K2/K3 finding: the Apktool 2.10.0 rebuild drops 16 non-signature `META-INF/` entries
(androidx `*.version` files, licence files, `app-metadata.properties`). These are real
removals, so FAILED rather than UNDETERMINED is the correct outcome.

The original OpenLink SHA-256 was unchanged after every run.

## Tests

`regression/pytest-full-with-corpus.txt`: 891 passed, 0 failed, 0 skipped (860 unit, 21 integration, 10 opt-in corpus). `regression/pytest-unit-force-color-3.txt`: 860 unit tests pass with `FORCE_COLOR=3`. See also
`docs/verification.md`. Commands:

```bash
source tools/env.sh; unset FORCE_COLOR
.venv-validation/bin/python -m pytest -q tests                              # unit + integration
APKFORGE_CORPUS_BUILD=1 .venv-validation/bin/python -m pytest -q tests      # + corpus rebuilds
```

Verification establishes structural/signing validity and plan conformance within the
stated comparator coverage. It does not establish that an APK is safe, and a clean diff
does not prove an APK is malware-free.
