# APKForge build corpus (Phase C.4)

Real F-Droid APKs used as the regression baseline for `BuildService`
(decode → build → align → sign → verify). The APK files themselves are not committed
(`*.apk` is git-ignored); `manifest.json` identifies them.

## Files

| file | purpose |
|---|---|
| `manifest.json` | Corpus definition: per-APK id, filename, **SHA-256**, size, metadata, expected outcome, notes. |
| `results/baseline.json` | Authoritative machine-readable result of the C.4 baseline run. |
| `results/baseline-report.md` | Human-readable report for the same run. |
| `results/c5-semantic-noop-baseline.{json,md}` | C.5 precondition: semantic classification of each no-op rebuild (separate from the C.4 build baseline). |
| `results/c5-toolchain-comparison.{json,md}` | C.5: no-op output of the Phase B toolchain vs the current one (3 APKs). |
| `results/c5-openlink-result.{json,md}` | C.5: the OpenLink boot-receiver modification and its expected-vs-actual verdict. |
| `*.apk` | The corpus APKs (local only). |

## Identity

An entry is identified by its `id` (`<package>@<versionCode>`) and its SHA-256. Filenames
are informational:

- file at the manifest filename with the manifest hash → `OK`
- manifest filename absent, another `*.apk` here has the hash → `RENAMED` (still built)
- file at the manifest filename has a different hash → `HASH_MISMATCH` (**not built**; corpus error)
- no file has the hash → `MISSING` (corpus error)

A replaced APK therefore can never silently become the new baseline. The default test run
(`test_corpus_manifest_matches_files`) fails if a present APK no longer matches its hash.

## Metadata

`package_name`, version, SDK levels and `characteristics` (DEX/native/resource inventory,
ABIs, permission and component counts) were produced by APKForge's `InspectionEngine`:

```bash
.venv-validation/bin/python build-tests/run_corpus_validation.py describe tests/corpus/X.apk
```

Nothing is recorded that the tooling did not establish. `baseline_toolchain` lists the tool
versions the expectations were established with.

## Expected outcomes

Each entry's `expected` is `SUCCESS`, or `FAILURE` with `failure_stage`,
`failure_category` (the canonical `BuildFailureCategory`) and a mandatory documented
`reason`. The manifest loader rejects an expected failure without a reason.

All 9 current entries are expected to `SUCCESS`, based on the C.2 corpus run
(`build-tests/c2_results.json`, 9/9) and the C.3 real-toolchain pipeline. No expected
failures exist.

## Comparison categories

| observed vs. baseline | category | gate |
|---|---|---|
| success → success | `UNCHANGED_SUCCESS` | ok |
| documented failure → same stage + category | `UNCHANGED_KNOWN_FAILURE` | ok |
| failure → success | `IMPROVEMENT` | ok (update the manifest) |
| success → failure | `REGRESSION` | **fail** |
| failure without baseline, or a different failure mode | `NEW_FAILURE` | **fail** |
| success without baseline (previous-run comparison only) | `NEW_SUCCESS` | ok |
| APK missing/replaced | `CORPUS_ERROR` | **fail** |

Repeated runs (default 2) must give the same semantic signature per APK (final status,
failing stage/category, per-stage statuses, input hash, signer digest, no-op integrity
summary). Signed APK bytes are not compared: signatures and timestamps differ by design.

## Running

```bash
# Normal test suite: unit tests + manifest/hash check (no rebuild)
.venv-validation/bin/python -m pytest -q

# Opt-in real-toolchain corpus test (one pytest case per entry, several minutes)
APKFORGE_CORPUS_BUILD=1 .venv-validation/bin/python -m pytest -q tests/integration/test_build_service_corpus.py

# Full validation run: repeated runs, results.json + report.md under work/corpus/<run-id>/
.venv-validation/bin/python build-tests/run_corpus_validation.py run
#   --previous tests/corpus/results/baseline.json   compare with an earlier run as well
#   --only org.schabi.newpipe@1015                  restrict to entries
#   --write-baseline                                refresh results/baseline*.{json,md}

# Manifest and hash check only
.venv-validation/bin/python build-tests/run_corpus_validation.py check
```

Requirements: the C.1/C.2 toolchain (Java 25, Apktool 3.0.3, Android SDK build-tools
35.0.0, platform android-35), discovered by `ToolchainConfig.discover()`. Signing uses
`APKFORGE_SIGNING_*` if set, otherwise the APKForge development key. Exit code of `run`:
0 baseline passed, 1 regression/new failure/corpus error/inconsistency, 2 manifest invalid
or toolchain unavailable.

## Changing the baseline

- **Adding an APK**: copy it here, run `describe`, add an entry with an `expected` outcome
  backed by evidence from an actual run.
- **Recording a known failure**: only with a documented `reason` (root cause, not "it
  failed once") and the evidence (run id / log).
- **Toolchain upgrade**: results produced with a different toolchain are not assumed
  identical; the report flags differences from `baseline_toolchain`. Re-establish the
  baseline and update `baseline_toolchain` deliberately.
