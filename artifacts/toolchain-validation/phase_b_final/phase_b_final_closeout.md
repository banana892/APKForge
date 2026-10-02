# Phase B Final Close-Out: Reproducible Environment and Pre-Phase-C Hardening

Scope: environment lock, environment identity in corpus artifacts, certificate-fallback
status handling, and nested-APK archive safety, plus their validation. No Phase C work, no
ApktoolService wiring, no change to PRC-01/03/05/07/08 or any other security rule, no change
to modification planning or the verifier, no investigation of or workaround for the
historical SHA-1 anomaly. Nothing committed. No historical artifact modified.

`F/` = `artifacts/toolchain-validation/phase_b_final/`,
`RC/` = `artifacts/toolchain-validation/reconciliation/`.

## Changes made

| item | files |
|---|---|
| Lock | `requirements/validation.in` (new), `requirements/validation.lock` (new), `docs/validation-environment.md` (new), `docs/development.md` (pointer), `.gitignore` (`.venv-validation/`) |
| Corpus metadata | `tests/corpus_runner.py`: `environment_identity()` → `meta.environment` (additive; no existing field changed) |
| Certificate fallback | `src/apkforge/intake/certificates.py` (recovered-fallback branch, `_is_complete`, backend labels); `src/apkforge/intake/__init__.py` (`SigningCertificate.extraction_backend`, `.extraction_notes`, additive) |
| Nested archive safety | `src/apkforge/intake/archive.py` (`validate_archive_entries`, extracted from `SafeZipExtractor.list_entries`, which now delegates to it unchanged); `src/apkforge/inspection/embedded.py` (`_nested_entry_names` under `ExtractionLimits`, `EmbeddedFileInspector(limits=…)`); `src/apkforge/inspection/engine.py` (passes `config.extraction`) |
| Tests | `tests/unit/test_phase_b_final_closeout.py` (new, 16 tests) |
| Docs | `docs/known-limitations.md`: new §15 and a status-update section (earlier entries not edited) |

## 1. Environment reproducibility: **PASS**

* Lock: `requirements/validation.lock`, 61 pinned packages, 1,183 `--hash` lines, SHA-256
  `62e61de0ddb41b87771f763c103f1dd1deae655035dc5d615c0fda35c9919acf`
  (`F/lock_identity.txt`). It covers the whole environment: runtime dependencies, their
  transitive dependencies, and the pytest/ruff/mypy dev tools. Compiling it pulled in no
  additional packages.
* The pins come from the reconciliation reference freeze: `validation.in` vs
  `RC/environment_manifest.txt` freeze shows a 0-line diff, and lock pins vs `validation.in`
  shows a 0-line diff (`F/lock_identity.txt`).
* Recreated from scratch with the documented commands (`uv venv --python 3.14.7
  .venv-validation`; `uv pip sync --require-hashes requirements/validation.lock`;
  `uv pip install --no-deps -e .`). All three steps exited 0, and 61 packages were installed
  with hash verification (`F/env_recreate.log`).
* The recreated environment matches the lock and the reference freeze, with 0-line diffs
  for both (`F/freeze_vs_lock.diff`, `F/freeze_vs_reconciliation.diff`; empty files).
* Identity: Python 3.14.7, cryptography 50.0.1, bundled OpenSSL 4.0.2 (25 Aug 2026),
  androguard 4.1.4, asn1crypto 1.5.1, Fedora 44 x86_64
  (`F/environment_manifest_recreated.txt`).
* Every validation run below used `.venv-validation`, not the original `.venv`.

## 2. Environment metadata in corpus artifacts: **PASS**

`F/corpus_results_final.json` → `meta.environment`:
`python_version 3.14.7`, `cryptography_version 50.0.1`,
`cryptography_bundled_openssl "OpenSSL 4.0.2 25 Aug 2026"`, `androguard_version 4.1.4`,
`asn1crypto_version 1.5.1`, `pydantic_version 2.13.5`, `lock_file requirements/validation.lock`,
`lock_sha256 62e61de0…9acf`, plus interpreter path and platform. The lock hash in the
artifact equals the lock file's hash. The baseline artifact has no `meta.environment`
(`F/corpus_comparison.json` → `environment_metadata_baseline_present: false`). All
pre-existing result fields are unchanged.

## 3. Certificate fallback handling: **PASS**

New behaviour: if Androguard fails and the PKCS#7 fallback returns only complete certificates
with no warnings of its own, the Androguard message is attached to each certificate as an
`extraction_notes` entry, `extraction_backend="pkcs7_fallback"` is set, and no warning is
returned, so intake stays COMPLETE. Every other combination (no fallback certificate,
incomplete record, fallback warnings) returns warnings exactly as before. Extraction itself
is unchanged.

* 6 focused tests pass (`F/regression_tests_final_closeout.txt`, `TestCertificateFallbackStatus`).
  They cover: intake COMPLETE with no warnings; full certificate identity retained with
  backend and note recorded; inspection, privacy and security results **identical** with
  and without the injected failure; unrecovered failure still PARTIAL with both warnings;
  incomplete fallback still warns.
* The tests detect the defect: against the pre-fix code, the 3 tests for the new behaviour
  (COMPLETE status, retained-with-note, no downstream degradation) fail, and the 3
  unchanged-behaviour tests pass (`F/regression_tests_against_prefix_code.txt`).
* Real APK: Applications Info with the observed SHA-1 backend failure injected, through the
  full corpus-runner pipeline. All **11/11 capabilities PASS**. Intake is `complete` with
  `warnings []`, `certificate_count 1`, SHA-256 `e71b0ec1…b4e460` (same as the
  reconciliation), `extraction_backend pkcs7_fallback`, and the failure recorded in
  `extraction_notes` (`F/applicationsinfo_injected_failure.json`).

## 4. Nested archive safety: **PASS**

Nested archives (both the PRC-05 code-presence check and ZIP content sniffing) are now listed
through `validate_archive_entries` under the configured `ExtractionLimits`. That enforces
entry count, absolute/traversal/drive-letter path rejection, declared per-entry and total
size, and recursion depth (nested inspection reads one level and never opens an archive found
inside it, so the depth is fixed at 1 and checked against `max_recursion_depth`). Only the
central directory is parsed, as before.

A rejected nested APK is still reported, is marked `has_code=True` (it cannot be proven
code-free, so PRC-05 suppression is not granted), and produces a warning. A rejected archive
found by content sniffing is left unclassified, with a warning. Valid nested APKs behave
exactly as before.

* 10 focused tests pass (`F/regression_tests_final_closeout.txt`, `TestNestedArchiveSafety`).
  They cover entry count over the limit (25 > 20), path traversal, absolute and drive-letter
  paths, the recursion-depth limit, rejection on the sniffing path, a valid code-free
  framework APK (still `has_code=False`, no payload finding), a valid code-bearing APK (still
  detected, payload finding present), a valid APK at exactly the entry limit, and the engine
  passing the configured limits.
* Against the pre-fix code, the 6 hostile-input tests fail and the 4 legitimate-input tests
  pass (`F/regression_tests_against_prefix_code.txt`).
* Real corpus: no nested-limit warning on any APK (`F/corpus_comparison.json` →
  `nested_limit_warnings_in_final: []`), and PRC-05 behaviour on AppManager is unchanged (§6).

## 5. Full corpus: **PASS**

`F/corpus_results_final.json`, `F/corpus_run_stdout.txt`, produced in `.venv-validation`:
**99 evaluations, 96 PASS, 3 PARTIAL, 0 FAIL**, 358.0 s.

* PARTIALs: only `org.mozilla.fennec_fdroid_1560020.apk` → `inspection_full`, `privacy`,
  `security`. Same as the baseline.
* Applications Info: 11/11 PASS.
* Diff pairs: PASS / PARTIAL / PASS, identical to the baseline.
* Full comparison: `F/corpus_comparison.json` (see §9).

## 6. Three-app security validation: **PASS**

Regenerated in `.venv-validation` with `RC/regen_security.py` → `F/final_security/`.
Comparison: `F/security_comparison.json`.

* Counts: OpenLink 5, PCAPdroid 9, AppManager 28 (42 total), the same as the reconciliation.
  No finding added or removed.
* **0 finding-identity differences** (every field except the evidence list, plus evidence
  count). Summaries and all non-evidence fields are equal for all three apps.
* **35/35 reviewed true positives present**, checked individually by app + rule ID, with
  0 severity or confidence changes. `SEC-MAL-ROOT-INDICATORS` is present on AppManager
  (`F/security_comparison.json` → `tp_matrix`, `summary`).
* PRC behaviour (`F/prc_checks.json`):
  * PRC-05: no code-free framework payload findings, and code-bearing payloads (`am.jar`,
    `main.jar`, `SEC-MAL-DYN-LOAD`) are still reported.
  * PRC-07: no bare PEM-header finding.
  * PRC-08: the bundled-cipher findings are absent, and both SHA-1 findings are attributed to
    `…AppManager.apk.signing.Signer` at `low`/`medium`, matching the reconciliation's UNCLEAR
    disposition.
* 12 finding records differ **only** in evidence order or sample. This is pre-existing
  nondeterminism, not a change from this task: unseeded runs of identical code in the
  identical environment produce different evidence digests, and the pre-fix code at a fixed
  `PYTHONHASHSEED` varies run-to-run too, while finding identity stays constant everywhere
  (`F/hashseed_probe_results.txt`). `F/final_security_seeded_hashseed1/` is the output of
  that seed experiment. Recorded as known-limitations §15.

## 7. Unit tests / Ruff / Mypy: **PASS**

| gate | result | artifact |
|---|---|---|
| pytest (full) | **414 passed**, 0 failed, 0 skipped (398 + 16 new) | `F/pytest_full.txt` |
| focused regression | 16 passed | `F/regression_tests_final_closeout.txt` |
| `ruff check src` | 6, the same pre-existing findings as the close-out and reconciliation baselines; none in a touched file | `F/ruff_src.txt` |
| ruff, new test file | clean | `F/ruff_new_test_and_runner.txt` |
| ruff, `tests/corpus_runner.py` | 15 findings, identical to the `HEAD` version of the file: 0 new | `F/ruff_corpus_runner_head_vs_now.txt` |
| `mypy src/apkforge` (non-incremental) | 124 errors; error set identical to the reconciliation set: 0 new | `F/mypy.txt`, `F/mypy_vs_reconciliation.diff` (empty) |

## 8. Historical-artifact preservation: **PASS**

`F/history_check.json`: 81 evidence/report files plus the decoded AntennaPod (30,343 files)
and OpenLink (791 files) trees, checked against the start of this task (the mtime of
`requirements/validation.in`, the first file this task created).

* **0 files modified.**
* Tracked artifacts show no diff vs `HEAD`.
* `RC/corpus_results_reconciliation.json` sha256 matches its recorded value
  (`584e6551…51cd`).
* Nothing is staged; `HEAD` is still `212227f`.
* `tests/corpus_results.json` is overwritten by the runner by design. The reconciliation
  copy was verified identical before the run, and the new run is snapshotted at
  `F/corpus_results_final.json`.

## 9. Differences from the 96/3/0 reconciliation baseline

From `F/corpus_comparison.json` (baseline `RC/corpus_results_reconciliation.json`):

* **Verdict differences: 0** (of 99).
* **Diff-pair differences: 0** (of 3).
* **Substantive field differences: 0.** There are 22 non-timing field differences, and all
  22 are list-ordering only: ABI lists, `finding_categories`, and plan `change_types`, which
  the runner builds with `list(set(...))`. None remains after order normalisation. The same
  effect appears between two pre-task artifacts (close-out vs reconciliation: 19 order-only
  differences; `F/corpus_comparison_control_closeout_vs_reconciliation.json`).
* Timing: 341.1 s → 358.0 s. Durations are excluded from the comparison.
* Added: `meta.environment` (§2).

## 10. Final Phase B gate assessment

The reconciliation left Gate A with one clause unmet (RC/phase_b_regression_reconciliation.md §10):

1. *The 91/8 result is caused by an environment/representation difference*: met in the
   reconciliation, unchanged.
2. *The baseline behaviour is correctly explained*: met in the reconciliation, unchanged.
3. *The project has a documented reproducible environment*: **now met.** There is a hashed,
   complete lock (§1), documented recreation steps (`docs/validation-environment.md`), an
   environment rebuilt from it that is identical to the reference (§1), environment identity
   in every new corpus artifact (§2), and the full corpus reproduced at 96/3/0 in the
   rebuilt environment with zero verdict or substantive differences (§5, §9).

The other requirements also hold:

* All 35 TPs are verified by ID (§6).
* PRC-05/07/08 are unchanged (§6).
* There are no unrelated security-rule changes and no new findings (§6).
* Applications Info is PASS, both normally and with the recoverable failure injected (§3, §5).
* Fennec is the only source of the 3 PARTIALs (§5).
* Historical artifacts are intact (§8).
* There is no Phase C work and no commit.

Residual items are recorded in `docs/known-limitations.md`. None is a Gate A requirement:

* the historical SHA-1 backend event stays unexplained (out of scope by instruction);
* evidence ordering is nondeterministic (§15);
* the top-level archive in `embedded.py` still uses raw `zipfile`, and the 64 MiB detection
  bound is still a separate constant (status update for §14).

**All remaining Gate A requirements are satisfied. PHASE B READY TO CLOSE.**

## Commands

```bash
# Lock (from the reference venv, before any code change)
.venv/bin/python -m pip freeze | grep -v '^-e '            # → requirements/validation.in (with header)
uv pip compile requirements/validation.in --generate-hashes --python-version 3.14 \
  --python-platform x86_64-unknown-linux-gnu -o requirements/validation.lock

# Recreate
uv venv --python 3.14.7 .venv-validation
uv pip sync --python .venv-validation/bin/python --require-hashes requirements/validation.lock
uv pip install --python .venv-validation/bin/python --no-deps -e .

# Validate (all in .venv-validation)
.venv-validation/bin/python -m pytest -q -p no:cacheprovider
.venv-validation/bin/python -m pytest -v -p no:cacheprovider tests/unit/test_phase_b_final_closeout.py
.venv-validation/bin/python -m ruff check src
.venv-validation/bin/python -m mypy --no-incremental src/apkforge
.venv-validation/bin/python tests/corpus_runner.py
.venv-validation/bin/python artifacts/toolchain-validation/reconciliation/regen_security.py F/final_security
.venv-validation/bin/python F/applicationsinfo_injected_failure.py

# Comparisons
.venv-validation/bin/python F/compare_corpus.py   > F/corpus_comparison.json
.venv-validation/bin/python F/compare_security.py > F/security_comparison.json
PYTHONHASHSEED=<n> .venv-validation/bin/python F/hashseed_probe.py

# Pre-fix detection check (scratch copy of src/ with only this task's two fixes reverted)
PYTHONPATH=<scratch>/prefix_src .venv/bin/python -m pytest -q tests/unit/test_phase_b_final_closeout.py -rf
```
