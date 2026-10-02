# Phase B Regression Reconciliation — Applications Info corpus delta

**Scope:** reconciliation only. No Phase C work. Nothing committed. No historical artifact
overwritten. No change to PRC-05 / PRC-07 / PRC-08, PRC-01 / PRC-03, any other security
rule, the modification layer, or the verifier.

**Status of this document:** this is a *correction / reconciliation* artifact. It does not
edit `artifacts/security-validation/prc_validation/findings_review_post_prc.md`, which
remains on disk as written. Two defects in that report are recorded in §6 and §7 below
instead of being silently repaired.

Paths below are repo-relative. `RC/` = `artifacts/toolchain-validation/reconciliation/`,
`CO/` = `artifacts/toolchain-validation/closeout/`,
`PRC/` = `artifacts/security-validation/prc_validation/`,
`SV/` = `artifacts/security-validation/`.

---

## 1. The exact corpus regression

### 1.1 Artifacts located

| run | artifact | verdicts | duration | mtime |
|---|---|---|---|---|
| Step 4 (committed) | `git show 212227f:tests/corpus_results.json` | 96 PASS / 3 PARTIAL / 0 FAIL | 263.8 s | commit `212227f` |
| Phase B close-out baseline | `CO/corpus_results_closeout.json` | **96 / 3 / 0** | 343.3 s | 2026-10-02 13:11:23 +0530 |
| Post-PRC | `PRC/corpus_results_post_prc.json` | **91 / 8 / 0** | 377.2 s | 2026-10-02 15:37:26 +0530 |
| Reconciliation (this task) | `RC/corpus_results_reconciliation.json` | **96 / 3 / 0** | 341.1 s | 2026-10-02 16:0x +0530 |

`PRC/corpus_results_post_prc.json` is byte-identical (sha256
`03295e58d9903abd1058bc85d32ecf68662005e857cdf44f88d846ffc319b3d4`) to the
`tests/corpus_results.json` left in the tree by the 15:36 runner invocation, so it is a
genuine runner output and not a hand-edited file. That file was snapshotted to
`RC/corpus_results_post_prc_preserved.json` before this task's run overwrote it.

### 1.2 Capability-by-capability diff, baseline → post-PRC

Across all 9 APKs × 11 capabilities (99 evaluations) exactly **five** verdicts changed, all
on `com.oF2pks.applicationsinfo_19.apk`:

| capability | baseline | post-PRC |
|---|---|---|
| `intake` | PASS | PARTIAL |
| `inspection_full` | PASS | PARTIAL |
| `privacy` | PASS | PARTIAL |
| `security` | PASS | PARTIAL |
| `modification_planning` | PASS | PARTIAL |

Unchanged on the same APK: `manifest`, `dex`, `native_libraries`, `resources_assets`,
`strings_urls_domains`, `assets` — all PASS in both. A sixth degradation appears at the
diff level: diff pair 1 (`applicationsinfo` vs `openlink`) went PASS → PARTIAL. It is not
one of the 99 and is part of the same cascade.

### 1.3 First failing capability and the dependency chain

The five are **one** regression, not five. `intake` is the only capability that produced a
new diagnostic of its own; every other message is empty or inherited:

```
intake            PARTIAL  warnings = ["Androguard certificate extraction failed:
                                        sha1 is not supported by this backend for RSA signing."]
  └─ inspection_full  PARTIAL  "Failed inspectors: []"   warnings = <the same single string>
                               inspector_statuses: all 8 "complete"
       ├─ privacy        PARTIAL  "Privacy analysis PARTIAL: []"   own warnings = []
       │    └─ security  PARTIAL  "Security analysis PARTIAL: []"  own warnings = []
       └─ modification_planning PARTIAL
                         "Limitations: ['Inspection was partial; proposal generation
                          may miss uninspected components.']"
```

**First failing capability: `intake`.** Sole proximate cause: one warning string appended
by `_extract_via_androguard` in `src/apkforge/intake/certificates.py:80-82`, which sets
intake `status = partial`; `inspection_full` inherits the intake status and warning,
`privacy` and `security` inherit the inspection status (their own `warnings` and `errors`
arrays are empty in the artifact), and `modification_planning` degrades because inspection
is partial.

### 1.4 No analytical content was lost in the post-PRC run

Every substantive field for this APK is identical between the two runs, including the
certificate count — the PKCS#7 fallback in `extract_certificates` (Strategy 2) succeeded,
so the certificate was still extracted:

| field | baseline | post-PRC |
|---|---|---|
| `package_name` | `com.oF2pks.applicationsinfo` | same |
| `file_count` / `dex_count` | 37 / 1 | same |
| **`certificate_count`** | **1** | **1** |
| manifest perms / activities | 4 / 4 | same |
| dex classes / methods | 63 / 413 | same |
| privacy perms / SDKs / endpoints | 4 / 0 / 2 | same |
| security findings | 1 (C0 H0 M0 L1 I0, `network`) | same |
| intake `errors` | `[]` | `[]` |

The delta is a status/warning difference only. No finding, permission, class, endpoint or
certificate was lost.

---

## 2. Controlled commit-vs-working-tree comparison

Both states exercised in the **same** interpreter, venv, host and APK, via
`RC/controlled_runs/controlled_intake.py` (the apkforge source tree is selected by
`sys.argv[1]`, asserted against `apkforge.__file__`).

* **State A** — commit `212227f` (the Phase B close-out commit), materialised with
  `git worktree add -f --detach <scratch>/wt_212227f 212227f`.
* **State B** — the current working tree, `/home/naishring/APKForge/src`.

APK: `tests/corpus/com.oF2pks.applicationsinfo_19.apk`, sha256
`…` as recorded in both JSON files.

| probe | State A (`212227f`) | State B (working tree) |
|---|---|---|
| `intake` capability verdict | **PASS** | **PASS** |
| `APKIntakeService.process` status | `complete` | `complete` |
| intake warnings / errors | `[]` / `[]` | `[]` / `[]` |
| `extract_certificates` cert count | 1 | 1 |
| `extract_certificates` warnings | `[]` | `[]` |
| cert SHA-1 fingerprint | `311dc975ac2d106fb239a0e2618322f1c1f4ba9b` | same |
| cert SHA-256 fingerprint | `e71b0ec100a2a93675f5e5c9b0fa2674b0658fa399e9fdbc1bce8ec063b4e460` | same |
| `androguard APK.get_certificates()` | **OK**, 1 cert | **OK**, 1 cert |
| v1 signer digest / signature alg | `sha1` / `rsassa_pkcs1v15` | same |
| `min_sdk` / signed attrs present | 16 / `False` | same |
| backend SHA-1 RSA **sign** | OK | OK |
| backend SHA-1 RSA **verify** | OK | OK |

Field-by-field comparison of the two JSON captures (excluding the tag/timestamp/source-path
fields): **17 fields identical, 0 differing.**

Artifacts: `RC/controlled_runs/state_A_commit_212227f.json`,
`RC/controlled_runs/state_B_working_tree.json`.

**Verdict: this is case A (not a code regression).** The historical commit and the current
working tree produce the same result, and that result is PASS.

### 2.1 Why the failure cannot come from project code

The exception text is emitted by the `cryptography` Rust extension, not by any Python
source in the venv or the repo:

```
$ grep -rn "is not supported by this backend for" .venv/.../cryptography --include=*.py
   → only ML-KEM / ML-DSA messages; no RSA message
$ strings .venv/.../cryptography/hazmat/bindings/_rust.abi3.so | grep "not supported by this backend for"
   → "2 is not supported by this backend for RSA signing."
```

The call path is entirely inside androguard:
`APK.get_certificates()` → `get_certificates_v1()` → `get_certificate_der()` →
`verify_signer_info_against_sig_file()` → `verify_signature()` →
`public_key.verify(sig, sf_bytes, PKCS1v15(), SHA1())`
(`.venv/.../androguard/core/apk/__init__.py:1914-1968`). androguard catches only
`InvalidSignature` there, and `get_certificate_der` catches only
`(ValueError, TypeError, OSError, InvalidSignature)`, so `UnsupportedAlgorithm` propagates
out of `get_certificates()` and is caught by APKForge's broad `except Exception` at
`src/apkforge/intake/certificates.py:79`.

APKForge touches `cryptography` in exactly one place
(`src/apkforge/intake/certificates.py:134`) and contains no FIPS, provider,
`OPENSSL_CONF`, `default_backend` or security-level manipulation:

```
$ grep -rniE "fips|_enable_fips|openssl_conf|default_backend|set_fips|SECLEVEL" src/ tests/corpus_runner.py
   → no matches
```

The working-tree diff to `certificates.py` is 4 lines and is the getattr audit only
(`getattr(cert, "not_valid_before_utc", None)` → `cert.not_valid_before_utc`). It cannot
affect `get_certificates()`, which is called earlier and whose failure is what produced the
warning.

### 2.2 Why the blast radius is exactly one APK

`com.oF2pks.applicationsinfo_19.apk` is the **only** APK in the 9-APK corpus whose v1
signature uses SHA-1:

| APK | minSdk | v1/v2/v3 | v1 digest / signature |
|---|---|---|---|
| `com.emanuelef.remote_capture_95` | 23 | T T T | sha256 / rsassa_pkcs1v15 |
| **`com.oF2pks.applicationsinfo_19`** | **16** | T T T | **sha1 / rsassa_pkcs1v15** |
| `de.audioattack.openlink_28` | 21 | T T T | sha256 / rsassa_pkcs1v15 |
| `de.danoeh.antennapod_3120295` | 23 | T T T | sha256 / rsassa_pkcs1v15 |
| `eu.siacs.conversations_4218104` | 23 | T T F | sha256 / rsassa_pkcs1v15 |
| `godau.fynn.usagedirect_10` | 21 | T T T | sha256 / rsassa_pkcs1v15 |
| `io.github.muntashirakon.AppManager_451` | 21 | T T T | sha256 / rsassa_pkcs1v15 |
| `org.mozilla.fennec_fdroid_1560020` | 26 | T T T | sha256 / rsassa_pkcs1v15 |
| `org.schabi.newpipe_1015_cb84069` | 23 | T T T | sha256 / rsassa_pkcs1v15 |

A process-wide condition in which the OpenSSL backend refuses to configure SHA-1 as an RSA
signature digest would therefore degrade **exactly one** APK and leave the other eight
untouched — which is precisely the observed 5-PARTIAL pattern. This is positive evidence
that the trigger is the APK's SHA-1 signature meeting a backend-level condition, and not a
code path that the PRC changes introduced (every PRC change is in the security/inspection
layers, which run *after* intake and which produced identical output in both runs).

### 2.3 Reproduction attempts (all negative)

| attempt | result |
|---|---|
| `extract_certificates`, 40 in-process iterations | 0 failures (`RC/flaky_probe.py`) |
| `extract_certificates`, 20 separate processes | 0 failures |
| `APKIntakeService.process` alone / twice in one process | PASS, PASS |
| Applications Info intake after a full PCAPdroid pipeline in the same process (corpus order) | PASS |
| Raw `cryptography` RSA SHA-1 sign and verify | both OK |
| Same, with `OPENSSL_CONF=/etc/pki/tls/openssl.cnf` (Fedora policy sets `rh-allow-sha1-signatures = no`) | sign OK — the bundled upstream OpenSSL 4.0.2 does not implement the Fedora `rh-*` switch |
| `backend._enable_fips()` | cannot be enabled — the wheel ships no `fips.so` (`dlfcn_load … fips.so: No such file or directory`), so FIPS is not the mechanism |
| Full 9-APK corpus at the working tree | 96 / 3 / 0, no warning |

Occurrences of the string `is not supported by this backend for RSA signing` across the
four corpus artifacts: Step 4 **0**, close-out **0**, post-PRC **5**, reconciliation **0**.

**The condition is not reproducible in the current environment: 0 failures in 60+ attempts
plus a clean full-corpus run.** It occurred in exactly one of four corpus runs executed
against an unchanged venv.

---

## 3. Environment / dependency drift

### 3.1 Captured environment

Full manifest: `RC/environment_manifest.txt` (includes `pip freeze`).

| item | value |
|---|---|
| host | Fedora 44, Linux 7.2.7-200.fc44.x86_64 |
| Python | 3.14.7 (`/home/naishring/APKForge/.venv/bin/python`) |
| `cryptography` | **50.0.1**, bundled **OpenSSL 4.0.2 25 Aug 2026** |
| backend repr | `<OpenSSLBackend(version: OpenSSL 4.0.2 …, FIPS: False, Legacy: True)>` |
| `androguard` | 4.1.4 |
| `asn1crypto` | 1.5.1 |
| `pyOpenSSL` | **not installed** |
| system OpenSSL (used by `hashlib`/`ssl`) | 3.5.8 — separate from the bundled build |
| `/proc/sys/crypto/fips_enabled` | 0 |
| system crypto policy | `DEFAULT`, `rh-allow-sha1-signatures=no` (does not reach the bundled OpenSSL) |
| `OPENSSL_CONF` | unset |
| SHA-1 RSA signing available now | yes |

### 3.2 No drift between the baseline and post-PRC runs

```
.venv/pyvenv.cfg                              2026-09-29 19:22:55
.venv/lib/python3.14/site-packages/cryptography-50.0.1.dist-info/   2026-09-29 19:45:08
.venv/lib/python3.14/site-packages/androguard/ , androguard-4.1.4.dist-info/   2026-09-29 19:45:08
```

The last package installation predates **all four** corpus runs (Sep 30 21:20, Oct 2 13:11,
Oct 2 15:36, Oct 2 16:0x). No package was installed, upgraded or removed between the
96/3/0 baseline and the 91/8/0 post-PRC run. **A dependency version change is ruled out as
the cause**, and therefore no pin is added — the evidence does not justify one (see §3.4).

### 3.3 No preserved historical Python-environment evidence

Searched: `artifacts/**`, `docs/**`. The only environment record in the repository is
`CO/openlink_acceptance/toolchain_versions.txt`, which pins the **Android** toolchain
(Apktool 2.10.0, apksigner 0.9, JDK 17.0.20.1, image `sha256:79434918ee5e…`). There is **no
`pip freeze`, interpreter version, or OpenSSL record for any historical run.** Consequently
the post-PRC environment cannot be compared field-by-field against the baseline
environment — only the venv mtimes above establish that the installed packages were the
same. `RC/environment_manifest.txt` is the first such record; it is additive.

### 3.4 Pin / lock mechanism

`pyproject.toml` declares open lower bounds only — `androguard>=4.0.0`,
`cryptography>=42.0.0`, `pydantic>=2.7,<3`, `typer>=0.12,<1`, `rich>=13.7,<15`,
`pyyaml>=6.0` — and there is **no lock file, `requirements.txt`, or constraints file** in
the repository. The project therefore has **no reproducible-environment mechanism**.

No pin was added. Per the task constraint, a pin requires evidence that a specific version
difference is responsible; §3.2 shows there was no version difference. Adding
`cryptography==50.0.1` now would pin the project to the very version under which the
anomaly was observed, on no evidence, and would be a dependency-policy change outside this
task. The gap is recorded as an open item in §7 and in `docs/known-limitations.md` §10.

### 3.5 Root cause statement

The regression is **not** a code regression and **not** a dependency-version regression. It
was a **transient, non-reproducible failure of the OpenSSL backend to configure SHA-1 as an
RSA signature digest** (`UnsupportedAlgorithm: sha1 is not supported by this backend for
RSA signing.`, raised from `cryptography`'s Rust RSA signature-context setup) during
androguard's v1 signature verification, inside the single corpus APK that is SHA-1 signed.
Its exact trigger is **not established** — this is the one residual uncertainty, and it is
recorded as such rather than attributed to a guessed mechanism. What is established:

1. the failing call is inside `cryptography`'s native extension, reached only through
   androguard, with no APKForge code in the path that could influence it (§2.1);
2. the working tree and the close-out commit behave identically (§2);
3. no dependency changed (§3.2);
4. the blast radius matches the one SHA-1-signed APK exactly (§2.2);
5. it does not reproduce in 60+ attempts or in a full corpus run (§2.3);
6. no analytical content was lost even when it did occur (§1.4).

It is also worth stating plainly what the event exposed in APKForge's own code, as a
robustness weakness rather than a regression: a **recoverable** androguard failure is
recorded as a permanent intake warning even when Strategy 2 extracts the same certificate
successfully, and that single warning then degrades five capability verdicts. No code was
changed for this (the working tree did not cause the regression, so the task's Task 4
precondition is not met); it is recorded as an open item in §7 and in
`docs/known-limitations.md` §11.

---

## 4. Final corpus result

`RC/corpus_results_reconciliation.json`, `RC/corpus_run_reconciliation_stdout.txt`.
Command: `.venv/bin/python tests/corpus_runner.py`, current working tree, same host and venv.

```
  Total tests: 99
  PASS:        96
  PARTIAL:     3
  FAIL:        0
  N/A:         0
  Duration:    341.1s
```

Compared against `CO/corpus_results_closeout.json` across all 99 capability evaluations:
**0 differences.** The 3 PARTIALs are the same APK and the same three capabilities as the
baseline (`org.mozilla.fennec_fdroid`: `inspection_full`, `privacy`, `security`), with the
same known cause (`lib/arm64-v8a/libxul.so` at 156,864,024 B > `_MAX_DETECT_SIZE` 64 MiB,
`src/apkforge/inspection/embedded.py:53`; known-limitations §2).

All three diff pairs also match the baseline exactly, including pair 1 returning to PASS:

| diff pair | baseline | post-PRC | reconciliation |
|---|---|---|---|
| applicationsinfo vs openlink | PASS | PARTIAL | **PASS** |
| applicationsinfo vs fennec | PARTIAL | PARTIAL | PARTIAL |
| pcapdroid vs antennapod | PASS | PASS | PASS |

Applications Info in this run: `intake PASS, inspection_full PASS, manifest PASS, dex PASS,
native_libraries PASS, resources_assets PASS, strings_urls_domains PASS, assets PASS,
privacy PASS, security PASS, modification_planning PASS` — 11/11.

### 4.1 Other gates re-run at the working tree

The recorded `PRC/` static-analysis and test artifacts predate the final source edits
(`src/apkforge/security/rules.py` 15:38:50, `src/apkforge/security/vulnerabilities/crypto.py`
15:38:35, both **after** the 15:36 corpus run and the 15:24 findings artifacts), so all
gates were re-run.

| gate | result | artifact |
|---|---|---|
| `pytest -q` | **398 passed, 0 failed, 0 skipped**, 9.62 s | `RC/pytest_reconciliation.txt` |
| `ruff check src` | **6 errors** — identical count to the close-out baseline (`CO/ruff_closeout.txt`, 6) and to `PRC/ruff_validation.txt` (6); **no new finding** | `RC/ruff_reconciliation_src.txt` |
| `mypy src/apkforge` | **124 errors in 12 files** — after line-number normalisation the error set is **byte-identical** to `CO/mypy_closeout.txt` (124); **no new error** | `RC/mypy_reconciliation.txt` |

Note on `PRC/mypy_validation.txt`: it records 123 errors, one fewer than both the close-out
baseline and this run. The missing entry is
`src/apkforge/modification/serialization.py: Returning Any from function declared to return "str"`
in a file that is **not modified** in the working tree (`git status` clean for it). That
record is therefore incomplete — consistent with a mypy incremental-cache artifact — and is
not evidence of a change in either direction. Recorded, not edited.

No focused regression test was added: Task 4 is conditional on the working tree having
introduced the regression, and §2 demonstrates it did not. A test asserting "Applications
Info intake yields no warning" would pass at both `212227f` and the working tree and would
not have caught the observed event.

---

## 5. True-positive verification by app + rule ID

`PRC/findings_review_post_prc.json` was built from raw findings generated at 14:56–15:24,
before the final `rules.py` / `crypto.py` edits at 15:38. Its "35 == 35" is therefore not
evidence about the current code. The three-app findings were **regenerated at the current
working tree** (`RC/regen_security.py` → `RC/final_security/raw_{openlink,pcapdroid,appmanager}_security.json`)
and each of the 35 baseline true positives was checked individually by app and rule ID.

Findings totals at the working tree: OpenLink 5, PCAPdroid 9, AppManager 28 — **42 total**,
down from 59.

| app | rule_id = finding_id | present | severity base→final | confidence base→final | evidence |
|---|---|---|---|---|---|
| appmanager | `SEC-COMB-ACCESSIBILITY-OVERLAY` | ✓ | high→high | high→high | 2 |
| appmanager | `SEC-MAL-CODE-EXEC` | ✓ | high→high | high→high | 3 |
| appmanager | `SEC-MAL-DYN-LOAD` | ✓ | high→high | confirmed→confirmed | 2 |
| appmanager | `SEC-MAL-DYNLOAD-001` | ✓ | high→high | high→high | 1 |
| appmanager | `SEC-MAL-EXEC-001` | ✓ | high→high | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_am_jar` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_blanks_blank_odp` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_blanks_blank_odt` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_blanks_blank_pdf` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_blanks_blank_pptx` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_dexopt_baseline_prof` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PAYLOAD-ENTROPY-assets_main_jar` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-MAL-PERSISTENCE-BOOT` | ✓ | low→low | high→high | 1 |
| appmanager | `SEC-MAL-PERSISTENCE-FG-SERVICE` | ✓ | informational→informational | confirmed→confirmed | 5 |
| appmanager | **`SEC-MAL-ROOT-INDICATORS`** | **✓** | low→low | medium→medium | **5** |
| appmanager | `SEC-SPY-ACCESSIBILITY-001` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-SPY-ACCESSIBILITY-ABUSE` | ✓ | medium→medium | confirmed→confirmed | 1 |
| appmanager | `SEC-SPY-CALLS-001` | ✓ | medium→medium | medium→medium | 2 |
| appmanager | `SEC-SPY-CLIPBOARD-001` | ✓ | low→low | medium→medium | 2 |
| appmanager | `SEC-SPY-DEVICE-IDENTIFIERS` | ✓ | medium→medium | high→high | 23 |
| appmanager | `SEC-SPY-OVERLAY-001` | ✓ | medium→medium | high→high | 1 |
| appmanager | `SEC-VULN-BACKUP-001` | ✓ | low→low | confirmed→confirmed | 1 |
| appmanager | `SEC-VULN-EXPORTED-RECEIVER` | ✓ | low→low | confirmed→confirmed | 4 |
| appmanager | `SEC-VULN-MANIFEST-BACKUP` | ✓ | low→low | confirmed→confirmed | 1 |
| openlink | `SEC-MAL-PERSISTENCE-BOOT` | ✓ | low→low | high→high | 1 |
| openlink | `SEC-NET-CLEARTEXT-URLS` | ✓ | low→low | high→high | 1 |
| openlink | `SEC-VULN-BACKUP-001` | ✓ | low→low | confirmed→confirmed | 1 |
| openlink | `SEC-VULN-EXPORTED-RECEIVER` | ✓ | low→low | confirmed→confirmed | 1 |
| openlink | `SEC-VULN-MANIFEST-BACKUP` | ✓ | low→low | confirmed→confirmed | 1 |
| pcapdroid | `SEC-MAL-PERSISTENCE-BOOT` | ✓ | low→low | high→high | 1 |
| pcapdroid | `SEC-MAL-PERSISTENCE-FG-SERVICE` | ✓ | informational→informational | confirmed→confirmed | 2 |
| pcapdroid | `SEC-NET-CLEARTEXT-URLS` | ✓ | low→low | high→high | 4 |
| pcapdroid | `SEC-SPY-CLIPBOARD-001` | ✓ | low→low | medium→medium | 2 |
| pcapdroid | `SEC-VULN-BACKUP-001` | ✓ | low→low | confirmed→confirmed | 1 |
| pcapdroid | `SEC-VULN-MANIFEST-BACKUP` | ✓ | low→low | confirmed→confirmed | 1 |

**35 expected, 35 present, 0 missing, 0 severity changes, 0 confidence changes.**
Machine-readable: `RC/tp_matrix.json` (one row per TP, with `present_in_final`,
`present_in_stale_post_prc`, both severities, both confidences, evidence count).

No finding absent from the baseline appeared in any app (`NEW = []` for all three), so the
42 are a strict subset of the 59 and the 17-finding reduction is entirely AppManager FPs.

### 5.1 `SEC-MAL-ROOT-INDICATORS` specifically

Verified present in `RC/final_security/raw_appmanager_security.json` with severity `low`,
confidence `medium`, and **5 evidence items** — the same severity and confidence as the
baseline. Its earlier disappearance is explained by the `_MAX_STRINGS = 100_000` truncation
budget in `src/apkforge/inspection/dex.py:65`: the PRC-08 provenance work began appending
crypto-keyword `const-string` references (with owning class) during class iteration, before
the general string-pool loop, so the pool was truncated earlier and the root-indicator
strings fell outside it. The subsequent dex.py change added the dedup guard
`s_val not in string_set` at the pool loop (`dex.py:382-390`), recovering budget. The
dependence of this rule on a truncation cap is a real fragility and is recorded as an open
item in §7 and `docs/known-limitations.md` §12 — verified present here, but by a margin
this artifact does not measure.

---

## 6. AppManager SHA-1 accounting — final disposition

### 6.1 Where the "5 (or 3)" came from

Resolved, and it was never two answers to the same question. `PRC/findings_review_post_prc.json`
`totals` records `false_positives: 5, retained_fps_count: 5`, which is the **global**
retained-FP count across all three apps. `PRC/findings_review_post_prc.md` §1 then prints
`AppManager FP Rate … 17.9% (5/28)` — that line applies the **global** FP count of 5 to
**AppManager's** finding total of 28. AppManager's own retained FP count is **3**
(`SEC-NET-CLEARTEXT-URLS` + the two SHA-1 findings), giving 3/28 = **10.7%**, not 17.9%.
The published 17.9% is an arithmetic error and is corrected here rather than in that file.

Full reconciliation of all 42 surviving findings against their baseline verdicts:

| baseline verdict | surviving | which |
|---|---|---|
| TRUE_POSITIVE | 35 | §5 |
| FALSE_POSITIVE | 3 | pcapdroid `SEC-SPY-ACCESSIBILITY-001`, pcapdroid `SEC-SPY-ACCESSIBILITY-ABUSE` (both PRC-01/PRC-03, out of scope), appmanager `SEC-NET-CLEARTEXT-URLS` (PRC-03, out of scope) |
| UNCLEAR | 2 | pcapdroid `SEC-SPY-DEVICE-IDENTIFIERS`, appmanager `SEC-NET-CAPABILITY-FLOW` |
| FALSE_POSITIVE, re-dispositioned below | 2 | appmanager `SEC-VULN-CRYPTO-WEAK-HASH`, appmanager `SEC-VULN-WEAK-HASH-001` |
| | **42** | |

### 6.2 The two findings

Both from `RC/final_security/raw_appmanager_security.json`, current working tree:

| field | `SEC-VULN-CRYPTO-WEAK-HASH` | `SEC-VULN-WEAK-HASH-001` |
|---|---|---|
| rule ID / finding ID | `SEC-VULN-CRYPTO-WEAK-HASH` | `SEC-VULN-WEAK-HASH-001` |
| category | `crypto` | `vulnerability` |
| severity (unchanged) | `low` | `low` |
| confidence (unchanged) | `medium` | `medium` |
| evidence location | `class:io.github.muntashirakon.AppManager.apk.signing.Signer` | same |
| evidence description | "Weak hash algorithm referenced in …Signer: SHA-1" | "Discovered string pattern in …Signer: SHA-1" |
| snippet | `SHA-1` | `SHA-1` |
| matching code | `crypto.py` analyzer §3 (weak hashes) gated on `index.is_string_attributed_to_app` | `rules.py` `_evaluate_condition`, `string_any` with `is_crypto=True` |

### 6.3 Why the string is attributed to the application — independently verified

Provenance read directly from `DEXInspection.strings` (`RC/sha1_provenance.py` →
`RC/sha1_provenance.json`), independent of the rule engine:

| string | total refs | app-owned classes | BouncyCastle | other third-party | unattributed |
|---|---|---|---|---|---|
| `SHA-1` | 31 | **5** | 17 | 9 | 0 |
| `SHA1` | 27 | **0** | 20 | 6 | 1 |
| `DESede` | 9 | 0 | 9 | 0 | 0 |
| `Blowfish` | 5 | 0 | 5 | 0 | 0 |

The 5 app-owned `SHA-1` sites, by method:

```
io.github.muntashirakon.AppManager.apk.signing.Signer.logEncoded
io.github.muntashirakon.AppManager.utils.DigestUtils.getDigests
io.github.muntashirakon.AppManager.details.info.AppInfoFragment.lambda$onViewCreated$7$…
io.github.muntashirakon.AppManager.fm.dialogs.ChecksumsDialogFragment$ChecksumsViewModel.generateChecksums
io.github.muntashirakon.AppManager.fm.dialogs.ChecksumsDialogFragment.lambda$onCreateDialog$1$…
```

Other third-party owners of `SHA-1` (not app, not BouncyCastle): `com.android.apksig.*`
(`V1SchemeVerifier`, `DigestAlgorithm`, `OidConstants`), `android.sun.security.*`,
`com.google.common.hash.Hashing$Sha1Holder`, `com.android.tools.smali.dexlib2.writer.DexWriter`,
`org.jf.dexlib2.writer.DexWriter`.

Two things follow, and they are separate claims:

* **Attribution claim — objectively TRUE.** `SHA-1` genuinely occurs in application-owned
  code in 5 classes across 5 methods. The baseline FP cause (the string attributed solely
  to bundled BouncyCastle) is genuinely fixed by PRC-08, and the companion string `SHA1` —
  which has **zero** app-owned references — is correctly suppressed. PRC-08 is working as
  specified.
* **Vulnerability claim — not objectively determinable by the current rule.** Both rules
  match a bare string with no use-site semantics. The observable app-owned call sites are
  checksum and display paths (`DigestUtils.getDigests`, `ChecksumsDialogFragment.generateChecksums`,
  `AppInfoFragment` rendering a signing-certificate fingerprint), which is exactly the case
  each rule's own `limitations` field already disclaims — "MD5 and SHA-1 are frequently used
  for non-cryptographic cache keys or file integrity checksums". The fifth site,
  `Signer.logEncoded`, sits inside AppManager's APK-signing implementation, where SHA-1 is
  **mandated** by the v1 JAR signature format for backward compatibility and so is not a
  defect either — but the rule has no API or usage analysis that could establish any of
  this.

### 6.4 Final disposition

**Both findings are RETAINED, at unchanged severity `low` and unchanged confidence
`medium`, and are classified UNCLEAR — neither TRUE_POSITIVE nor FALSE_POSITIVE.**

* They are **not** false positives: the attribution the rule asserts is verifiably correct
  (§6.3), so the baseline's stated FP cause no longer holds.
* They are **not** true positives: the vulnerability the rule implies is not established,
  and the rule's own semantics cannot establish it.
* **No severity or confidence was changed.** The published values (`low` / `medium`) are
  the ones already assigned; nothing was downgraded to improve a metric.

The classification uncertainty is documented rather than forced. New proposed rule change,
**recorded only, not applied**:

> **PRC-13** — `SEC-VULN-CRYPTO-WEAK-HASH` / `SEC-VULN-WEAK-HASH-001`: a weak-hash finding
> should require a use-site signal (e.g. `MessageDigest.getInstance` / `Signature.getInstance`
> reached from the owning method, or the algorithm string flowing into a signing or
> password API) rather than string presence alone, and should exclude algorithm strings
> whose only app-owned uses are checksum/display paths or v1 JAR-signature compatibility.

### 6.5 FP accounting under each reading, stated explicitly

So the number cannot be hidden behind the classification choice:

| reading | TP | FP | UNCLEAR | overall FP rate | AppManager FP rate |
|---|---|---|---|---|---|
| **1** — SHA-1 pair = FALSE_POSITIVE (the stale report's totals) | 35 | 5 | 2 | 5/42 = **11.9%** | 3/28 = **10.7%** (not 17.9%) |
| **2** — SHA-1 pair = UNCLEAR (**adopted**, §6.4) | 35 | **3** | 4 | 3/42 = **7.1%** | 1/28 = **3.6%** |
| **3** — SHA-1 pair = TRUE_POSITIVE | 37 | 3 | 2 | 7.1% | 3.6% |

Reading 3 is **rejected**: it would assert a vulnerability claim §6.3 shows is
unestablished, and it would inflate the TP count above the 35 reviewed. Reading 2 is
adopted on the evidence in §6.3. Under every reading the baseline's 37.3% FP rate and the
35 TPs are improved or held, and PRC-05/07/08 remain validated.

---

## 7. Known-limitations observations reviewed

Both recorded in `docs/known-limitations.md` (new §10–§13). No redesign performed.

### 7.1 Bundled-library attribution uses a hardcoded provider list

`SecurityEvidenceIndex.is_string_attributed_to_app` (`src/apkforge/security/rules.py:118-147`)
names exactly two providers:

```python
c.startswith(("org.bouncycastle.", "org.spongycastle."))
```

in all three of its branches. **Should be recorded: yes.** Evidence that the limitation is
live rather than theoretical comes from this APK: of the 31 `SHA-1` references, 9 belong to
third-party code that is *not* in the list — `com.android.apksig.internal.apk.v1.V1SchemeVerifier`,
`com.android.apksig.internal.apk.v1.DigestAlgorithm`, `com.android.apksig.internal.oid.OidConstants`,
`android.sun.security.x509.AlgorithmId`, `android.sun.security.pkcs12.PKCS12KeyStore`,
`com.google.common.hash.Hashing$Sha1Holder`, `com.android.tools.smali.dexlib2.writer.DexWriter`,
`org.jf.dexlib2.writer.DexWriter`, `com.android.apksig.internal.pkcs7.AlgorithmIdentifier`
(`RC/sha1_provenance.json`). None is suppressed as a bundled provider. In AppManager this
is harmless because app-owned references exist anyway and the app-prefix branch wins first;
in an app that bundles Conscrypt, Tink, `javax.crypto` shims, jose4j, Netty-tcnative or an
Apache Commons Codec equivalent and has **no** app-owned reference, the same misattribution
PRC-08 was written to fix would recur. The suppression is also provider-specific rather
than general ("is this class part of the application?"), so the list must grow per library.
Recorded as a **known limitation** — PRC-08's measured effect on the reviewed corpus stands;
the generalisation beyond BouncyCastle/SpongyCastle is untested.

### 7.2 Nested APK inspection and archive-safety limits — **limits are NOT enforced**

Verified, with sufficient evidence to document rather than leave open.

Top-level intake routes archive access through `SafeZipExtractor`
(`src/apkforge/intake/archive.py:80-246`) with `ExtractionLimits`
(`src/apkforge/core/config.py:74-113`): `max_file_count` 10,000, `max_single_file_bytes`
256 MiB, `max_total_size_bytes` 1 GiB, `max_recursion_depth` 4, plus per-entry path-traversal
validation. That class's docstring states the limits "must be respected by every future
extraction implementation".

`src/apkforge/inspection/embedded.py` does **not** use it:

```
$ grep -n "ZipFile\|BytesIO\|SafeZip" src/apkforge/inspection/embedded.py
70:                    zipfile.ZipFile(io.BytesIO(data), "r") as inner_zf,      # nested, _detect_file_type
112:            with zipfile.ZipFile(apk_path, "r") as zf:                      # top-level, raw
149:                                zipfile.ZipFile(io.BytesIO(data), "r") as inner_zf,  # nested, PRC-05
```

It imports neither `SafeZipExtractor` nor `ExtractionLimits`. So:

* **Not enforced for nested archives:** `max_file_count` (a nested APK may declare
  unlimited entries), `max_total_size_bytes`, `max_recursion_depth`, and path validation.
* **Partially mitigated by a different, unrelated constant:** the enclosing loop skips
  entries whose *declared uncompressed* size exceeds `_MAX_DETECT_SIZE = 64 MiB`
  (`embedded.py:53,128`) before reading, so a single nested entry read is bounded at 64 MiB
  — but by a module constant that is not configurable and is not the configured
  `max_single_file_bytes` (256 MiB). The two limits are independent and inconsistent.
* **Bounded decompression:** both nested reads call only `inner_zf.namelist()`, which parses
  the central directory and decompresses **no** inner entry. The classic nested
  decompression bomb is therefore not amplified; the exposure is the 64 MiB in-memory
  `bytes` plus `io.BytesIO` copy per candidate entry, and an unbounded central-directory
  entry count.
* **PRC-05 specifically** (`embedded.py:149-155`) inherits exactly this posture: it reads
  the nested central directory in memory under no configured limit.

Recorded as a **known limitation with a concrete, verified scope** — not an open
verification item, since the code paths and the absent imports are both established above.
No redesign of nested archive handling was attempted, per the task constraint.

### 7.3 Additional open items recorded (from this reconciliation)

* **No reproducible Python environment** — open bounds only, no lock file, no preserved
  `pip freeze` for any historical run (§3.3, §3.4). *Unresolved defect* in process terms;
  this is the item that blocks a clean "no real regression" close (see §9).
* **Recoverable certificate-extraction failures degrade five capability verdicts** — a
  warning retained even when the fallback succeeds, with no code change made here (§3.5).
* **`SEC-MAL-ROOT-INDICATORS` depends on the `_MAX_STRINGS` truncation budget** (§5.1).

---

## 8. Commands used

```bash
# Corpus artifacts and capability diff
git show 212227f:tests/corpus_results.json
python3 <diff script>   # baseline CO/corpus_results_closeout.json vs PRC/corpus_results_post_prc.json

# Controlled A/B (same venv, same APK, same host)
git worktree add -f --detach <scratch>/wt_212227f 212227f
.venv/bin/python RC/controlled_runs/controlled_intake.py <scratch>/wt_212227f/src A_commit_212227f \
    /home/naishring/APKForge/tests/corpus/com.oF2pks.applicationsinfo_19.apk
.venv/bin/python RC/controlled_runs/controlled_intake.py /home/naishring/APKForge/src B_working_tree \
    /home/naishring/APKForge/tests/corpus/com.oF2pks.applicationsinfo_19.apk

# Error-origin and backend probes
grep -rn "is not supported by this backend for" .venv/lib/python3.14/site-packages/ --include=*.py
strings .venv/lib/python3.14/site-packages/cryptography/hazmat/bindings/_rust.abi3.so \
    | grep -i "not supported by this backend for"
grep -rniE "fips|_enable_fips|openssl_conf|default_backend|set_fips|SECLEVEL" src/ tests/corpus_runner.py
OPENSSL_CONF=/etc/pki/tls/openssl.cnf .venv/bin/python -c '<RSA SHA-1 sign/verify>'
.venv/bin/python -c 'from cryptography.hazmat.backends.openssl.backend import backend; backend._enable_fips()'

# Signature algorithm survey across the corpus, reproducibility probes
.venv/bin/python -c '<androguard per-APK digest/signature survey>'
.venv/bin/python RC/flaky_probe.py 40           # in-process
for i in $(seq 1 20); do .venv/bin/python RC/flaky_probe.py 1; done   # separate processes

# Environment
stat -c '%y %n' .venv/pyvenv.cfg .venv/lib/python3.14/site-packages/cryptography-50.0.1.dist-info
.venv/bin/python -m pip freeze
update-crypto-policies --show; cat /proc/sys/crypto/fips_enabled

# Final gates
.venv/bin/python tests/corpus_runner.py
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src
.venv/bin/python -m mypy src/apkforge

# TP matrix and SHA-1 provenance, regenerated at the working tree
.venv/bin/python RC/regen_security.py RC/final_security
.venv/bin/python RC/sha1_provenance.py
```

## 9. Evidence preservation

* **Nothing committed.** `git status` shows the same modified tracked files as before this
  task plus the new `artifacts/toolchain-validation/reconciliation/` tree; no file was
  staged or committed.
* **No historical artifact overwritten.** `CO/`, `SV/`, `PRC/`, `step5/`,
  `step5_verifier_robustness.md`, `step4_unverified_claims.md` and `phase_b_closeout.md`
  are untouched. `PRC/findings_review_post_prc.md`'s "READY"-adjacent claims and its 17.9%
  arithmetic error are corrected **here**, not in that file.
* `tests/corpus_results.json` is overwritten by the runner by design; the post-PRC version
  was snapshotted to `RC/corpus_results_post_prc_preserved.json` (sha256 verified identical
  to `PRC/corpus_results_post_prc.json`) before this task's run, and the new run is
  snapshotted to `RC/corpus_results_reconciliation.json`.
* The `git worktree` used for State A was created under the session scratchpad, outside the
  repository tree.
* `RC/environment_manifest.txt` is the first Python-environment record in the repository;
  it is additive.

## 10. Acceptance gate

| requirement | status | evidence |
|---|---|---|
| All 35 expected TPs verified individually by app + rule ID | **PASS** | §5, `RC/tp_matrix.json`, `RC/final_security/` |
| `SEC-MAL-ROOT-INDICATORS` present in the final JSON | **PASS** | §5.1 |
| SHA-1 findings have one explicit final disposition | **PASS** | §6.4 — RETAINED, UNCLEAR, severity/confidence unchanged |
| PRC-05 / PRC-07 / PRC-08 remain validated | **PASS** | §5 (0 TP loss, 17 AppManager FPs eliminated, no new findings), §6.3 (PRC-08 attribution verified correct, `SHA1` correctly suppressed) |
| No unrelated security-rule changes | **PASS** | `git diff` limited to the PRC and getattr-audit edits; PRC-01/PRC-03 FPs deliberately still present |
| No Phase C work | **PASS** | no modification/verifier/architecture change |
| Nothing committed | **PASS** | §9 |
| No historical evidence overwritten | **PASS** | §9 |
| Corpus at 96 PASS / 3 PARTIAL / 0 FAIL, no unexplained degradation | **PASS** | §4 — 0 differences vs baseline across 99 evaluations and 3 diff pairs |
| 398/398 unit tests; no new ruff finding; no new mypy error | **PASS** | §4.1 |

### Gate A vs Gate B

**Gate B does not apply:** the regression was not caused by the working tree (§2), so there
was no minimal regression to fix.

**Gate A is satisfied on two of its three clauses:**

1. *The 91/8 result is demonstrated to be caused by an environment/representation
   difference* — **met.** Demonstrated by controlled runs, not inferred from changed-file
   lists: 17/17 identical fields at `212227f` and at the working tree (§2), the failing call
   proven to lie inside `cryptography`'s native extension with no APKForge code in the path
   (§2.1), the blast radius matching the corpus's single SHA-1-signed APK exactly (§2.2),
   no dependency change (§3.2), and the full corpus back to 96/3/0 (§4).
2. *The baseline behaviour is correctly explained* — **met.** The baseline is the correct
   behaviour and is reproduced; the post-PRC run was the anomaly, it cost no analytical
   content (§1.4), and the five PARTIALs are one upstream intake warning, not five
   regressions (§1.3).
3. *The project has a documented reproducible environment* — **NOT met.** `pyproject.toml`
   carries open lower bounds, there is no lock or constraints file, and no historical run
   preserved a `pip freeze`, interpreter version or OpenSSL version (§3.3, §3.4). A pin was
   deliberately **not** added because the evidence shows no version difference caused the
   event, so pinning would be unjustified by this task's own rule. This also means the
   exact trigger of the anomaly cannot be established (§3.5) — only bounded.

## PHASE B NOT READY TO CLOSE

One gate clause is unmet, and it is a project-level gap, not a defect in the PRC work. The
security fixes and the corpus are clean: PRC-05/07/08 are validated, 35/35 TPs hold at
unchanged severity, AppManager's FP count is down 17, the SHA-1 ambiguity has a single
explicit disposition, and the corpus is bit-for-bit back to 96 PASS / 3 PARTIAL / 0 FAIL.
What is missing is a documented reproducible environment: until the validation environment
is pinned and recorded, a non-reproducible backend-level event like the one in §2.3 can
reappear in any future corpus run and cannot be distinguished from a real regression except
by repeating this entire exercise.

Smallest sufficient remedy, out of scope here because it is a dependency-policy decision:
adopt a lock or constraints file (or a pinned container) for the Python validation
environment, commit a `pip freeze` alongside each corpus artifact, and re-state Gate A
clause 3 against it. Nothing in the analysis layer needs to change for Phase B to close
once that exists.
