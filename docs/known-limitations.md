# Known Limitations

Scope: APKForge Phase A/B. Each entry is classified as:

- **Accepted behaviour** — a deliberate design boundary. Not a defect; will not change
  without a scope decision.
- **Known limitation** — a real gap with a known cause, consciously not closed yet.
- **Unresolved defect** — incorrect behaviour that should be fixed. Listed here so it is
  visible, **not** to reclassify it as acceptable.

Every quantitative statement cites the persistent artifact it came from.

Entries 1–9 are the Phase B close-out register. Entries 10–14 were added by the Phase B
regression reconciliation (`artifacts/toolchain-validation/reconciliation/phase_b_regression_reconciliation.md`);
no earlier entry was edited.

---

## 1. Fennec: three PARTIAL corpus results (embedded-file size threshold)

**Classification: accepted behaviour.**

`org.mozilla.fennec_fdroid_1560020.apk` reports PARTIAL for `inspection_full`,
`privacy` and `security` — the only non-PASS results in the 9-APK corpus.

**Root cause (from the persisted corpus result, not re-derived here):** the embedded-file
inspector skips archive entries above its size threshold and emits a warning; a warning
makes the inspection PARTIAL, and that status correctly propagates to the privacy and
security engines, which must never report a complete result over an incomplete
inspection.

```
warnings: ["File 'lib/arm64-v8a/libxul.so' too large for embedded detection (156864024 bytes)."]
```

| fact | value | evidence |
|---|---|---|
| warning text and triggering file | `lib/arm64-v8a/libxul.so`, 156,864,024 bytes (≈149.6 MiB) | `tests/corpus_results.json` → `per_apk_results[fennec].capabilities[inspection_full].data_summary.warnings` |
| threshold that was exceeded | `64 * 1024 * 1024` = 64 MiB | `src/apkforge/inspection/embedded.py:53` (`_MAX_DETECT_SIZE`), used at `embedded.py:128` |
| PARTIAL count, close-out run | 3 (all Fennec) | `artifacts/toolchain-validation/closeout/corpus_run_stdout.txt` |
| PARTIAL count, Step 5 baseline | 3 (all Fennec, same capabilities) | `git show 212227f:tests/corpus_results.json` |

**Two corrections to how this limit has previously been described** (recorded because the
numbers matter for reproducibility):

1. The threshold is **64 MiB**, not 100 MB.
2. It is a **module-level constant**, not a configurable setting — there is no config key
   for it (`_MAX_DETECT_SIZE` is not read from `APKForgeConfig`).

**Why accepted:** reading a 150 MiB entry into memory to scan for nested archives is a
poor trade for a native library that is not a plausible container, and the behaviour is
transparent (a warning plus a PARTIAL status, never a silent skip). This entry references
the existing Phase A evidence rather than reopening the issue.

---

## 2. Residual unmatched resource rename pairs

**Classification: known limitation.**

After content-hash matching and ARSC resource-identity pairing, some removed/added paths
remain unpaired in an Apktool no-op round trip:

| APK | unmatched removed | unmatched added | residual pairs | evidence |
|---|---|---|---|---|
| OpenLink | 18 | 2 | **20** | `artifacts/toolchain-validation/step5/rename_pairing_before_after.json` → `openlink.after_content_hash_plus_resource_identity`; independently reproduced at close-out in `artifacts/toolchain-validation/closeout/openlink_acceptance/acceptance.json` → `noop_result.files` |
| AntennaPod | 77 | 4 | **81** | `artifacts/toolchain-validation/step5/rename_pairing_before_after.json` → `antennapod.after_content_hash_plus_resource_identity` |

**Composition of the residue** (from the same artifacts): overwhelmingly `META-INF/*`
signature and build-version markers, which are expected re-signing churn and are not
resources at all — 18 of 18 for OpenLink, 75 of 77 for AntennaPod. The genuine resource
residue is **2 removed + 2 added paths in AntennaPod**, where the ARSC identity could not
be resolved to a unique counterpart.

**Why not closed:** by design, an ambiguous or unresolvable resource identity is left as
a separate remove + add rather than guessed, so that a real content substitution can
never be hidden behind a "renamed" label. Tightening this further would require guessing.
See `tests/unit/test_phase_b_step5.py::TestResourceIdentityRenamePairing::test_ambiguous_identity_match_is_not_paired`.

---

## 3. Manifest resource resolution is single-configuration and numeric-reference only

**Classification: known limitation.**

`_resolve_resource_value()` (`src/apkforge/inspection/manifest.py:64-97`) resolves a
manifest attribute that holds a resource reference to its string value, but:

1. **First configuration wins.** It iterates `arsc.get_resolved_res_configs(res_id)` and
   returns the first non-empty string (`manifest.py:91-96`). Locale, density and
   API-level variants of the same resource are not enumerated, so an attribute whose
   value differs per configuration is represented by one arbitrary-but-deterministic
   variant.
2. **Only numeric `@<hex-id>` references are resolved.** The reference must parse as hex
   (`manifest.py:79-83`); a symbolic form such as `@string/provider_authority` is returned
   verbatim.
3. **Only selected attributes are resolved at all** — provider `authorities`,
   `permission`, `readPermission`, `writePermission`, and the non-boolean `<application>`
   attributes. Other attributes keep their raw value.

**Mitigation already in place:** the diff layer compensates by comparing through
`is_semantically_equivalent()` with the per-APK `resource_map`, so an unresolved `@7F…`
on one side and an inlined literal on the other do not produce a false difference
(`tests/unit/test_diff_gap_fixes.py::TestManifestResourceNormalization`).

---

## 4. DEX normalization limitations remaining after the Phase B close-out

**Classification: known limitation** (the two below), after this task closed the
exception-handler gap.

What the normalized method representation now covers: instruction mnemonics, register
operands, literals, branch offsets, pool references resolved to symbolic identities, and
exception-handler structure (try ranges, caught types in order, handler targets,
catch-all) — see `src/apkforge/inspection/dex.py` and
`artifacts/toolchain-validation/closeout/dex_exception_handler_experiment.json`.

Remaining gaps:

1. **Unresolvable operand kinds fall back to the raw pool index.** A small set of
   Androguard `Kind` values (`METH_PROTO`, `CALL_SITE`, `VARIES`, and the odex-only
   `INLINE_METHOD` / `VTABLE_OFFSET` / `FIELD_OFFSET`) have no symbolic resolution, so
   those operands are hashed as `("sym_unresolved", kind, raw_index)` and are **not**
   table-index-stable. These appear in `invoke-polymorphic` / `invoke-custom`, which are
   rare in the corpus. Documented in `_normalize_operand`; covered by
   `tests/unit/test_phase_b_step5.py::TestDEXNormalizedHashing::test_unresolved_kind_falls_back_to_raw_index_deterministically`.
2. **Addresses that do not land on an instruction boundary fall back to `("raw_addr", n)`.**
   Well-formed DEX should never hit this; it exists so a malformed handler table degrades
   deterministically instead of being dropped. Covered by
   `tests/unit/test_phase_b_closeout.py::TestExceptionHandlerNormalization::test_address_off_instruction_boundary_uses_documented_fallback`.

**Accepted behaviour (not a gap):** branch width is part of a method's identity, so `goto`
and `goto/16` hash differently even when the branch target is the same. A smali round trip
that re-selects branch widths will therefore report the method as changed. This is
deliberate — the alternative would hide real instruction-selection changes. Test:
`test_different_opcode_changes_normalized_instruction`.

---

## 5. `android:process` — implemented, with one residual nuance

**Classification: known limitation** (narrow).

`android:process` is now inspected, modelled and diffed for all four component types
(evidence: `artifacts/toolchain-validation/closeout/process_attribute_evidence.json`;
extraction verified against all 9 corpus APKs — Fennec 94 components, NewPipe 5,
PCAPdroid 1, AppManager 1, others 0).

Residual nuance: comparison is exact string equality. Android treats a leading `:` as
shorthand for a process private to the package (`:remote` ≡
`<package>:remote`), so a manifest that switches between the shorthand and the
fully-qualified spelling would be reported as a change although the runtime process is the
same. No corpus APK exhibits this, and normalizing it would require the package name to be
threaded into the component differ.

---

## 6. Security rule precision — unresolved defects

**Classification: unresolved defect.** These are **not** accepted behaviour. They
produce incorrect security findings, including at HIGH severity, and are recorded with
proposed fixes that were deliberately not applied during the close-out (the task
prohibited changing rule severity, confidence, scoring or thresholds).

Measured false-positive rates from the hand review
(`artifacts/security-validation/findings_review.json`,
summarised in `artifacts/security-validation/findings_review.md`):

| app | findings | false positives | rate |
|---|---|---|---|
| OpenLink | 5 | 0 | 0.0% |
| PCAPdroid | 9 | 2 | 22.2% |
| AppManager | 45 | 20 | 44.4% |
| **total** | **59** | **22** | **37.3%** |

The two dominant causes, both affecting HIGH-severity output:

1. **Bundled third-party library strings are attributed to the application** (`PRC-07`,
   `PRC-08`). AppManager bundles 6,139 `org.bouncycastle.*` classes; the provider's
   algorithm registry supplies `DES/CBC/PKCS5Padding`, `DESede`, `Blowfish`, `SHA1` and
   the PEM armor header `-----BEGIN RSA PRIVATE KEY-----`, none of which reflect an
   application choice. Produces 2 HIGH + 3 lower-severity false positives.
2. **Code-free archives classified as executable payloads** (`PRC-05`, `PRC-06`).
   AppManager's 14 `frameworks/android/android-NN.apk` entries contain only
   `resources.arsc` + `AndroidManifest.xml`; all 14 are reported HIGH as `payload`.

Also unresolved: substring API matching flags apps that do not implement the matched
capability (`PRC-01`; PCAPdroid flagged twice for an accessibility service it does not
declare), evidence citing the rule's probe pattern instead of the matched artifact
(`PRC-02`), XML namespace URIs treated as cleartext network endpoints (`PRC-03`),
package names extracted as domains (`PRC-10`), and five rule pairs double-reporting one
fact (`PRC-04`).

Full problem statements and proposals: `proposed_rule_changes` in
`artifacts/security-validation/findings_review.json`.

---

## 7. `ManifestInspection` silently discards unknown keyword arguments

**Classification: unresolved defect** (latent; no current incorrect output).

`ManifestInspection` uses Pydantic's default `extra="ignore"`
(`src/apkforge/inspection/models.py`, no `model_config` override), so
`ManifestInspection(package_name=..., debuggable=True)` silently drops `debuggable` —
that field lives on `ApplicationInfo`, not on `ManifestInspection`.

Discovered during the `getattr` audit: `security/engine.py` previously probed
`inspection.manifest.<attr>` as a fallback tier, which could never succeed for exactly
this reason (dead code, now removed — see
`artifacts/toolchain-validation/closeout/getattr_audit.json` →
`dead_fallbacks_removed`). The same silent-drop also means
`tests/unit/test_security_engine.py:731` does not exercise the debuggable path its
fixture implies; that test asserts only determinism, so it still passes, and it was left
unchanged.

Proposed fix (not applied): set `extra="forbid"` on the inspection models so a
misdirected field raises instead of vanishing.

---

## 8. Static-analysis baseline

**Classification: known limitation.**

| tool | at `HEAD` 212227f | at close-out | evidence |
|---|---|---|---|
| mypy | 119 errors | 124 errors | `artifacts/toolchain-validation/closeout/mypy_baseline_HEAD_212227f.txt`, `…/mypy_closeout.txt` |
| ruff | 25 findings | 6 findings | `artifacts/toolchain-validation/closeout/ruff_baseline_HEAD_212227f.txt`, `…/ruff_closeout.txt` |

The mypy delta is **+8 new instances of one pre-existing pattern minus 3 fixed**: the
`process` extraction added four `apk.get_attribute_value(...)` calls to
`inspection/manifest.py`, where the `apk` parameter is annotated `object`, so each call
reports `attr-defined` plus an `unused-ignore`. No new *class* of type error was
introduced, and no new error exists outside `inspection/manifest.py`
(verified by set-differencing the two baselines). Retyping that module's `apk: object`
to the Androguard type would clear roughly 56 errors and is proposed as follow-up work.

---

## 9. No integration test suite

**Classification: known limitation.**

`tests/integration/` contains only `__init__.py`; all 386 tests are unit tests
(`artifacts/toolchain-validation/closeout/unit_test_run.txt`). End-to-end coverage is
provided instead by `tests/corpus_runner.py` against the 9-APK corpus and by the
Docker-based toolchain acceptance runs under `artifacts/toolchain-validation/`, neither
of which runs under `pytest`.

---

## 10. No reproducible Python validation environment

**Classification: unresolved defect (process).**

`pyproject.toml` declares open lower bounds only — `androguard>=4.0.0`,
`cryptography>=42.0.0`, `pyyaml>=6.0` — and the repository contains **no lock file, no
`requirements.txt`, and no constraints file**. No historical validation artifact preserves
a `pip freeze`, interpreter version, or OpenSSL version; the only environment record is
`artifacts/toolchain-validation/closeout/openlink_acceptance/toolchain_versions.txt`, which
pins the **Android** toolchain (Apktool / apksigner / JDK / Docker image), not the Python
analysis environment.

The consequence is concrete rather than theoretical. During the Phase B regression
reconciliation a corpus run produced five PARTIAL verdicts on
`com.oF2pks.applicationsinfo_19.apk` from a single intake warning
(`Androguard certificate extraction failed: sha1 is not supported by this backend for RSA
signing.`). The failing call lies inside `cryptography`'s native RSA signature-context
setup, reached through androguard's v1 signature verification; it is not reproducible
(0 failures in 60+ attempts and a clean full-corpus run), the installed packages were
provably unchanged across all four corpus runs, and the Phase B close-out commit and the
working tree behave identically. Because no environment was recorded for any earlier run,
the event can be bounded but its exact trigger cannot be established.

No pin was added: the evidence shows no dependency version difference caused it, so pinning
`cryptography==50.0.1` would be unjustified — and it would pin the project to the version
under which the anomaly was observed. The remedy is a lock or constraints file (or a pinned
container) for the validation environment, plus a `pip freeze` committed alongside each
corpus artifact. Until that exists, a non-reproducible backend-level event cannot be
distinguished from a real regression without repeating the full reconciliation.

Current environment, for reference:
`artifacts/toolchain-validation/reconciliation/environment_manifest.txt` — Fedora 44,
Python 3.14.7, `cryptography` 50.0.1 (bundled OpenSSL 4.0.2), androguard 4.1.4,
asn1crypto 1.5.1, no pyOpenSSL, FIPS disabled.

Full analysis: `artifacts/toolchain-validation/reconciliation/phase_b_regression_reconciliation.md`.

---

## 11. A recoverable certificate-extraction failure degrades five capability verdicts

**Classification: known limitation (robustness).**

`extract_certificates` (`src/apkforge/intake/certificates.py:37-64`) has two strategies:
Androguard first, then raw PKCS#7 parsing of `META-INF/*.RSA|DSA|EC`. When Androguard fails
but the fallback succeeds, the certificate **is** extracted — yet the Androguard warning is
still appended to the package, which sets intake `status = partial`. `inspection_full`
inherits that status and warning, `privacy` and `security` inherit the inspection status
with empty warnings of their own, and `modification_planning` degrades because inspection
is partial. One recoverable upstream failure therefore turns into five PARTIAL capability
verdicts and one PARTIAL diff pair, with **no loss of analytical content** — in the observed
case `certificate_count` was 1 and every permission, class, endpoint and finding was
identical to the passing run.

The warning itself is correct and should be retained; what is missing is a distinction
between "a strategy failed and was recovered" and "the capability is degraded". No code was
changed for this during the reconciliation, because the working tree was shown not to have
caused the event and the task's remit was limited to the regression. Recorded for a future
pass.

---

## 12. `SEC-MAL-ROOT-INDICATORS` depends on the DEX string truncation budget

**Classification: known limitation.**

`_MAX_STRINGS = 100_000` (`src/apkforge/inspection/dex.py:65`) caps the number of DEX
strings collected per APK. The PRC-08 provenance work appends crypto-keyword
`const-string` references (with their owning class) during class iteration, i.e. **before**
the general string-pool loop, so those entries consume part of the same budget. On
AppManager this truncated the pool before the root-indicator strings were reached and
`SEC-MAL-ROOT-INDICATORS` disappeared; the subsequent dedup guard at `dex.py:382-390`
(`s_val not in string_set`) recovered enough budget to restore it, verified present with
severity `low`, confidence `medium` and 5 evidence items in
`artifacts/toolchain-validation/reconciliation/final_security/raw_appmanager_security.json`.

The rule is therefore correct on the current corpus but its presence depends on a
truncation cap rather than on the evidence itself, and the surviving margin is not measured.
Any future change that adds strings earlier in collection can silently remove the finding
again. A string-pool budget that cannot evict rule-relevant strings — or an explicit
"truncated" limitation emitted when the cap is hit — would remove the fragility.

---

## 13. Bundled-crypto-library attribution covers only BouncyCastle and SpongyCastle

**Classification: known limitation.**

`SecurityEvidenceIndex.is_string_attributed_to_app`
(`src/apkforge/security/rules.py:118-147`) suppresses crypto-string attribution when the
owning class belongs to a bundled provider, and that provider set is a hardcoded two-entry
prefix tuple in all three of its branches:

```python
c.startswith(("org.bouncycastle.", "org.spongycastle."))
```

PRC-08's measured effect on the reviewed corpus is real — on AppManager it eliminated the
BouncyCastle-owned `SHA1`, `DESede` and `Blowfish` attributions (verified: 20, 9 and 5
BouncyCastle-owned references respectively, with **zero** app-owned references for each) —
but the mechanism does not generalise. In the same APK, 9 of the 31 `SHA-1` references
belong to third-party code that is **not** in the list:
`com.android.apksig.internal.apk.v1.V1SchemeVerifier`,
`com.android.apksig.internal.apk.v1.DigestAlgorithm`,
`com.android.apksig.internal.oid.OidConstants`,
`com.android.apksig.internal.pkcs7.AlgorithmIdentifier`,
`android.sun.security.x509.AlgorithmId`, `android.sun.security.pkcs12.PKCS12KeyStore`,
`com.google.common.hash.Hashing$Sha1Holder`,
`com.android.tools.smali.dexlib2.writer.DexWriter`, `org.jf.dexlib2.writer.DexWriter`
(`artifacts/toolchain-validation/reconciliation/sha1_provenance.json`). None of these is
suppressed as a bundled provider.

On AppManager this is harmless, because app-owned references exist and the app-prefix
branch is evaluated first. In an application that bundles a different crypto library —
Conscrypt, Tink, jose4j, Netty-tcnative, Apache Commons Codec, a `javax.crypto` shim — and
has **no** app-owned reference to the matched string, the same misattribution that PRC-08
was written to fix would recur. The check is also provider-specific rather than a general
"does this class belong to the application?" test, so the list must grow per library.

---

## 14. Nested APK inspection does not enforce the configured archive-safety limits

**Classification: known limitation.**

Top-level intake routes archive access through `SafeZipExtractor`
(`src/apkforge/intake/archive.py:80-246`), which enforces `ExtractionLimits`
(`src/apkforge/core/config.py:74-113`): `max_file_count` 10,000, `max_single_file_bytes`
256 MiB, `max_total_size_bytes` 1 GiB, `max_recursion_depth` 4, plus per-entry
path-traversal validation. That class's docstring states the limits "must be respected by
every future extraction implementation".

`src/apkforge/inspection/embedded.py` does not use it. It opens archives with raw
`zipfile.ZipFile` — at `embedded.py:112` for the top-level APK and at `embedded.py:70` and
`embedded.py:149` for nested archives via `io.BytesIO` — and imports neither
`SafeZipExtractor` nor `ExtractionLimits`. The PRC-05 nested-APK code-presence check
(`embedded.py:149-155`) inherits this posture.

What this does and does not mean:

- **Not enforced for nested archives:** `max_file_count` (a nested archive may declare an
  unbounded number of central-directory entries), `max_total_size_bytes`,
  `max_recursion_depth`, and path validation.
- **Bounded by a different, unrelated constant:** the enclosing loop skips entries whose
  declared uncompressed size exceeds `_MAX_DETECT_SIZE = 64 MiB`
  (`embedded.py:53`, checked at `embedded.py:128`) *before* reading, so a single nested
  entry read is capped at 64 MiB — but by a non-configurable module constant that is not
  the configured `max_single_file_bytes` (256 MiB). The two limits are independent and
  mutually inconsistent.
- **Decompression is bounded:** both nested reads call only `inner_zf.namelist()`, which
  parses the central directory and decompresses **no** inner entry. The classic nested
  decompression bomb is therefore not amplified. The residual exposure is the 64 MiB
  in-memory `bytes` plus its `io.BytesIO` copy per candidate entry, and an unbounded
  central-directory entry count.

The fix is to route nested inspection through `SafeZipExtractor` (or to apply
`ExtractionLimits` to the in-memory path) so that one configured limit set governs both
levels. Nested archive handling was deliberately not redesigned during the reconciliation.

---

## 15. Security evidence ordering and sampling are not deterministic across runs

**Classification: known limitation.**

Repeated runs of identical code in an identical environment report the same findings
(ID, title, category, severity, confidence, evidence **count**), but the **order** of evidence
items, and **which** items are kept where a rule truncates evidence to a sample, can differ
between processes. Examples: the order of foreground services cited by
`SEC-MAL-PERSISTENCE-FG-SERVICE`, the 5 domains sampled by `SEC-NET-CAPABILITY-FLOW`, and the
5 strings sampled by `SEC-MAL-ROOT-INDICATORS`. The corpus runner shows the same effect in
lists it builds with `list(set(...))` (ABIs, `finding_categories`, plan `change_types`).

The variation is **not** caused only by `PYTHONHASHSEED`. With the seed fixed at 1, five
runs of the pre-close-out source produced two different evidence digests, while finding
identity stayed constant across every run
(`artifacts/toolchain-validation/phase_b_final/hashseed_probe_results.txt`). It predates the
final close-out: the close-out and reconciliation corpus artifacts, both produced before it,
already differ by 19 order-only fields
(`artifacts/toolchain-validation/phase_b_final/corpus_comparison_control_closeout_vs_reconciliation.json`).

Consequence: security and corpus artifacts cannot be compared byte-for-byte. They must be
compared on finding identity plus evidence count, and on order-normalised corpus fields, which
is what `artifacts/toolchain-validation/phase_b_final/compare_security.py` and
`compare_corpus.py` do. A deterministic evidence order (sort before truncation) would let
artifacts be compared directly. The root cause was not investigated in the final close-out.

---

## Status updates — Phase B final close-out

Recorded here rather than by editing the entries above. Evidence:
`artifacts/toolchain-validation/phase_b_final/phase_b_final_closeout.md`.

- **§10 No reproducible Python validation environment — resolved.**
  `requirements/validation.lock` (hashed, 61 packages, SHA-256
  `62e61de0ddb41b87771f763c103f1dd1deae655035dc5d615c0fda35c9919acf`) pins the complete
  reference environment. `docs/validation-environment.md` documents how to recreate it, and
  every new corpus result records `meta.environment` including the lock's SHA-256. The
  historical SHA-1 backend anomaly itself remains unexplained. It was not investigated
  further, and no workaround was added.
- **§11 Recoverable certificate-extraction failure degrades five verdicts — resolved.**
  When the PKCS#7 fallback recovers complete certificates, the Androguard failure is attached
  to each certificate as an informational `extraction_notes` entry,
  `extraction_backend="pkcs7_fallback"` is recorded, and no intake warning is raised. An
  unrecovered or incomplete fallback still warns exactly as before.
- **§14 Nested APK inspection does not enforce the configured archive-safety limits —
  resolved for nested archives.** `EmbeddedFileInspector` now lists nested archives through
  `apkforge.intake.archive.validate_archive_entries` under the configured `ExtractionLimits`
  (entry count, path validation, declared per-entry and total sizes, recursion depth). A
  nested APK that violates them is still reported, is treated as possibly containing code
  (so PRC-05 code-free suppression is not granted), and produces a warning. Two limitations
  remain: the top-level archive in `embedded.py` is still opened with raw `zipfile`
  (intake has already processed it), and the 64 MiB `_MAX_DETECT_SIZE` read bound is still
  a separate module constant.

---

## Phase C.2 — BuildService

The APK rebuild pipeline's limitations (no runtime install/launch validation, no semantic
equivalence check of DEX/resources, 4 KiB `.so` page alignment only, platform framework
only) are listed in [build-service.md §10](build-service.md#10-known-limitations), with the
corpus evidence in `build-tests/phase-c2-report.md` and `build-tests/c2_results.json`.

Phase C.4 (corpus regression baseline): the corpus definition and expected outcomes are in
`tests/corpus/manifest.json`, the baseline result in `tests/corpus/results/baseline.json`
and `baseline-report.md`. The baseline only covers the no-op rebuild of these 9 APKs with
the recorded toolchain; it says nothing about install/runtime behaviour or other APKs.

---

## Phase C.5 — controlled modification

Workflow, noise rules and the semantic no-op baseline: [controlled-modification.md](controlled-modification.md).
Entries 16–19 were added in C.5; no earlier entry was edited.

### 16. The manifest inspector extracts no intent filters from real APKs

> **Pre-fix record — fixed.** The text below describes the inspector before the fix and
> is kept as written. Current state: "Status update — intent-filter extraction fix (§16)".

**Classification: unresolved defect** (pre-existing; found in C.5, not fixed in C.5).

`ManifestInspector._extract_intent_filters` returns early unless it is given an
`xml.etree.ElementTree.Element`. Androguard's `get_android_manifest_xml()` returns
`lxml.etree._Element`, and the whole extraction runs inside `contextlib.suppress(Exception)`.
So every activity, service and receiver of a real APK has `intent_filters == []`. Measured
on OpenLink and AntennaPod: 0 filters across all component types, although OpenLink's
manifest declares 8. Synthetic test APKs take the text-XML fallback path, which is why the
unit tests did not catch it.

Consequences:

- `ComponentDiffer`'s intent-filter comparison never fires on real APKs.
- Everything downstream that reads `intent_filters` sees none: deep-link hosts in the
  network inspector, and security/privacy rules about exported components with filters.

Why not fixed in C.5: the fix is small (accept any element with `findall`/`get`), but it
changes security and privacy results on real APKs and therefore invalidates the Phase B
precision evidence. That needs a deliberate re-validation, not a side effect of C.5.

C.5 mitigation: the modifier verifies the complete decoded-manifest structure, intent
filters included, before the build. The integration test decodes the output's binary
manifest independently and checks the target receiver's actions. DiffEngine itself does
not cover intent filters.

### 17. Legacy `ModificationFramework` reports SUCCESS when nothing was changed

> **Pre-fix record — fixed.** The text below describes the framework before the fix and
> is kept as written. Current state: "Status update — pre-Phase-D groundwork".

**Classification: unresolved defect** (pre-existing, Phase D scope; C.5 does not use this path).

`ModificationResult.all_succeeded` counts `SKIPPED` as success. `ComponentModifier` returns
`SKIPPED` when the component is not found. So an approved plan to disable a non-existent
component finishes with overall status `success` and nothing changed. Reproduced with a
synthetic APK during C.5.

### 18. Failed intakes keep their workspace by default

**Classification: accepted behaviour** (documented setting; recorded because it looks like a leak).

`WorkspaceSettings.keep_on_failure` defaults to `True`. `APKIntakeService.process()` with
default config therefore retains the workspace of every failed intake under
`/tmp/apkforge/` for debugging. In C.5 the intake security tests, which fail on purpose,
were moved to pytest temp directories. Changing the default is a separate decision.

### 19. Workspace leak (`InspectionEngine`) — fixed in C.5

Repeated test runs left `/tmp/apkforge/apkforge_*` directories behind: 58 per unit-suite
run before the fix, 0 after (three consecutive full-suite runs). The cause:
`InspectionEngine.inspect()` searched the *original* APK's parent directories for an
`apkforge_*` directory, so it never found the intake workspace of a standalone APK. Its
cleanup also ran on the success path only, and it could delete an unrelated user
directory named `apkforge_*`.

Intake now hands the retained workspace to the caller (`AndroidPackage.workspace_root`),
and the engine removes exactly that directory in a `finally` block. `ModificationFramework`
removes a workspace it created when the run does not succeed, unless
`keep_workspace=True`. It never removes a caller-supplied workspace, and it no longer
reuses one directory across runs under `workspace_base`. Regression tests:
`tests/unit/test_workspace_lifecycle.py`.

Directories leaked before the fix are not removed automatically.

---

## Status update — intent-filter extraction fix (§16)

Recorded here rather than by editing §6 or §16. Evidence: `artifacts/intent-filter-fix/`
(`report.md` summarises it; every figure below cites a file in that directory).

**§16 — fixed.** `ManifestInspector` now accepts any ElementTree-compatible element, so it
reads the `lxml.etree._Element` tree Androguard returns. An extraction failure is no longer
swallowed: it adds a warning that names the component and the exception, which makes the
manifest inspection PARTIAL. Components are now matched to their manifest element by
resolved class name first, falling back to the old simple-name match. AntennaPod has two
receivers named `MediaButtonReceiver`, and the simple-name match would have given the
library one the app's filters. Regression tests:
`tests/unit/test_inspection_manifest_intent_filters.py` (6 of 7 fail against the pre-fix
source, `tests_against_prefix_src.txt`).

Measured on the 9-APK corpus: 0 intent filters before, 200 after (`filter_counts.json` in
`before/` and `after/`). Per filter, the actions, categories and number of `<data>` elements
match `aapt2 dump xmltree` for every component in all 9 APKs (`aapt2_verification.json`).
No manifest inspection became PARTIAL and nothing other than `intent_filters` changed
(`comparison.json`).

### Phase B security precision was measured with the pre-fix inspector

The false-positive rates in §6 (59 findings, 37.3%) and the post-PRC rate (42 findings,
5 FP, **11.9%**, `artifacts/security-validation/prc_validation/findings_review_post_prc.md`)
were measured while every real APK had zero intent filters. Those numbers stay as recorded.
Measured with the fixed inspector, same three apps and same method
(`artifacts/intent-filter-fix/precision.json`):

| | findings | TP | FP | unclear | FP rate |
|---|---:|---:|---:|---:|---:|
| post-PRC, pre-fix inspector (reproduced from `before/`) | 42 | 35 | 5 | 2 | 11.9% |
| post-PRC, **post-fix inspector** | 44 | 37 | 5 | 2 | **11.4%** |

Per app after the fix: OpenLink 0/5, PCAPdroid 2/10 (20.0%), AppManager 3/29 (10.3%).
The two added findings are `SEC-MAL-BOOT-001` in PCAPdroid and AppManager, both classified
true positive: each app's `BootReceiver` declares BOOT_COMPLETED (aapt2) and starts a
service from `onReceive` (`boot_receiver_xrefs.json`). `SEC-MAL-PERSISTENCE-BOOT` moves from
confidence `high` to `confirmed` in all three apps. Its severity is unchanged, and it now
names the boot receiver as evidence.

Outside the three reviewed apps (not hand-reviewed; `other_apps.json`):
`SEC-MAL-BOOT-001` is added in AntennaPod, Conversations, Fennec and NewPipe, and the HIGH
finding `SEC-COMB-PERSISTENT-LOC` (boot receiver + location) is added in Conversations and
Fennec. Capability verdicts are unchanged: 96 PASS / 3 PARTIAL before and after
(`corpus_comparison.json`).

### Limitations found while measuring (not fixed here)

- `SEC-MAL-BOOT-001` duplicates `SEC-MAL-PERSISTENCE-BOOT` (the §6 PRC-04 pattern). Its
  evidence location `manifest:receiver:BOOT_COMPLETED` does not name the receiver. It also
  lists every declared service, not the one the receiver starts.
- Deep-link hosts from intent-filter `<data android:host>` are now fed into the network
  inspector and counted as privacy endpoints (`network:extracted_domain`). NewPipe gains
  13 domains, AntennaPod 1 (`new_domains_vs_aapt2_hosts.json`). They are hosts the app
  *handles links for*, not hosts it is shown to contact.
- `<activity-alias>` elements and their intent filters are not modelled. AppManager
  declares 5 aliases.
- Component and permission order in `ManifestInspection` comes from Androguard sets and
  varies run to run. Compare these lists order-insensitively.
- The C.5 runner's limitation text (`build-tests/run_c5_validation.py`) still says intent
  filters of real APKs are not compared. That is no longer true for DiffEngine. It was left
  unchanged in this step.

### Baselines

The C.5 semantic no-op baseline is identical before and after once timestamps and paths
are removed. All 9 verdicts, noise-rule counts and residue are unchanged
(`c5_comparison.json`), so it was not regenerated. The OpenLink C.5 result is also
unchanged (VERIFIED, 2 expected, 74 noise, 0 unexpected/unknown). DiffEngine now sees the
same 8 filters on both sides (`after/c5/openlink_filter_check.json`). The C.4 build
baseline does not use the inspector. `tests/corpus_results.json` and
`tests/corpus_results_baseline.json` were not updated. The tracked file already differed
from a fresh pre-fix run in 7 unrelated fields, and the baseline file in 25 verdicts. The
post-fix run is in `after/corpus_results.json`.

---

## Status update — pre-Phase-D groundwork

Recorded here rather than by editing §16–§19. Evidence: `artifacts/pre-phase-d/`
(`README.md` summarises it).

**§17 — fixed.** A skipped step is no longer a success. `StepStatus` gains
`VERIFICATION_FAILED` (a step that was executed and then failed verification) and
`PARTIAL` (aggregate only).

- `ModificationStepResult` records `verified` (True, False, or None for "not verified")
  and `rolled_back`. A step is `executed` when its status is SUCCESS or
  VERIFICATION_FAILED.
- The framework calls a modifier's optional `verify()` after each real apply. A failed or
  raising verification makes the step VERIFICATION_FAILED and rolls it back.
- An exception in `apply()` is recorded as FAILED, with the exception type kept.
- Changes after a failure are recorded as PENDING ("Not attempted").
- The original APK is checked by full SHA-256, not just by existence.
- `ModificationResult.aggregate_status()` derives the overall status from the steps:

| steps | overall status |
|---|---|
| any failure, failed verification, rollback or not-attempted step | FAILED |
| nothing executed (no accepted changes, or every step skipped) | SKIPPED |
| some steps executed, others skipped | PARTIAL |
| every step executed | SUCCESS (DRY_RUN in a dry run) |

`all_succeeded` is False for an empty or skipped result. `apkforge modify` exits with 0
(SUCCESS/DRY_RUN), 1 (failed) or 3 (SKIPPED/PARTIAL). Its report shows the planned,
executed, verified, skipped, failed, not-attempted and rolled-back counts. The working copy
is kept for SUCCESS and PARTIAL runs, because both contain executed changes. None of the
built-in modifiers defines `verify()` yet, so their steps report `verified=None`, never
True. Regression tests: `tests/unit/test_modification_status_semantics.py`. All 31 fail
against the old code (`status_tests_against_old_framework.txt`). Two existing tests asserted
the old semantics (an empty result counting as success, and "no accepted changes" reporting
SUCCESS) and were updated. C.5 does not use this framework and its result is unchanged.

**§16 follow-ups.** The C.5 runner's limitation text and `controlled-modification.md` now
say that DiffEngine compares intent filters. The tracked `c5-openlink-result.{json,md}`
was regenerated for that line alone. Its verdict, stages, classification counts (2
expected, 74 noise, 0 unexpected/unknown) and original SHA-256 are unchanged. Only
timestamps, paths, the commit and the per-signing output SHA-256 differ. The pre-fix copy
is in `artifacts/intent-filter-fix/before/c5/`. The semantic no-op baseline was not
regenerated: a fresh run differs from it only in `rebuilt_sha256`, which changes on every
build. The changed security findings are tabulated with their review status in
`artifacts/pre-phase-d/finding_changes.md`. In AntennaPod, Fennec and NewPipe the only
boot receiver is androidx WorkManager's `RescheduleReceiver`. Those findings, including
Fennec's HIGH `SEC-COMB-PERSISTENT-LOC`, have not been reviewed by hand. `<activity-alias>`
is still not modelled.

**§19 — verified.** The 543 directories in `/tmp/apkforge` all predated the fix and were
removed. Two full test runs, the C.4 corpus build, the C.5 runs and the security corpus run
then left the temp space unchanged.

**Retired C.1 test key.** `build-tests/run_proof.py` and `run_noop_roundtrip.py` still name
the deleted `tools/test-signing-key.jks` and its fixed throwaway password. Both scripts now
stop at startup with exit code 2 and say that the key is retired and must not be recreated.

**Test environment.** With `FORCE_COLOR` set, rich writes ANSI codes into `--json` output,
and 6 CLI JSON tests fail. That also happens on unmodified HEAD source. Run the tests with
`FORCE_COLOR` unset.

---

## Status update — Phase D modification framework

Recorded here rather than by editing earlier entries. Design and usage:
`docs/modification-framework.md`. Evidence: `tests/corpus/results/phase-d-openlink-result.{json,md}`
(`build-tests/run_phase_d_validation.py`).

**C.5 now runs through the general pipeline.** `run_disable_boot_receiver` is a wrapper
around `ModificationPipeline` with the `c5.disable_boot_receiver` modifier. The C.5 unit
and integration tests pass unchanged. A fresh `run_c5_validation.py modify` matches the
committed `c5-openlink-result.json` in status, failures, stages, classification counts
(2 expected, 74 noise, 0 unexpected/unknown), noise per rule, planned and observed edits,
original SHA-256 and the verification flags. The committed result was not regenerated.
No baseline (C.4 build baseline, C.5 semantic no-op baseline, C.5 OpenLink result) was
changed.

**The legacy framework is unchanged.** `ModificationFramework` and its seven
change-type modifiers (§17) still never decode, build or verify an APK. Phase D does not
route through them; it reuses their `StepStatus`/`ModificationStepResult` semantics.

**Phase D limitations** (known limitations, not defects):

- Expected changes can only name what DiffEngine observes. `resources.arsc` entries,
  recompiled resources and uncompared manifest content (`<queries>`, `<meta-data>`,
  `<activity-alias>`) are covered only by the framework's pre-build source check.
- Conflict detection is syntactic: shared targets, files and expected-change subjects.
  Interactions that do not show there are caught only when a later modifier is
  re-planned before it is applied, or by the source check.
- Rollback restores declared files and removes unplanned new files. An unplanned edit
  of an existing file cannot be undone; it is reported as a rollback failure, and
  `rolled_back` stays False.
- Modifiers are trusted in-process code and are not sandboxed. The source check and the
  original's SHA-256 detect what they do to the decoded project and the original. They
  do not detect writes elsewhere.
- Outside the 9 corpus APKs there is no recorded noise floor. `--measure-noise-floor`
  measures one with an extra unmodified build. Without one, a run is FAILED by design.
- `apkforge diff` (unlike `modify --modifier`) still lets androguard's loguru DEBUG
  output through to stderr. This is pre-existing and cosmetic.

## Status update — Phase E diff + verification hardening

Recorded here rather than by editing earlier entries. Design: `docs/verification.md`.
Evidence: `artifacts/phase-e/` (`build-tests/run_phase_e_validation.py`).

**Closed by Phase E**

- *Path-only accepted noise* (Phase C.5/D): any content change at a path a noise rule
  covers (`res/` re-encoded, `classes.dex` re-encoded, renamed resources...) passed as
  rebuild noise. Noise is now accepted only by content identity with the APK's measured
  no-op rebuild (schema-2 baseline fingerprint). Demonstrated on a re-signed OpenLink
  APK with one altered `res/` entry (`artifacts/phase-e/openlink`, scenario H).
- *Uncompared manifest content* (Phase D limitation): `<queries>`, `<meta-data>`,
  `<activity-alias>`, intent-filter attributes and every attribute the inspection model
  does not extract are compared by the full manifest tree and can be declared as
  `manifest_element` expected changes. Undeclared ones are unexpected (scenario C).
- *Baselines reused across toolchains*: a schema-2 baseline records its toolchain
  identity and is `BASELINE_INCOMPATIBLE` for any other one.
- *`--json` output coloured under `FORCE_COLOR`*: all `--json` CLI output is written with
  `typer.echo`; the six CLI tests that failed with `FORCE_COLOR=3` now pass with it set.
- `apkforge verify` is implemented (single APK and original/modified pair).

**Remaining (known limitations, not defects)**

- `<activity-alias>` is compared structurally (manifest tree) only, not as a component.
- `resources.arsc` entries and `res/` binary XML are compared by content hash, never
  decoded. A planned resource change is `unknown`, so a modifier that edits resources
  cannot reach VERIFIED.
- Manifest tree values are compared as decoded. One serialization difference was
  observed and turned into a rule (`manifest_reference_inlined`: AntennaPod's
  FileProvider `android:authorities` `@7F130332` → its literal value, accepted only when
  the reference has a single value across all configurations).
- Fennec's no-op diff is incomplete (embedded inspector size threshold, §1): its
  baseline entry is `BASELINE_PARTIAL` and its verification is UNDETERMINED by design.
- DEX extraction budgets and the 50-value string enumeration limit make the `dex` /
  `strings` comparators partial on very large changes (never `unchanged`).
- Native libraries: hash and ELF metadata only.
- The schema-1 C.5 baseline remains loadable but can never yield VERIFIED.
- A clean diff does not prove that an APK is malware-free; a verified signature proves
  structural/signing validity, not safety.

---

## Status update — Phase F Privacy, Tracker & Ads Intelligence

Recorded here as part of Phase F verification. Design and models: [`docs/privacy-analysis.md`](privacy-analysis.md).
Evidence: `artifacts/phase-f/` (`build-tests/run_phase_f_validation.py`).

**Introduced by Phase F**

- *Dedicated Privacy Layer*: Structured static intelligence model separating observed evidence, inferred capabilities, suspected third-party SDKs, confidence levels, and explicit unknown/partial analysis states.
- *Auditable Tracker & SDK Catalog*: Declarative detection rules for advertising, analytics, tracking, attribution, and crash telemetry SDKs with explicit false-positive risk assessment and source references.
- *Domain & Endpoint Categorization*: Categorization of network endpoints (first-party, CDN, social login, update infrastructure, potentially sensitive, unknown) with raw endpoint preservation and runtime transmission disclaimers.
- *Permission + Component Static Correlation*: Explicit classification of permission status (`STRONG_CORRELATION`, `DECLARED_ONLY`, `API_WITHOUT_PERMISSION`), reporting declared-only permissions as uncertain rather than active.
- *Static Behavior Indicators*: Declarative catalog detecting 13 sensitive behavior patterns (device IDs, audio capture, camera, contacts, clipboard, accessibility, notification listeners, webviews, background scheduling, boot receivers, dynamic code loading, reflection).
- *Phase B Security Cross-Check*: Systematic reconciliation comparing overlapping, new, strengthened, and incomplete findings, with documented technical justifications for labeling differences.
- *Dedicated CLI & Programmatic Service*: `apkforge privacy APK` (ANSI-free `--json`, `--report PATH`, `--verbose`) and `PrivacyAnalysisService`.

**Static Analysis Boundaries & Invariants (Not Defects)**

- *Static Presence != Runtime Execution*: The presence of classes, methods, or strings proves that code is packaged in the APK, not that it is executed during user sessions.
- *Endpoint Presence != Network Transmission*: Discovered URLs and domains indicate configured endpoints. They do not constitute proof of active data transfer without dynamic traffic capture.
- *No Malicious Intent Inferences*: Third-party tracking libraries and sensitive permissions are common in legitimate commercial and open-source applications; APKForge never labels apps "malware" or "spyware" based solely on static indicator presence.
- *Obfuscation and Reflection*: Bytecode obfuscated via aggressive renaming or classes loaded dynamically via reflection or `DexClassLoader` cannot be fully mapped to static catalog signatures.
- *Native Code Boundaries*: Network communication or device identifier access performed exclusively inside compiled native binaries (`.so`) is invisible to DEX bytecode scanners.
- *Absence of Evidence Is Not Proof of Safety*: Zero detected trackers or APIs does not prove that an application is harmless.

---

## Status update — Phase G Controlled Privacy/Security Remediation

Recorded here as part of Phase G verification. Design and models: [`docs/remediation.md`](remediation.md).
Evidence: `artifacts/phase-g/` (`build-tests/run_phase_g_validation.py`).

**Introduced by Phase G**

- *Controlled Remediation Layer*: Explicit multi-stage workflow: `Finding -> Evidence -> Candidate -> Plan -> User Approval (--apply) -> Modifier -> BuildService -> Phase E Verification -> Post-Remediation Privacy Analysis -> Diff Report`.
- *Dedicated Remediation Catalog*: Small, conservative, auditable catalog (`G-REM-001` Disable Boot Receiver, `G-REM-002` Remove Specific Permission, `G-REM-003` Disable Manifest Component, `G-REM-004` Guarded SDK Artifact Removal).
- *Strict Approval Gate*: Modifications are never automatic or silent; `--apply` / `approved=True` is strictly required. Unapproved runs produce dry-run plans only.
- *Original APK Byte-Integrity*: The original input APK is never modified; SHA-256 is verified byte-identical before and after all operations.
- *Target Resolution vs. APK Verification*: Clear architectural distinction between APK verification (structural/signature/noise integrity) and finding resolution (`REMEDIATED`, `PARTIALLY_REMEDIATED`, `STILL_PRESENT`, `NO_LONGER_COMPARABLE`, `UNKNOWN`).
- *Partial Remediation Transparency*: When a manifest permission is removed (`G-REM-002`) but DEX bytecode retains invocations to the protected API, the resolution is reported as `PARTIALLY_REMEDIATED` rather than falsely claiming complete elimination.
- *Conflict and Rollback Safety*: Pre-modification conflict detection and atomic workspace rollback upon failure, preserving the workspace for manual review if rollback fails.

**Remediation Boundaries & Invariants (Not Defects)**

- *No Safety Claims*: Remediating a finding does not make an APK "safe", "malware-free", or "spyware-free".
- *Bytecode Retention on Permission Removal*: Removing a `<uses-permission>` tag from `AndroidManifest.xml` prevents the runtime grant of that permission, but does not alter DEX bytecode instructions. If the application attempts to invoke the permission-gated API at runtime without checking permissions, a `SecurityException` may occur.
- *Component Interdependencies*: Disabling an activity, service, or receiver via `android:enabled="false"` may cause application instability if other components rely on it via explicit intents or bindings.
- *SDK Stripping Limits*: Complete removal of third-party SDKs without breaking bytecode references requires byte-level stubbing or AST refactoring, which is beyond Phase G's conservative scope (`G-REM-004` is conditional and refused when references remain).
- *Dynamic Feature / Split APK Limits*: Remediation operates on monolithic APKs; split APKs with external feature modules are not supported.

---

## Status update — Phase H.1 Evidence & Reference Model

Design and models: [`docs/transformation.md`](transformation.md). Evidence:
`artifacts/phase-h/` (`build-tests/run_phase_h1_validation.py`).

**Introduced by Phase H.1**

- *Read-only reference index*: class, method, field, type, string, constructor and
  `const-class` references from decoded smali; reflection and native/JNI indicators;
  manifest and resource/asset references — each with file/line/XML provenance and a
  stable evidence id.
- *Explicit completeness*: `COMPLETE` / `PARTIAL` / `UNKNOWN` / `NOT_ANALYZED` per
  component and per query; aggregates are never more complete than their weakest input.
- *No false proof of absence*: `absence_established` is true only for an empty result of a
  COMPLETE analysis; `assess_absence` reports `ABSENCE_NOT_ESTABLISHED` otherwise.
- *No transformation*: H.1 never modifies, rebuilds, signs or installs an APK.

**Limitations (by design, not defects)**

- *Static scope only*: unresolved reflection, dynamic code loading (`DexClassLoader`...),
  native code, generated code, incomplete decoding, encrypted/obfuscated configuration and
  server-driven behaviour can reference a class with no static evidence. Evidence (or its
  absence) never establishes runtime behaviour.
- *Local register tracking*: reflection and `loadLibrary` targets resolve only from a
  constant in the same straight-line block (cleared at branch-target labels). Values built
  by concatenation, loaded from fields/resources, or passed across methods are
  `TARGET_UNKNOWN`. Any unresolved indicator makes `reflection` PARTIAL, so in practice
  most real apps never reach a COMPLETE class-reference conclusion.
- *Native binaries are not analysed*: any native method, `System.load*` call or bundled
  `.so` makes `native_code` `NOT_ANALYZED`; JNI `FindClass`/`RegisterNatives` references
  are not observed. Third-party loaders (e.g. ReLinker) are not recognised as library
  loads (their calls are still ordinary method references).
- *Uninterpreted smali*: `invoke-custom`, `const-method-handle`, `const-method-type`,
  odex `*-quick` instructions and unknown directives are reported as issues (the file is
  PARTIAL); their type descriptors are still recorded as `unsupported-operand` mentions.
- *Resource matching is target-bound*: res/assets are matched only against classes
  defined in the analysed smali and manifest provider authorities; textual matches
  (`EXACT_VALUE`, `EMBEDDED_TOKEN`) are indirect evidence. Binary assets that are not a
  known media/font format (embedded DEX/JAR/ZIP, databases...) are not inspected and make
  `assets` PARTIAL. Strings inside `dalvik.annotation.*` system annotations are ignored.
- *Manifest XML location* is the Phase E manifest-tree element key, not a line number.
- *Volume*: large apps produce millions of records (NewPipe: ~1.5M, ~40 s, ~0.85 GB RSS).
  The CLI JSON omits per-instruction code references unless `--all-evidence` is given;
  the programmatic result and `--report x.json` keep everything.
- *Class / type mentions are aggregated per (source method, target, role)*: the first
  location is kept and `occurrences` counts the rest; method/field/string records are
  per occurrence.

## Status update — Phase H.2 Transformation Eligibility & Planning

Design: [`docs/transformation.md`](transformation.md#phase-h2--transformation-eligibility--deterministic-planning).
Evidence: `artifacts/phase-h/H2-TRANSFORMATION-PLANNING.md`
(`build-tests/run_phase_h2_validation.py`).

**Introduced by Phase H.2**

- *Planning only*: `apkforge transform` / `TransformationPlanningService` evaluate
  H-TRANS-001 (remove isolated class) and H-TRANS-002 (remove isolated method) and emit
  deterministic plans; nothing is modified, rebuilt, signed or installed, `--apply` is
  rejected.
- *Machine-readable decisions*: five eligibility states, reason codes with a fixed state
  each, per-precondition status, compact target evidence summaries with H.1 evidence ids.
- *H.1 schema 2 (additive)*: class access flags, interfaces, annotations, file state,
  duplicate definitions and method declarations are now recorded by the smali indexer.
  H.1 artifacts committed at 4013e9e were produced with schema 1 and are not regenerated.

**Limitations (by design, not defects)**

- *Most real-app decisions are UNDETERMINED*: one unresolved reflection call, any native
  code or any incomplete resource/asset input anywhere in the APK blocks every removal
  that relies on absence. This is intended; the rules are not relaxed to produce plans.
- *Override resolution needs supertypes*: a virtual method whose class extends or
  implements a framework/library type that is not defined in the APK is UNDETERMINED
  (`OVERRIDE_RELATIONSHIP_UNRESOLVED`); there is no Android API database. Package-private
  visibility is not modelled (a same-signature method in a sub/supertype is treated as an
  override).
- *Method names in resources are not indexed*: only the android:onClick shape (public
  `(Landroid/view/View;)V`) is caught (UNDETERMINED). Data-binding and other XML method
  references are visible only through the generated code H.1 does index.
- *Strings are matched exactly for methods*: any string constant equal to the method name
  (common for short/obfuscated names) makes H-TRANS-002 UNDETERMINED.
- *Runtime annotations are treated as possible dispatch*: any method annotation other than
  `dalvik.annotation.*` / Kotlin metadata blocks H-TRANS-002 (UNDETERMINED).
- *Single-target evaluation*: each request is evaluated against the original APK; a group
  of classes that only reference each other is refused one by one. Group removal and
  cascading plans are out of scope.
- *Plans are not proofs*: an ELIGIBLE plan states that the static evidence supports the
  change within H.1's scope; it does not establish runtime safety, and it does not
  establish that the target is malicious, unnecessary or tracking-related.

## Status update — Phase H.3 Controlled Transformation

Design: [`docs/transformation.md`](transformation.md#phase-h3--controlled-transformation-h-trans-001).
Evidence: `artifacts/phase-h/H3-CONTROLLED-TRANSFORMATION.md`
(`build-tests/run_phase_h3_validation.py`).

**Introduced by Phase H.3**

- *One transformation*: `apkforge transform APK --plan PLAN.json --apply -o OUT` applies an
  ELIGIBLE H-TRANS-001 plan (remove one isolated class) to a copy of the APK, through the
  Phase D pipeline, BuildService, Phase E verification and an H.1 re-analysis. H-TRANS-002
  remains planning-only (`UNSUPPORTED_TRANSFORMATION`).
- *No override*: plans are re-validated (source SHA-256, plan id, H.2 re-evaluation with an
  identical plan); every refusal and failure has a machine-readable reason and stage.

**Limitations (by design, not defects)**

- *Real apps rarely qualify*: H.3 inherits every H.2 rule; on the 9-APK corpus no target is
  ELIGIBLE, so no real-world APK is transformed. The rules are not relaxed.
- *Static verification only*: the output is rebuilt, signed, diffed and re-analysed, never
  installed or run. VERIFIED means "exactly the planned class was removed and nothing else
  changed within the analysed scope", not "the app still works" or "the app is safe".
- *Re-signed output*: the output carries the configured (by default development) key and
  cannot update an installation signed with the original key.
- *Exact consequence prediction*: every DEX string / framework API reference that
  disappears with the class must be predicted before mutation; a misprediction fails the
  run (never passes it). Targets whose removal would drop more than 50 pool strings (the
  Phase E enumeration limit) are refused (`ANALYSIS_INCOMPLETE`), and removals that drop a
  URL or host fail as `UNEXPECTED_DIFF`.
- *Noise floor required*: verification needs a usable no-op baseline for the APK (measured
  by default: one extra unmodified rebuild). An APK whose no-op rebuild is not semantically
  equivalent cannot be transformed (`NOISE_BASELINE_UNAVAILABLE`). Synthetic test APKs are
  therefore "published" once (round trip + a separate v2/v3-only publisher key), as real
  apps are.
- *Archive bytes are not reproducible*: two applications of the same plan give the same
  result and identical entry contents; the APK bytes differ by ZIP metadata.

## Status update — Phase H.4 Transformation Verification Hardening

Design: [`docs/transformation.md`](transformation.md#phase-h4--transformation-verification-hardening).
Evidence: `artifacts/phase-h/H4-TRANSFORMATION-VERIFICATION.md`
(`build-tests/run_phase_h4_validation.py`).

**Introduced by Phase H.4**

- *Control rebuild*: an H-TRANS-001 output is verified against the original and an
  unmodified control rebuild of it; noise is accepted only when the control reproduces the
  same difference with the same content, and the control -> transformed signal must be
  exactly the declared change.
- *Per-domain completeness*: dex, manifest, resources, assets, native, archive, signing and
  endpoints each report `COMPLETE` / `PARTIAL` / `UNKNOWN` / `NOT_ANALYZED`; the overall
  status is never stronger than the weakest mandatory domain.

**Limitations (by design, not defects)**

- *Static only*: H.4 does not establish that the transformed application is safe,
  malware-free, spyware-free or functionally correct when executed.
- *Re-encoded resources are bounded, not proven*: when the toolchain re-encodes
  `resources.arsc` / `res/` binary XML, H.4 establishes byte identity with the control
  rebuild but not semantic identity with the original; the result is at most
  `VERIFIED_WITH_LIMITATIONS` (stricter than the Phase E matrix, which accepts content-
  assured noise as complete).
- *Native code is not analysed*: libraries are compared by content hash and ELF metadata;
  a change is detected, never interpreted. No ELIGIBLE plan exists for an APK with native
  libraries (H.2: `NATIVE_DEPENDENCY_UNKNOWN`), so native modification is demonstrated with
  the plan-less control experiment.
- *v1 signature files* between the control and transformed rebuild are accepted by path
  only; their correctness rests on apksigner and the certificate check.
- *Eligibility is H.2/H.3's*: H.4 checks plan identity and source SHA-256 but does not
  re-run the H.2 eligibility evaluation.
- *No real-world transformation*: H.2 yields no ELIGIBLE target on the 9-APK corpus, so H.4
  is exercised on real APKs only through the noise-floor experiment.

