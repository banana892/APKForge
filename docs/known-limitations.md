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
