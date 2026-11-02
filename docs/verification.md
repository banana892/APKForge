# Diff and verification (Phase E)

Phase E hardens how APKForge compares an original APK with a rebuilt or modified one,
and how it decides whether the result is what was asked for. It separates five kinds of
difference:

| kind | meaning |
|---|---|
| expected modification | a change a modifier declared before it ran, matched exactly |
| planned entry | an archive entry (`AndroidManifest.xml`, `classesN.dex`) whose bytes change because a planned edit compiles into it; its *meaning* is checked by the semantic observations |
| rebuild noise | a difference the no-op rebuild of the same APK, with the same toolchain, produces **with the same content** |
| unexpected | APKForge compared the object reliably and it changed outside the plan |
| unknown | APKForge cannot establish whether the difference is meaningful |

Unknown never becomes expected, and nothing is called noise because it is inconvenient
to explain: every noise rule comes from an observed no-op rebuild, and acceptance needs
content identity with that rebuild.

> A clean diff does not prove that an APK is malware-free.
>
> Successful APK verification proves structural and signing validity, not application
> safety.

## Layers

```
E1 raw diff          archive entries: added / removed / modified / unchanged (path + SHA-256)
E2 normalized diff   observations classified against the APK's no-op fingerprint
E3 semantic diff     per-comparator results (manifest, manifest tree, permissions,
                     components, intent filters, certificate, DEX, strings, network,
                     native, resources, resource table, assets, embedded, files)
E4 security diff     security-relevant changes grouped by category, descriptive only
E5 expected/actual   requested -> expected -> actual -> unexpected / unknown
E6 verification      matrix of independent checks, conservative overall status
```

### E1 — raw diff (`apkforge.diff.archive`)

`ArchiveInventory.from_apk()` reads every entry once: path, sizes, CRC, SHA-256 of the
content, ZIP metadata (timestamp, compression, extra-field length) and a kind derived
from the path alone (`manifest`, `dex` — root `classesN.dex` only —, `resource_table`,
`resource`, `asset`, `native_library` — `lib/<abi>/<name>.so` —, `lib_other`,
`signature`, `signing_metadata`, `meta_inf`, `embedded_archive`, `other`). Duplicate
entry names, unreadable entries and unusual paths (dot segments, absolute paths,
backslashes, control characters) are recorded, never dropped.

`raw_diff()` compares two inventories by exact path and content hash. Nothing is paired
or normalised: a moved resource is one removal and one addition at this layer. An entry
with identical content but different ZIP metadata stays `unchanged` and is counted in
`metadata_only_changes`.

Evidence: two no-op rebuilds of the same APK with the same toolchain and key produce
byte-identical content for every entry (all 9 corpus APKs, `artifacts/phase-e/corpus`);
only entry timestamps differ. This is the "zip alignment / generated metadata"
normalisation category: it never touches content, so the raw diff ignores it by
construction rather than by rule.

`DiffResult.raw` carries the raw diff whenever both inputs are APK files.

### E2 — normalized diff (`apkforge.diff.normalization`)

The C.5 noise rules (`expectations.NOISE_RULES`) are path rules. They still *explain* a
no-op rebuild, but since Phase E a later comparison accepts noise only by **content
identity** with what the no-op rebuild of the same APK produced:

1. `run_semantic_noop()` rebuilds the APK unmodified and classifies the diff with the
   path rules. Every accepted difference is stored in the APK's `NoiseFingerprint`
   with its content: SHA-256 before and after for archive entries, certificate
   fingerprints, or the exact identifier/detail for strings and manifest attributes.
2. `verify_expectations(..., fingerprint=...)` accepts an observation as noise only if
   the fingerprint holds the same difference **with the same content**.

| policy | used for | accepted when |
|---|---|---|
| `exact` | DEX, manifest, resource table, resources, renames, residue, compiler marker, manifest path canonicalisation | content before and after equal the fingerprint |
| `signer` | the signing certificate | original certificate equals the fingerprint's and the new one is the certificate APKForge signed with |
| `path_only` | v1 signature files (`META-INF/MANIFEST.MF`, `*.SF`, `*.RSA/DSA/EC`) | same path and change kind |

Signature files are the only path-only rule, because their content is a function of
every other entry and of the key: it necessarily differs whenever anything else does.
Their correctness is established by `apksigner verify` and the certificate check, never
by the diff. A signature file the baseline does not have (e.g. a new `META-INF/X.SF`)
is unexpected.

This closes the path-only blind spot of Phase C/D: before, any content change to an
accepted path (`res/...` re-encoded, `classes.dex` re-encoded) passed as noise. The
OpenLink scenario `H_content_hash` demonstrates it on a real, re-signed APK: the
schema-1 path rules accept a tampered `res/` entry, the fingerprint reports it as
unexpected.

#### Planned entries

When a modifier edits `AndroidManifest.xml` or smali, the compiled entry's bytes change
and cannot match the no-op fingerprint. The pipeline maps the plan's decoded-project
paths to archive entries (`archive_entries_for`). A modified entry in that set is a
`planned_entry` only if the comparators that establish its meaning are complete
(manifest: `manifest_tree`, identity, manifest, permissions, components, intent
filters; DEX: `dex`, `strings`); then every semantic change inside it must still be
expected. Planned changes to `resources.arsc` or `res/` files cannot be verified
semantically and are `unknown`. A plan that touches a project file with no known
archive mapping (e.g. `apktool.yml`) is reported in the warnings.

### Baselines and toolchains

A semantic no-op baseline (`NoopSemanticBaseline`) has two schema versions:

- **1** (Phase C.5, `tests/corpus/results/c5-semantic-noop-baseline.json`): rule ids and
  residue only. Still loadable; reported as `LEGACY_PATH_RULES`. Content is not
  compared, so a run classified with it can never be `VERIFIED`.
- **2** (Phase E, `tests/corpus/results/phase-e-noise-baseline.json`): adds the
  `toolchain_identity` (java, apktool, zipalign, apksigner, build-tools, platform,
  normalization schema, semantic schema) and per APK the content fingerprint,
  comparator statuses and raw counts. No absolute local paths are stored.

`NoopSemanticBaseline.check(sha256, toolchain)` decides whether it can be used:

| status | meaning | classification |
|---|---|---|
| `COMPATIBLE` | schema 2, identical toolchain identity | fingerprint; content mismatch is **unexpected** |
| `BASELINE_PARTIAL` | schema 2, identical toolchain, but the APK's own no-op diff was incomplete (Fennec: embedded inspector partial) | fingerprint; the matrix row is `partial`, so the result is at best UNDETERMINED |
| `TOOLCHAIN_UNKNOWN` | schema 2, build toolchain not declared (`apkforge verify` without `--built-locally`) | fingerprint; content mismatch is **unknown** |
| `LEGACY_PATH_RULES` | schema 1 | path rules, `path_rule` assurance, never VERIFIED |
| `BASELINE_INCOMPATIBLE` | toolchain or schema identity differs | no noise accepted: rule-shaped differences unknown, others unexpected |
| `NO_ENTRY` / `NOT_EQUIVALENT` / `MISSING` | no usable entry | as incompatible |

No cross-toolchain compatibility rule has been validated, so none exists: a baseline
measured with Apktool 3.0.3 / build-tools 35 is never reused for another toolchain.
The modification pipeline always knows its toolchain, so it gets `COMPATIBLE` or
`BASELINE_INCOMPATIBLE`.

Creating a baseline: `build-tests/run_phase_e_validation.py baseline [--write]` for the
corpus; `measure_noise_floor()` / `apkforge modify --measure-noise-floor` /
`apkforge verify --measure-noise-floor` for one APK. If a baseline changes, the runner
reports the drift against the previous one per APK; the reason must be recorded
(toolchain change, normalisation change, extractor fix, APK change, corruption).

### E3 — semantic diff

`DiffResult.comparisons` holds one `ComparatorResult` per comparator with a status:
`unchanged`, `added`, `removed`, `modified` (complete), `partial` (some data compared,
e.g. truncated string enumeration or an inspector that reported warnings),
`not_comparable` (not implemented at that level by design), `undetermined` (a differ or
inspector failed, inputs missing). Inability to compare is never `unchanged`.

New in Phase E: **the full manifest tree** (`apkforge.diff.manifest_tree`). Both
binary manifests are decoded and every element and attribute is compared. Each
difference is either *explained* by a specialised differ that reported exactly that
fact (`explained_by`) or becomes a `manifest_element` observation. `<meta-data>`,
`<queries>`, `<uses-feature>`, `<activity-alias>`, intent-filter `priority`, and any
attribute the inspection model does not extract are therefore covered. Values are
compared as decoded (resource references are not resolved). On the 9 corpus APKs a
no-op rebuild changes no manifest element or attribute.

Comparison levels (also in each `ComparatorResult.level`):

- manifest, permissions, components, intent filters: semantic; `<activity-alias>` only
  in the manifest tree (not modelled as a component)
- certificate: SHA-256 fingerprints
- DEX: classes, methods (code hash), fields; partial when extraction was truncated
- strings / network: extracted values; URLs and domains are not resolved or contacted
- native libraries: content hash and ELF metadata; no code analysis
- resources and assets: content hash per entry; binary XML is not decoded
- resource table: content hash only. A changed `resources.arsc` is `not_comparable`;
  verification accepts it only when it is byte-identical to the no-op rebuild

### E4 — security-relevant diff (`apkforge.diff.security`)

`build_security_diff(diff, verdict)` groups changes into: permissions, components,
intent filters, certificate, network domains/IPs, URLs, native libraries, DEX classes,
embedded executables/archives, sensitive manifest changes (identity, debuggable,
allowBackup, cleartext traffic, network security config, SDK levels) and other manifest
elements. Each item states the observed change, its evidence location, the observation
it belongs to and — when a verdict is given — its classification. Each section states
its availability (`complete` / `partial` / `not_comparable` / `undetermined`). Nothing
is labelled malicious; a new domain is a new domain.

### E5 — expected vs actual

Every pipeline report lists **requested** (plan changes), **expected** (declared
`ExpectedChange`s), **actual** (expected modifications and planned entries observed),
**unexpected** and **unknown**. An expected change is specific: category, kind,
identifier, exact detail (e.g. which component attributes change, from what to what)
and optionally the content (`content_before` / `content_after`, e.g. the SHA-256 of an
added file). A vague expectation ("manifest changed") matches nothing.

### E6 — verification (`apkforge.verification`)

`VerificationMatrix` rows, each `passed` / `failed` / `partial` / `undetermined` /
`not_applicable`, with evidence:

| check | question |
|---|---|
| structural | readable ZIP, CRCs, no duplicate names, decodable binary manifest, DEX/ARSC headers |
| signature | `apksigner verify`, `zipalign -c`, ZIP integrity, expected signer |
| noise_baseline | compatible content-aware baseline available? |
| modification | every modifier executed and passed its own `verify()`? |
| expected_changes | every declared change observed? |
| unexpected_changes | every difference expected, planned or content-identical noise? |
| semantic_diff | every comparator complete (or its changes byte-identical to the no-op)? |
| security_diff | every security category comparable, none unexpected? |

Overall: `FAILED` if any row failed; otherwise `UNDETERMINED` if any row is partial or
undetermined; otherwise `VERIFIED`. The signature check never assumes validity: without
a toolchain it is `undetermined`.

The matrix is part of the modification lifecycle: `ModificationPipeline.run()` builds it
after the diff (`PipelineResult.verification_matrix`, `.report`). A matrix that is not
`VERIFIED` turns a `verified` run into `unverified` (CLI exit 3); a `FAILED` matrix makes
the run fail.

## Reports

`VerificationReport` (`schema_version` 1, `kind: apkforge.verification_report`) is the
JSON document of `apkforge verify --json` and of `PipelineResult.report`.
`render_markdown()` renders the sections RAW DIFF, NORMALIZED DIFF, SEMANTIC DIFF,
SECURITY-RELEVANT DIFF, REQUESTED, EXPECTED CHANGES, ACTUAL CHANGES, UNEXPECTED
CHANGES, UNKNOWN / UNDETERMINED, VERIFICATION, LIMITATIONS and the evidence discipline:
observed fact, inference, risk assessment (none), unknown. APKs are identified by file
name and SHA-256; no absolute paths are embedded.

`DiffResult` JSON is schema 2: the Phase 3 fields keep their meaning; `schema_version`,
`raw`, `manifest_tree` and `comparisons` were added.

## CLI

```bash
apkforge diff ORIGINAL MODIFIED [--raw] [--security] [--baseline BASELINE.json] [--json]
apkforge verify APK [--json]                              # structure + signature
apkforge verify ORIGINAL MODIFIED [--baseline FILE | --measure-noise-floor]
                [--built-locally] [--expected EXPECTED.json] [--expected-signer SHA256]
                [--planned-file PROJECT_PATH ...] [--json] [--report REPORT.md]
apkforge modify APK -m MODIFIER --noop-baseline tests/corpus/results/phase-e-noise-baseline.json
```

`--planned-file` (repeatable) names a decoded-project path the modification edited
(`AndroidManifest.xml`, `smali_classes2/com/x/A.smali`, `res/values/strings.xml`, ...). The
archive entries rebuilt from it (`archive_entries_for`) are accepted when their semantic
changes are expected, as in the modification pipeline's own verification; a path with no
known archive mapping is a usage error.

`verify` exits 0 VERIFIED, 1 FAILED, 3 UNDETERMINED, 2 usage/toolchain error. JSON output
is written with plain `typer.echo` and contains no ANSI escapes, whatever `FORCE_COLOR`
says.

## Limitations

- `<activity-alias>` is compared only structurally (manifest tree), not as a component.
- `resources.arsc` entries and `res/` binary XML are not decoded. A same-path content
  change is detected (hash), but not interpreted; a planned resource change is unknown.
- DEX comparison is limited by the extraction budget (50 000 classes, 200 000 methods);
  truncation makes the comparator partial. String enumeration in the diff lists at most
  50 added/removed values; more makes `strings` partial and the verdict unknown.
- Native libraries: hash and ELF metadata only.
- Manifest tree values are compared as decoded; an attribute whose encoding changes
  without a semantic change would be reported (never hidden). None was observed on the
  corpus.
- APKs without a schema-2 baseline for the exact toolchain cannot be VERIFIED.
- Pair verification of an APK built elsewhere has `TOOLCHAIN_UNKNOWN` semantics: exact
  content identity is still accepted, everything else is unknown.
- Verification covers what the comparators can see. It is not a malware or safety
  verdict.
