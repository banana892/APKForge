# Transformation — Evidence Prerequisite (Phase H.1)

> **H.1 does not perform APK transformations. It only produces evidence that future
> transformation stages may consume.**

Phase H is built incrementally. Each stage must pass its own verification gate before the
next one begins:

```text
H.1  Evidence + reference analysis          <- this document (implemented)
H.2  Transformation eligibility / planning  (not started)
H.3  First narrow transformation            (not started)
H.4  Expanded controlled transformations    (not started)
```

The intended flow for a future deep transformation (for example removing an SDK class) is:

```text
Phase F/G finding -> evidence -> H.1 reference analysis
    -> H.2 eligibility decision -> H.3+ transformation (BuildService + Phase E verification)
```

H.1 stops after producing evidence. It answers:

> *What references this class / method / field, and is the analysis complete enough to
> make a transformation decision?*

Nothing in `apkforge.reference` builds, patches, signs, installs or executes an APK, and no
result claims an APK, class or reference is safe, unused, malware-free or spyware-free.

## Using it

```bash
apkforge references app.apk                       # component states + evidence counts
apkforge references app.apk -c com.example.Foo -v  # absence assessment for a class
apkforge references app.apk --json                 # ANSI-free JSON (code references as counts)
apkforge references app.apk --json --all-evidence  # every per-instruction reference
apkforge references app.apk --report refs.md       # Markdown (or .json: full JSON)
apkforge references app.apk --skip-resources       # res/assets reported NOT_ANALYZED
```

```python
from apkforge.reference import ReferenceAnalysisService

result = ReferenceAnalysisService().analyze("app.apk")  # read-only
index = result.index()
index.find_class_references("com.example.Foo")  # -> QueryResult
index.find_method_references("com.example.Foo", "bar", "(I)V")
index.find_field_references("com.example.Foo", "count", "I")
index.find_type_references("com.example.Foo")
index.find_string_references("com.example.Foo")
index.find_reflection_evidence("com.example.Foo")
index.find_native_dependencies("com.example.Foo")
index.find_manifest_references("com.example.Foo")
index.find_resource_references("com.example.Foo")
index.assess_absence("com.example.Foo")  # -> AbsenceAssessment
```

`ReferenceAnalysisService.analyze_decoded(project, apk_entries=...)` indexes an existing
Apktool project instead (no APK is touched).

### How the APK is read

`analyze()` hashes the APK, decodes it with the existing `BuildService.decode` (Apktool
3.0.3; the APK is first copied into a fresh workspace, the original is never handed to a
tool), indexes the decoded project, deletes the workspace and hashes the APK again
(`original_unchanged`). There is no second APK-processing pipeline: decoding is the
BuildService stage, and the manifest is flattened with the Phase E
`diff.manifest_tree.parse_manifest_xml`.

## Analysis states

| State | Meaning |
|---|---|
| `COMPLETE` | The relevant input was inspected; complete within the static scope below. |
| `PARTIAL` | Some relevant input could not be analysed. |
| `UNKNOWN` | The analyser cannot determine whether the relationship exists. |
| `NOT_ANALYZED` | The analysis was not requested or intentionally not performed. |

### Components

| Component | COMPLETE when | Otherwise |
|---|---|---|
| `dex` (+ `dex:classesN.dex`) | every smali file of every DEX parsed without an uninterpreted reference-bearing line, and every `classes*.dex` in the APK has decoded smali | `PARTIAL` (issues), `UNKNOWN` (a DEX with no decoded/parseable smali) |
| `reflection` | `dex` is COMPLETE and every reflection indicator resolved to a target | `PARTIAL` |
| `native_indicators` | `dex` is COMPLETE and every `System.load*` library was identified | `PARTIAL` |
| `native_code` | `dex` is COMPLETE and there are no native methods, library loads or bundled `.so` files | `NOT_ANALYZED` when native code exists (binaries are not disassembled) |
| `manifest` | the decoded manifest parsed and no class-valued attribute was a resource reference | `PARTIAL` / `UNKNOWN` |
| `resources` (`res/`) | every file parsed (XML) or was text / a media format | `PARTIAL` (unparseable XML, non-media binary, too large, symlink, `resources.arsc` without `res/`) |
| `assets` (`assets/`, Apktool `unknown/`) | as `resources` | `PARTIAL` (e.g. embedded `.dex`/`.jar`/binary blobs) |

### Propagation

`combine_states` never reports an aggregate more complete than its weakest input:

- all `COMPLETE` -> `COMPLETE`; all `NOT_ANALYZED` (or nothing) -> `NOT_ANALYZED`
- only `UNKNOWN`/`NOT_ANALYZED` -> `UNKNOWN`; any other mixture -> `PARTIAL`

So `classes.dex COMPLETE + classes2.dex PARTIAL + classes3.dex COMPLETE` gives `dex
PARTIAL`, and `dex COMPLETE + resources PARTIAL` gives an overall `PARTIAL`. Component
states are always exposed next to the aggregate.

Every query declares which components could have produced (or hidden) its evidence:

| Query | Components |
|---|---|
| class / method / field / type / constructor / const-class | `dex`, `reflection`, `native_code` |
| strings | `dex` |
| reflection | `dex`, `reflection` |
| native | `dex`, `native_indicators`, `native_code` |
| manifest | `manifest` |
| resources | `resources`, `assets` |
| `assess_absence` | all |

## No false proof of absence

`QueryResult.absence_established` is true only for an **empty** result of a **COMPLETE**
query. `AbsenceAssessment.conclusion` is one of:

| Conclusion | When |
|---|---|
| `REFERENCES_OBSERVED` | at least one structural reference from outside the class |
| `ONLY_INDIRECT_EVIDENCE` | no structural reference, but a string, reflection target or textual resource/manifest match mentions it |
| `ABSENCE_NOT_ESTABLISHED` | nothing observed, but some component is not `COMPLETE` |
| `NO_REFERENCES_WITHIN_SCOPE` | nothing observed and every component is `COMPLETE` — still limited to static analysis of this APK |

Example (fixture `f09_reflection`):

```text
No references to com.example.h1.C observed.
dex: COMPLETE   reflection: PARTIAL   native_code: COMPLETE   resources: COMPLETE
Conclusion: ABSENCE_NOT_ESTABLISHED (absence_established = false)
```

## Evidence model

Every record (`Evidence`) carries provenance and its own `analysis_state`:

| Field | Meaning |
|---|---|
| `evidence_id` | `ev-` + 16 hex of SHA-256 over identifying fields (kind, file, line, instruction, context, target, member, descriptor, XML location, matched value) — stable across runs and machines |
| `kind` | see below |
| `source_file` / `source_line` | path relative to the decoded project, 1-based line (`java_line`: smali `.line`) |
| `source_dex` / `source_class` / `source_method` | `classes2.dex`, `com.x.A`, `foo(I)V` |
| `target`, `target_class`, `member_name`, `descriptor` | what is referenced |
| `instruction`, `context` | opcode/directive/XML tag and the role (`method-parameter`, `superclass`, `operand`...) |
| `confidence_basis` | why this is evidence (text; no numeric score) |

Kinds: `CLASS_REFERENCE`, `METHOD_REFERENCE`, `FIELD_REFERENCE`, `TYPE_REFERENCE`,
`STRING_REFERENCE`, `CONSTRUCTOR_REFERENCE`, `CONST_CLASS_REFERENCE`,
`REFLECTION_INDICATOR`, `NATIVE_METHOD`, `NATIVE_LIBRARY_LOAD`, `MANIFEST_REFERENCE`,
`RESOURCE_REFERENCE`. There is no safety score and nothing is labelled malicious.

### Code references (smali)

- **Class references** — class-to-class edges from instructions: `invoke-*` owner,
  field-access owner, `new-instance`, `check-cast`, `instance-of`, `const-class`,
  `new-array`/`filled-new-array`, `.catch`, `.super`, `.implements`. One record per
  (source method, target, instruction, role); repeats increment `occurrences`.
- **Method references** — `invoke-static|direct|virtual|super|interface|polymorphic`
  (`/range` too) with owner, name, proto, readable parameter/return types. `<init>` calls
  are `CONSTRUCTOR_REFERENCE`.
- **Field references** — `iget*/iput*/sget*/sput*` with owner, name, type, access kind.
- **Type references** — every type mention, independent of method/field references:
  method signatures, field types, member descriptors, operands, casts, arrays (element
  type + `array_dimensions`), `const-class`, annotations, `.catch`, `.local` debug info.
  This answers "does anything still *mention* this class?". `TYPE_REFERENCE`s from
  annotation values are structural mentions too (e.g. `InnerClass`/`EnclosingClass`).
- **String references** — `const-string(/jumbo)`, string field initial values and
  non-system annotation strings, with `string_use`:
  `POSSIBLE_REFLECTION_TARGET` (flows into a class-name argument),
  `POSSIBLE_METHOD_NAME` (flows into a member-name argument),
  `POSSIBLE_CLASS_NAME` (class-name shaped **and** names a class defined in this APK),
  `UNKNOWN_STRING_USE` (identifier/class-name shaped, no supporting evidence),
  `STRING_LITERAL` (other text). A string never becomes a class reference by itself.

Self-references (`source_class == target`) are excluded by default from class/type queries
and from `assess_absence`.

### Reflection indicators

Recognised: `Class.forName`, `ClassLoader.loadClass` (any owner with a
`loadClass(String…)`), `Class.getMethod/getDeclaredMethod/getField/getDeclaredField`,
`Class.getConstructor/getDeclaredConstructor/get*s()/newInstance`, `Method.invoke`,
`Constructor.newInstance`, `Field.get*/set*`, `Proxy.newProxyInstance`,
`MethodHandles.Lookup.find*`, and `DexClassLoader`/`PathClassLoader`/
`InMemoryDexClassLoader`/`BaseDexClassLoader`/`DelegateLastClassLoader`/`URLClassLoader`
construction (dynamic code loading).

`resolution`: `TARGET_IDENTIFIED` (the name/class argument traced to a `const-string` /
`const-class` in the same straight-line block — cleared at branch-target labels, kept across
`:try_*` labels and `move-object`), `TARGET_UNKNOWN` (a name/class is taken but not
traceable), `NO_TARGET_IDENTIFIED` (the API acts on a reflective object or loader created
elsewhere). Linked string/const-class evidence ids are in `associated_evidence`.

A reflection indicator does not prove a class is dynamically referenced; it means static
reference analysis may be insufficient. Any indicator that is not `TARGET_IDENTIFIED`
makes the `reflection` component `PARTIAL`.

### Native / JNI indicators

- `NATIVE_METHOD` — methods with the `native` modifier, with the expected JNI symbol in
  `confidence_basis`; `native_resolution` is always `UNKNOWN` (no library association).
- `NATIVE_LIBRARY_LOAD` — `System.loadLibrary/load`, `Runtime.loadLibrary/load` with the
  library (`IDENTIFIED`, plus whether a matching `lib*.so` is bundled) or `UNKNOWN`.
- `bundled_native_libraries` lists every `.so` in the decoded project.

The absence of a `loadLibrary` string is never treated as absence of native dependency.

### Manifest references

From the decoded manifest via `parse_manifest_xml` (element keys such as
`application#0/service[name=.B]` are the XML location): component `android:name`
(activity, service, receiver, provider, instrumentation), `activity-alias`
`android:targetActivity`, `parentActivityName`, application `name` / `backupAgent` /
`appComponentFactory` / `manageSpaceActivity` (`CLASS_ATTRIBUTE`), provider authorities
(`PROVIDER_AUTHORITY`), and any other attribute whose value equals a class defined in the
APK (`EXACT_VALUE`, textual — e.g. `<meta-data android:value>`).

### Resource / XML references

`res/`, `assets/` and Apktool's `unknown/` (e.g. `META-INF/services`) are matched against
classes defined in the APK and declared provider authorities, with file, line, XML
location (`/LinearLayout[1]/com.x.View[1]/@android:name`) and matched value:

- structural: `XML_ELEMENT_NAME` (custom view tags), `CLASS_ATTRIBUTE` (`class`,
  `android:name`, `android:fragment`, `app:layout_behavior`, `actionViewClass`,
  `actionProviderClass`, `targetClass`), `SERVICE_LOADER_ENTRY`
- textual (indirect evidence only): `EXACT_VALUE`, `EMBEDDED_TOKEN`

XML is parsed with expat; DTD entity declarations are refused (`XML_PARSE_ERROR`). When a
file does not parse, its textual matches are kept and the component is `PARTIAL`.

## Determinism

Same APK -> identical JSON: evidence sorted by (file, line, kind, target, id), stable ids,
no timestamps in evidence, only project-relative paths, `exclude_none` serialisation. The
APK identity holds the file name, size and SHA-256 (not the path).

## Static analysis cannot establish runtime behaviour

Reference evidence (or its absence) does not establish what happens at runtime when any
of these are involved: unresolved reflection, dynamic code loading, native code, generated
code (e.g. runtime proxies, bytecode generated on device), incomplete decoding, encrypted
or obfuscated configuration, server-driven behaviour, or anything else unavailable to
static analysis. H.2 must treat `ABSENCE_NOT_ESTABLISHED` and `ONLY_INDIRECT_EVIDENCE` as
blocking for any transformation that relies on absence.

## Verification

- `tests/unit/test_phase_h1_reference.py` — parser, malformed/unsupported input,
  reflection/native, manifest, resources, propagation, determinism, absence.
- `tests/integration/test_phase_h1_references.py` — 14 synthetic fixtures built into real
  APKs with Apktool 3.0.3 (`tests/fixtures/h1_apks.py`), CLI JSON with `FORCE_COLOR=3`.
- `build-tests/run_phase_h1_validation.py all --write` — synthetic + read-only corpus run;
  evidence in `artifacts/phase-h/` (see `H1-REFERENCE-ANALYSIS.md`).
