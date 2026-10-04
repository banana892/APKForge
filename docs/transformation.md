# Transformation — Evidence (H.1), Eligibility Planning (H.2), Controlled Application (H.3), Verification Hardening (H.4)

> **H.1 does not perform APK transformations. It only produces evidence that future
> transformation stages may consume.**
>
> **H.2 determines whether a proposed transformation is supported by the available static
> evidence and produces a deterministic plan. It does not apply the transformation and
> does not establish that the target behavior is malicious.**
>
> **H.3 applies exactly one validated, ELIGIBLE H.2 plan of H-TRANS-001 (remove isolated
> class) to a copy of the APK and verifies the result. It has no override, never writes the
> input APK and never claims that an application is safe or malware-free.**

Phase H is built incrementally. Each stage must pass its own verification gate before the
next one begins:

```text
H.1  Evidence + reference analysis          (implemented, read-only)
H.2  Transformation eligibility / planning  (implemented, planning only — see below)
H.3  First narrow transformation            (implemented: H-TRANS-001 — see below)
H.4  Verification of transformed APK        (implemented — see below)
H.5  Controlled isolated-method removal     (implemented: H-TRANS-002)
H.6  Controlled call-site replacement       (implemented: H-TRANS-003 — see the end)
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

### Declarations (H.1 schema 2, added for H.2)

`DefinedClass` additionally records the class `access_flags` (smali modifiers, e.g.
`public`, `interface`, `abstract`, `enum`), `interfaces`, class-level `annotations`, the
`analysis_state` of the defining smali file, `duplicate_sources` (other files defining the
same class; the first definition is kept) and `methods` (`DefinedMethod`: name, proto
descriptor, access flags, method-level annotations, declaration line). Field and parameter
annotations are not recorded as class/method annotations. The change is additive; existing
evidence is unchanged. Compact JSON (`include_code_references=False`, the CLI default)
omits the per-class `methods`.

### Invocation operands (H.1 schema 3, added for H.6)

Every invocation record (`METHOD_REFERENCE` / `CONSTRUCTOR_REFERENCE`) additionally carries
`registers` (its operand registers in order, `/range` expanded) and, when the next
instruction is a `move-result*`, `result_instruction` / `result_register` (directives,
blank lines and labels between the two do not break the association). `invoke-custom`
call sites, previously visible only as an `UNSUPPORTED_INSTRUCTION` issue, are also
recorded as an invocation of their bootstrap method (`invoke_kind` `invoke-custom`,
`context` `call-site-bootstrap`); the issue stays, so the file stays `PARTIAL`.
`ReferenceIndex.invocations_in(class, method)` lists one method's invocations in source
order. The new fields are not part of the evidence id (schema-2 ids are unchanged) and are
`None` in results produced before schema 3; H.6 treats such records as
`CALLER_ANALYSIS_INCOMPLETE`, never as compatible. Because `analysis_schema` is part of
every plan id, plans written against schema 2 are refused as `PLAN_INVALID` (schema
mismatch) by the executor and must be re-planned.

---

# Phase H.2 — Transformation Eligibility & Deterministic Planning

H.2 is the decision layer between H.1 evidence and any future APK transformation:

```text
Phase F/G evidence ─> H.1 reference analysis ─> H.2 eligibility ─> deterministic plan
                                                                    │
                                                                 [STOP]
                                                                    │
                                    approval ─> H.3 transformation ─> build ─> verification
```

H.2 answers: *given the available evidence, is this proposed transformation sufficiently
supported to be considered eligible, or must APKForge refuse or defer it?* It never
modifies, rebuilds, aligns, signs or installs an APK, never executes app code, and accepts
no `--apply`. Plans describe what a future H.3 engine would do; `applied` is always false.

**Why H.2 does not modify APKs.** A plan is only as good as the evidence behind it. Keeping
decision and mutation in separate, separately verified layers means a wrong eligibility
rule can only produce a wrong *plan* — which is reviewable, deterministic and harmless —
never a damaged APK. The first transformation belongs to H.3 and is evaluated
independently.

## Using it

```bash
apkforge transform app.apk --transform H-TRANS-001 --target com.example.Target --dry-run
apkforge transform app.apk --transform H-TRANS-002 \
    --target 'com.example.Target->method(Ljava/lang/String;)V' --dry-run
apkforge transform app.apk -t H-TRANS-001 --target com.x.A --target com.x.B --json
apkforge transform app.apk -t H-TRANS-001 --target com.x.A \
    -t H-TRANS-002 --target 'com.x.B->m()V' --report plan.md -v
```

One `--transform` applies to every `--target`; otherwise give one per target (paired in
order). `--json` (ANSI-free, deterministic), `--report x.md|x.json`, `--verbose`,
`--skip-resources` (resource requirements become UNDETERMINED), `--work-dir`. `--dry-run`
is accepted for explicitness; with `-t/--target`, planning is the only mode. `--apply`
without `--plan` exits with code 2 ("planning-only"): planning and mutation are never
combined in one step (applying a saved plan is H.3, below). Exit codes: 0 planned,
1 analysis error / input changed, 2 usage error.

```python
from apkforge.transformation import TransformationPlanningService, TransformationRequest

svc = TransformationPlanningService()  # wraps ReferenceAnalysisService
result = svc.plan(
    "app.apk",
    [
        TransformationRequest(transformation_id="H-TRANS-001", target="com.example.Unused"),
    ],
)
result.decisions[0].eligibility  # EligibilityState
result.decisions[0].reasons  # [ReasonDetail(code=..., ...)]
result.plans  # plans for (conditionally) eligible requests

# over an existing H.1 result (pure, no I/O):
TransformationPlanningService.plan_from_result(reference_result, requests)
```

Package `apkforge.transformation`: `models` (states, reasons, plan models), `catalog`
(H-TRANS-001/002), `targets` (parsing/resolution), `selector`
(`TargetEvidenceSelector`), `eligibility` (`EligibilityEvaluator`), `conflicts`,
`planner` (`TransformationPlanner`, `TransformationPlanningService`), `report`.
Risk and reversibility reuse the Phase D `ModificationRisk` / `Reversibility` enums.

## Eligibility states

| State | Meaning |
|---|---|
| `ELIGIBLE` | Every required evidence item and precondition is satisfied (static scope). A plan is generated. |
| `CONDITIONALLY_ELIGIBLE` | Satisfied, but an explicit documented condition must be met before application. A plan is generated with unsatisfied `conditions`; it is **not** an approval. |
| `REFUSED` | The request conflicts with observed evidence or a defined safety rule. |
| `UNSUPPORTED` | APKForge does not support this transformation for this target shape. |
| `UNDETERMINED` | The available analysis is insufficient to establish eligibility. Never converted to `ELIGIBLE`. |

Every reason code imposes exactly one state (`REASON_STATES`). When several apply, the
strongest wins: `REFUSED > UNSUPPORTED > UNDETERMINED > CONDITIONALLY_ELIGIBLE`. `ELIGIBLE`
is the absence of reasons *and* every precondition `SATISFIED`; an unanswered
precondition can never become eligible. All reasons are reported, not only the deciding one.

## Decision reason codes

| Code | State | When |
|---|---|---|
| `TARGET_NOT_FOUND` | REFUSED | class/method not defined (and every class definition was read) |
| `TARGET_AMBIGUOUS` | REFUSED | class defined in several files, simple name matching several classes, or method name with several overloads and no proto |
| `TARGET_NOT_FULLY_QUALIFIED` | REFUSED | unqualified name matching exactly one class (never guessed) |
| `UNSUPPORTED_TARGET_TYPE` | UNSUPPORTED | member target for a class transformation (or vice versa), arrays/primitives, malformed proto |
| `UNKNOWN_TRANSFORMATION` | UNSUPPORTED | id not in the catalog |
| `ANALYSIS_INCOMPLETE` | UNDETERMINED | target not found but not every class definition was read (decode failure, missing decoded DEX) |
| `DEX_ANALYSIS_INCOMPLETE` | UNDETERMINED | `dex` is not COMPLETE, so code-reference absence is not established |
| `TARGET_DEFINITION_INCOMPLETE` | UNDETERMINED | the target's own smali file is PARTIAL |
| `REFLECTION_ANALYSIS_INCOMPLETE` | UNDETERMINED | `reflection` not COMPLETE although no unresolved target exists |
| `MANIFEST_ANALYSIS_INCOMPLETE` | UNDETERMINED | `manifest` not COMPLETE |
| `RESOURCE_ANALYSIS_INCOMPLETE` | UNDETERMINED | `resources` or `assets` not COMPLETE (incl. `--skip-resources`) |
| `CLASS_CALLER_PRESENT` | REFUSED | another class has an instruction-level class reference |
| `TYPE_REFERENCE_PRESENT` | REFUSED | another class mentions the type (signatures, fields, casts, annotations...) |
| `METHOD_CALLER_PRESENT` | REFUSED | method call through the class (H-TRANS-001) / call site on the class or a defined subclass (H-TRANS-002) |
| `FIELD_REFERENCE_PRESENT` | REFUSED | field access through the class |
| `CONSTRUCTOR_REFERENCE_PRESENT` | REFUSED | constructor invocation |
| `CONST_CLASS_REFERENCE_PRESENT` | REFUSED | `const-class` load |
| `STRING_REFERENCE_UNRESOLVED` | UNDETERMINED | a string constant names the target (indirect evidence; never a direct reference) |
| `REFLECTION_TARGET_PRESENT` | REFUSED | reflection statically resolved to the target |
| `REFLECTION_TARGET_UNKNOWN` | UNDETERMINED | reflection with an unresolved target exists (may reach the target) |
| `DYNAMIC_CODE_LOADING_PRESENT` | UNDETERMINED | a class loader is constructed |
| `ANNOTATION_DRIVEN_ACCESS_POSSIBLE` | UNDETERMINED | runtime annotation on the method (e.g. `@JavascriptInterface`, event-bus `@Subscribe`) |
| `NATIVE_METHOD_DECLARED` | UNSUPPORTED | the class declares native methods |
| `NATIVE_DEPENDENCY_UNKNOWN` | UNDETERMINED | `native_indicators` / `native_code` not COMPLETE (JNI can reach any class/method) |
| `MANIFEST_COMPONENT_REFERENCE` | REFUSED | activity / activity-alias / service / receiver / provider names the class |
| `MANIFEST_REFERENCE_PRESENT` | REFUSED | other structural manifest reference (application name, backupAgent, instrumentation...) |
| `MANIFEST_TEXTUAL_MATCH` | UNDETERMINED | a manifest value equals the class name (textual) |
| `RESOURCE_REFERENCE_PRESENT` | REFUSED | structural res/asset reference (custom view tag, `class=`, `android:fragment`, ServiceLoader entry...) |
| `RESOURCE_TEXTUAL_MATCH` | UNDETERMINED | textual res/asset match (`EXACT_VALUE`, `EMBEDDED_TOKEN`) |
| `RESOURCE_METHOD_REFERENCE_NOT_ANALYZED` | UNDETERMINED | public `(Landroid/view/View;)V` method (android:onClick shape; H.1 does not index method names in layouts) |
| `CONSTRUCTOR_METHOD`, `CLASS_INITIALIZER`, `ABSTRACT_METHOD`, `INTERFACE_METHOD`, `NATIVE_METHOD`, `SYNTHETIC_METHOD`, `ENUM_IMPLICIT_METHOD`, `SERIALIZATION_HOOK_METHOD` | UNSUPPORTED | special method shapes (see H-TRANS-002) |
| `METHOD_OVERRIDES` | UNSUPPORTED | overrides/implements a method of a defined supertype or `java.lang.Object` |
| `METHOD_OVERRIDDEN` | UNSUPPORTED | a defined subclass overrides it |
| `OVERRIDE_RELATIONSHIP_UNRESOLVED` | UNDETERMINED | a supertype of a virtual method is not defined in the APK (framework/library) |
| `CONFLICTING_TRANSFORMATION` | REFUSED | another request in the same set overlaps the target |
| `KOTLIN_METADATA_UPDATE_REQUIRED` | CONDITIONALLY_ELIGIBLE | the class carries `kotlin.Metadata`, which would still describe the removed function |

Each `ReasonDetail` carries the code, its state, the precondition it answers, a
human-readable message, the total `evidence_count` and up to 10 H.1 `evidence_ids`.

## H.1 -> H.2 data flow and target evidence extraction

```text
ReferenceAnalysisResult ─> result.index() (H.1, built once)
      └─ TargetEvidenceSelector (built once per result: class map, subtype map,
         reflection/native/manifest/resource records by class, string-token index)
            └─ select(target) ─> TargetEvidenceSet (only the target's records, by category)
                  └─ EligibilityEvaluator ─> state + reasons + precondition checks
                        └─ TransformationPlanner ─> TransformationDecision (+ plan)
```

The selector answers each target with dictionary lookups (`ReferenceIndex.evidence_targeting`
and the per-class tables); it never walks the full evidence list per target. The string-token
table (defined class name -> string constants mentioning it, same boundary rule as H.1
`assess_absence`) is built once, lazily, over the distinct strings.

Categories of a class target: `class_references`, `type_references`, `method_references`,
`field_references`, `constructor_references`, `const_class_references` (all excluding the
class's own self-references), `string_mentions`, `reflection_targeting` (resolved to the
class), `reflection_unresolved` (APK-wide `TARGET_UNKNOWN`), `dynamic_code_loading`,
`native_declared`, `native_code` (loads performed by the class), `manifest_references`,
`resource_references`. A method target: `call_sites` (owner = the class or any defined
subclass; a method calling itself is not a remaining caller), `reflection_targeting`
(member name resolved on the class/subclass, or `getMethods`/`getDeclaredMethods` on it),
`reflection_name_match` (member name resolved on an unresolved class),
`reflection_unresolved`, `dynamic_code_loading`, `string_mentions` (constants equal to the
method name), `native_declared`.

Every category reports its count, H.2 absence status, the combined state of the components
it depends on, up to 10 evidence ids (`truncated` when more) and up to 10 source classes.

### Completeness and absence rules

A category's absence status follows H.1 semantics:

| Status | When | Effect |
|---|---|---|
| `ABSENCE_ESTABLISHED` | nothing observed and the category's components are COMPLETE | may satisfy a precondition |
| `ABSENCE_NOT_ESTABLISHED` | nothing observed, a component is not COMPLETE | blocks: the precondition is `NOT_ESTABLISHED` (UNDETERMINED) |
| `ONLY_INDIRECT_EVIDENCE` | only strings / textual / unresolved hints | never a direct reference; UNDETERMINED (or REFUSED where a rule says so) |
| `REFERENCES_PRESENT` | structural references observed | REFUSED for removal preconditions |

Category -> components: code/strings/dynamic loading -> `dex`; reflection -> `dex`,
`reflection`; native -> `dex`, `native_indicators`, `native_code`; manifest -> `manifest`;
resources -> `resources`, `assets`. A decision is never stronger than these states:
`dex COMPLETE + reflection PARTIAL` cannot yield "no references", and `reflection UNKNOWN`
is never read as "no reflection".

## H-TRANS-001 — Remove isolated class

Target: a fully-qualified class name (`com.x.A`, `com/x/A` or `Lcom/x/A;`).

| Precondition | Satisfied when | Otherwise |
|---|---|---|
| `class_exists` | defined exactly once | `TARGET_NOT_FOUND` / `TARGET_AMBIGUOUS` / `TARGET_NOT_FULLY_QUALIFIED` (REFUSED); `ANALYSIS_INCOMPLETE` if definitions were not all read |
| `dex_analysis_complete` | `dex` and the class's file COMPLETE | `DEX_ANALYSIS_INCOMPLETE`, `TARGET_DEFINITION_INCOMPLETE` |
| `no_callers` | no class reference from another class | `CLASS_CALLER_PRESENT` |
| `no_type_references` | no type mention from another class | `TYPE_REFERENCE_PRESENT` |
| `no_member_references` | no method call / field access through the class | `METHOD_CALLER_PRESENT`, `FIELD_REFERENCE_PRESENT` |
| `no_constructor_references` | — | `CONSTRUCTOR_REFERENCE_PRESENT` |
| `no_const_class_references` | — | `CONST_CLASS_REFERENCE_PRESENT` |
| `no_string_references` | no string names the class | `STRING_REFERENCE_UNRESOLVED` |
| `no_reflection_target` | reflection COMPLETE and none resolved to the class | `REFLECTION_TARGET_PRESENT`, `REFLECTION_TARGET_UNKNOWN`, `REFLECTION_ANALYSIS_INCOMPLETE` |
| `no_dynamic_code_loading` | no class loader constructed | `DYNAMIC_CODE_LOADING_PRESENT` |
| `no_native_dependency` | no native method in the class; native components COMPLETE | `NATIVE_METHOD_DECLARED`, `NATIVE_DEPENDENCY_UNKNOWN` |
| `no_manifest_reference` | manifest COMPLETE, nothing names the class | `MANIFEST_COMPONENT_REFERENCE`, `MANIFEST_REFERENCE_PRESENT`, `MANIFEST_TEXTUAL_MATCH`, `MANIFEST_ANALYSIS_INCOMPLETE` |
| `no_resource_reference` | resources/assets COMPLETE, nothing names the class | `RESOURCE_REFERENCE_PRESENT`, `RESOURCE_TEXTUAL_MATCH`, `RESOURCE_ANALYSIS_INCOMPLETE` |
| `no_conflicting_transformation` | no overlapping request | `CONFLICTING_TRANSFORMATION` |

Inner/nested classes that reference the target count as references, so a class group that
only references itself is refused one class at a time (group removal is out of scope).

## H-TRANS-002 — Remove isolated method

Target: `class->name(proto)` with a smali proto (`com.x.A->m(ILjava/lang/String;)V`); the
proto may be omitted only when the name is not overloaded.

| Precondition | Satisfied when | Otherwise |
|---|---|---|
| `method_exists` | declared exactly once by the class | `TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS` |
| `dex_analysis_complete` | `dex` and the class's file COMPLETE | `DEX_ANALYSIS_INCOMPLETE`, `TARGET_DEFINITION_INCOMPLETE` |
| `ordinary_method` | not one of the special shapes below | UNSUPPORTED codes |
| `no_call_sites` | no invocation with owner = the class or a defined subclass | `METHOD_CALLER_PRESENT` |
| `no_override_relationship` | private/static, or every supertype defined and no override either way | `METHOD_OVERRIDES`, `METHOD_OVERRIDDEN` (UNSUPPORTED), `OVERRIDE_RELATIONSHIP_UNRESOLVED` (UNDETERMINED) |
| `no_reflection_target` | as for classes, by member name / method enumeration | `REFLECTION_TARGET_PRESENT`, `REFLECTION_TARGET_UNKNOWN`, `REFLECTION_ANALYSIS_INCOMPLETE` |
| `no_dynamic_invocation` | no class loader (`invoke-custom`/method handles already make `dex`/`reflection` incomplete) | `DYNAMIC_CODE_LOADING_PRESENT` |
| `no_native_boundary` | native components COMPLETE | `NATIVE_DEPENDENCY_UNKNOWN` |
| `no_annotation_driven_access` | no method annotation besides `dalvik.annotation.*` / Kotlin metadata | `ANNOTATION_DRIVEN_ACCESS_POSSIBLE` |
| `no_resource_method_reference` | not a public `(Landroid/view/View;)V` method | `RESOURCE_METHOD_REFERENCE_NOT_ANALYZED` |
| `no_string_references` | no string constant equals the method name | `STRING_REFERENCE_UNRESOLVED` |
| `metadata_consistency` | class has no `kotlin.Metadata` | `KOTLIN_METADATA_UPDATE_REQUIRED` (CONDITIONALLY_ELIGIBLE) |
| `no_conflicting_transformation` | no overlapping request | `CONFLICTING_TRANSFORMATION` |

Special shapes, never treated as ordinary removable methods (UNSUPPORTED): constructors
(`<init>`), the class initializer (`<clinit>`), `abstract` methods, any method of an
interface (incl. default/static), `native` methods, `bridge`/`synthetic` methods, enum
`values()`/`valueOf(String)` (called reflectively by the runtime), and Java serialization
hooks (`writeObject`, `readObject`, `readObjectNoData`, `writeReplace`, `readResolve`).
Overrides of `java.lang.Object` methods (`equals`, `hashCode`, `toString`, `finalize`,
`clone`) are `METHOD_OVERRIDES`.

## Policies

- **Reflection** (conservative): a reflection call statically associated with the target
  (class constant / resolved member name on the class or a subclass / method enumeration on
  it) -> REFUSED `REFLECTION_TARGET_PRESENT`. Any reflection with an unresolved target ->
  UNDETERMINED `REFLECTION_TARGET_UNKNOWN`. Only a COMPLETE reflection component with no
  target evidence satisfies the requirement. A reflection call resolved to a *different*
  class is unrelated and ignored.
- **Native/JNI**: a native target method or a class declaring native methods ->
  UNSUPPORTED. Native code present but not analysed (`native_code NOT_ANALYZED`) or an
  unidentified library load -> UNDETERMINED `NATIVE_DEPENDENCY_UNKNOWN` for every target,
  because JNI can reach Java classes and methods without static evidence.
- **Manifest**: a class named by `activity`, `activity-alias`, `service`, `receiver` or
  `provider` -> REFUSED `MANIFEST_COMPONENT_REFERENCE`. H.2 never proposes disabling the
  component instead; that is a Phase G remediation.
- **Resources/XML**: structural references -> REFUSED; textual matches are respected as H.1
  evidence kinds (indirect -> UNDETERMINED, never a definitive reference); incomplete
  resource or asset analysis -> UNDETERMINED `RESOURCE_ANALYSIS_INCOMPLETE`.

## Conflict handling

Each request is evaluated against the *original* APK; requests in a set are never assumed
to have been applied. Overlapping requests are detected before any plan is generated and
every participant is REFUSED with `CONFLICTING_TRANSFORMATION` (`PlanningResult.conflicts`
lists them):

- `duplicate_class_target` — the same class targeted twice (any target spelling);
- `duplicate_method_target` — the same method twice (a proto-less name overlaps every
  overload of that name; different overloads do not conflict);
- `class_method_overlap` — removing a class and transforming one of its methods.

No plan is ever marked eligible while its own request set is contradictory.

## Deterministic plans

A plan (for ELIGIBLE / CONDITIONALLY_ELIGIBLE only) contains `plan_id`, `planning_schema`,
`analysis_schema`, `transformation_id`, the APK identity (file name, size, SHA-256,
package, version — never a path), the normalised `target`, `parameters`, `eligibility`,
`decision_reasons`, `target_evidence_summary`, `preconditions` (every requirement with its
status), `conditions`, `planned_changes`, `expected_changes`, `verification_requirements`,
`risk`, `reversibility`, `compatibility_constraints`, `limitations` and `applied: false`.

```json
{
  "plan_id": "plan-8651a6db9a945c3a2761",
  "transformation_id": "H-TRANS-002",
  "target": {"kind": "method", "class_name": "com.example.h1.D",
             "method_name": "helper", "descriptor": "()V", "raw": "..."},
  "eligibility": "ELIGIBLE",
  "planned_changes": [{"type": "remove_method", "target": "com.example.h1.D->helper()V",
                       "artifact": "smali/com/example/h1/D.smali",
                       "details": {"dex": "classes.dex", "declaration_line": "47",
                                   "access_flags": "public"}}],
  "applied": false
}
```

`plan_id` (and `decision_id`) = SHA-256 over APK SHA-256 + transformation id + normalised
target + sorted parameters + H.1 schema + H.2 schema (first 20 hex). The same inputs give
the same id and identical plan content; nothing time-, machine- or path-dependent is
included and every list is sorted. Plans store a target evidence *summary* with evidence
ids, never the H.1 index: a decision stays a few KB even when 100,000 records reference the
target (`tests/unit/test_phase_h2_transformation.py::test_planning_is_index_based_and_compact`).

## Verification (H.2)

- `tests/unit/test_phase_h2_transformation.py` — every H-TRANS-001/002 case, reason
  codes, completeness propagation, conflicts, determinism, serialization, no filesystem
  mutation, and a 420k-record performance/size regression.
- `tests/integration/test_phase_h2_transformation.py` — real APKs built from
  `tests/fixtures/h1_apks.py` + `tests/fixtures/h2_apks.py`; CLI JSON with `FORCE_COLOR=3`,
  `--apply` rejection, usage errors, reports, input SHA preservation.
- `build-tests/run_phase_h2_validation.py all --write` — synthetic + 9-APK planning run;
  evidence in `artifacts/phase-h/` (see `H2-TRANSFORMATION-PLANNING.md`).

# Phase H.3 — Controlled Transformation (H-TRANS-001)

H.3 is the first stage that changes an APK — a *copy* of it. It applies exactly one H.2
plan, and only one transformation: **H-TRANS-001, remove isolated class**. H-TRANS-002
(remove isolated method) stays planning-only.

```text
APK ─> H.1 analysis ─> H.2 eligibility ─> H.2 plan (JSON)
                                              │  apkforge transform APK --plan PLAN.json --apply -o OUT
                                              ▼
  plan load ─> source SHA-256 ─> plan id ─> ELIGIBLE? ─> H.1 + H.2 re-run (same decision,
  identical plan) ─> expected DEX consequences + noise floor          [nothing written yet]
     ─> ModificationPipeline (Phase D): decode ─> target checks ─> remove ONE smali file
        ─> class census ─> build ─> align ─> sign ─> verify (BuildService)
        ─> Phase E: DiffEngine + expected-vs-actual classification + verification matrix
     ─> H.1 re-analysis of the output (target absent, nothing else changed, same states)
     ─> H.3 verification matrix ─> publish OUT (atomic) only when every check passed
```

## Using it

```bash
# 1. plan (H.2) and keep the plan
apkforge transform app.apk -t H-TRANS-001 --target com.example.Unused --report plan.json
# 2. validate the plan against the APK (dry run: nothing is decoded for mutation, built or signed)
apkforge transform app.apk --plan plan.json
# 3. apply it
apkforge transform app.apk --plan plan.json --apply -o app-transformed.apk --report h3.md
```

`--plan` accepts an H.2 `--report .json` holding exactly one decision, or a single plan
object. `--apply` requires `--plan` and `--output` (which must not be the input).
`--noop-baseline FILE` uses a semantic no-op baseline that contains the APK (for example
`tests/corpus/results/phase-e-noise-baseline.json`); otherwise the APK's noise floor is
measured first with one unmodified rebuild. `--keep-workspace` keeps the build workspace
(it is always kept after a failed mutation, for diagnosis). `--json`, `--report x.md|x.json`
and `--work-dir` as for H.2. There is no `--force`, `--unsafe` or equivalent.
Exit codes: 0 `VERIFIED` / `PLANNED`, 3 `REFUSED` / `UNKNOWN`, 1 `FAILED`, 2 usage error.

```python
from apkforge.transformation import TransformationExecutor

result = TransformationExecutor(build_service).run(
    "app.apk", "plan.json", apply=True, output_apk="out.apk"
)
result.status  # ApplicationStatus.VERIFIED / REFUSED / FAILED / UNKNOWN / PLANNED
result.failure  # ApplicationFailure(code=ApplicationReason..., stage=..., message=...)
result.verification  # the expected-vs-actual matrix (MatrixRow list)
```

Modules: `application` (result models, statuses, reason codes), `executor`
(`TransformationExecutor`, `load_plan`), `modifier` (`RemoveIsolatedClassModifier`, the
plan-bound Phase D modifier), `dexstate` (class census, DEX string-pool and API
attribution), `report` (`format_application_report`).

## H.2 plan consumption and integrity

H.3 never decides eligibility. It checks, in this order, before anything is written:

| Check | Refusal |
|---|---|
| plan file exists / is JSON / matches the H.2 schema (one decision, one `remove_class` change, current planning and H.1 schema versions) | `PLAN_NOT_FOUND` / `PLAN_INVALID` |
| the H.2 decision produced a plan | `PLAN_NOT_ELIGIBLE` (the decision's state and reasons are reported) |
| SHA-256 of the APK == the plan's | `SOURCE_SHA_MISMATCH` |
| plan id recomputed with the H.2 rules (`decision_id_for` over SHA, transformation, re-parsed target, parameters, schemas) | `PLAN_ID_MISMATCH` |
| transformation is H-TRANS-001 | `UNSUPPORTED_TRANSFORMATION` |
| plan eligibility is `ELIGIBLE` with no conditions | `PLAN_NOT_ELIGIBLE` |
| H.1 + the *same* H.2 planner re-run on the APK decide `ELIGIBLE` | `PLAN_NOT_ELIGIBLE` / `ANALYSIS_INCOMPLETE` |
| the re-run produces a plan identical to the given one, field by field | `PLAN_MISMATCH` |

The plan id covers only the plan-defining inputs, so the last two checks are what make an
edited plan (for example `"eligibility": "ELIGIBLE"` written into a refused target's plan,
even with a correctly recomputed id) fail closed. `CONDITIONALLY_ELIGIBLE`, `REFUSED`,
`UNSUPPORTED` and `UNDETERMINED` never reach mutation.

## Mutation semantics

The plan-bound modifier (`h3.remove_isolated_class`, deliberately absent from the default
modifier catalog, so `apkforge modify` cannot request it) runs inside the existing Phase D
`ModificationPipeline`:

- **plan** (decoded workspace, read-only): the target is defined exactly once, in the file
  and DEX the plan recorded; the workspace's class count equals the H.1 analysis'; the DEX
  keeps at least one class; every smali file has a readable `.class` directive. Failures:
  `TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS`, `TARGET_STATE_MISMATCH`, `ANALYSIS_INCOMPLETE`,
  `TRANSFORMATION_PRECONDITION_FAILED` (status `REFUSED`, nothing mutated).
- **apply**: re-checks the target file's SHA-256 and the class census, deletes exactly the
  target smali file, and before any build confirms that the target existed, is now absent,
  exactly one class was removed, no other class was removed, added or moved, and the count
  dropped by one. Anything else is `UNEXPECTED_MUTATION` (`FAILED`, nothing built).
  The pipeline's own source check independently rejects any unplanned file change.
- Mutation record: `{"transformation_id", "operation": "REMOVE_CLASS", "target",
  "target_file", "target_dex", "count", "pre_transform_sha256", "post_transform_sha256":
  null, "classes_before", "classes_after", "removed_classes", "added_classes",
  "census_before_sha256", "census_after_sha256"}`.

Nothing else is touched: no caller, method, permission, manifest component, resource,
asset, native library, SDK setting, URL or metadata is edited, and no code is injected.

## Expected changes (declared before mutation)

Phase E compares original and output semantically, and every observation must be either
declared or measured rebuild noise. Before mutating, H.3 declares:

- `dex_class removed <target>` — the planned change;
- `dex_string removed s` for every DEX string-pool entry (as Phase E enumerates it) that the
  target's smali contributes and no remaining class may contribute (descriptors, member
  and declaration names, prototype shorties, literals, debug names, annotation elements;
  remaining classes are tokenised generously so nothing they use is predicted to vanish);
- `dex_api_reference removed a` for every framework API reference that only the target
  uses, attributed per class exactly as the Phase E DEX inspector collects them (the
  attribution must reproduce the inspector's inventory, otherwise
  `TRANSFORMATION_PRECONDITION_FAILED`).

Both directions fail closed: an undeclared consequence is `UNEXPECTED`, a declared one
that does not happen is a missing expectation. No new diff category exists; nothing is
classified as "looks safe". More than 50 string removals (the Phase E enumeration limit)
is refused up front (`ANALYSIS_INCOMPLETE`). URL/host removals are never declared: a
class whose removal would remove an endpoint fails as `UNEXPECTED_DIFF`.

## Build, verification and post-transform analysis

BuildService builds, aligns, signs (configured or development key) and verifies the
output; stage failures map to `DECODE_FAILED`, `BUILD_FAILED`, `ALIGN_FAILED`,
`SIGN_FAILED`, `SIGNATURE_VERIFICATION_FAILED`. Phase E then runs `DiffEngine`, the
content-aware expected-vs-actual classification against the APK's no-op noise floor and
the verification matrix; any unexpected/unknown observation or missing expectation is
`UNEXPECTED_DIFF` (`NOISE_BASELINE_UNAVAILABLE` when no usable noise floor exists).

H.1 then re-analyses the output: the target must not be defined, no other class may be
removed or added, the class count must drop by exactly one, no structural or indirect
reference to the target may exist, and no component may be weaker than in the original
analysis with DEX `COMPLETE`. An insufficient analysis is `ANALYSIS_INCOMPLETE` with status
`UNKNOWN` (absence is never inferred from incomplete analysis); any other deviation is
`POST_TRANSFORMATION_VERIFICATION_FAILED`.

## Status model and verification matrix

`PLANNED` (validated dry run) → `APPLYING` → `BUILT` → `VERIFIED`; or `REFUSED` (before
any mutation), `FAILED` (a stage or mandatory check failed after mutation started) or
`UNKNOWN` (the result cannot be established). Only `VERIFIED` publishes the output, via a
temporary file and an atomic rename; the input SHA-256 is compared at the end of every run.

| Check | Expected |
|---|---|
| Source SHA | matches the plan |
| Plan ID | exact match |
| Eligibility | ELIGIBLE (plan and re-evaluation) |
| Target class before / after | present / absent (decoded project and H.1 re-analysis) |
| Classes removed / other classes removed | 1 / 0 |
| Build / Align / Sign / Signature verification | success |
| Post-transform analysis | sufficient |
| Unexpected semantic changes | none |
| Original APK SHA | unchanged |

Every row is mandatory; rows not reached are `NOT_RUN`, never `PASS`.

## Result schema

`TransformationApplicationResult` (`schema_version` 1, `phase` "H.3"): `planning_schema`,
`analysis_schema`, `transformation_id`, `plan_id`, `plan_source_sha256`, `source_apk`,
`source_apk_sha256`, `source_apk_sha256_after`, `original_unchanged`, `target` (class,
file, dex), `status`, `status_history`, `dry_run`, `workspace_id`, `planned_changes`,
`expected_changes`, `mutation`, `build` (stages, signer, verification, noise floor),
`diff` (verdict counts, observed/missing/unexpected, Phase E matrix), `analysis`
(`PostAnalysis`), `verification` (matrix), `output_apk`, `output_apk_sha256`,
`output_content_sha256` (over sorted entry name + entry SHA-256), `failure`
(`code`, `stage`, `message`, `details`), `warnings`, `limitations`.
`comparable()` drops run-specific fields (paths, workspace id, archive SHA-256).

## Reproducibility

Applying the same plan to the same APK twice gives an identical `comparable()` result
(mutation record, expected and observed changes, post-analysis, matrix) and identical
archive *entry contents* (`output_content_sha256`); the APK bytes differ only by ZIP
metadata written by the build tools, as for every BuildService rebuild.

## Verification (H.3)

- `tests/unit/test_phase_h3_transformation.py` — reason/status model, plan loading,
  integrity order (refused before any analysis), H-TRANS-002 not applied, string-pool
  tokenisation, class census, report and CLI usage errors.
- `tests/integration/test_phase_h3_transformation.py` — scenarios A–K on real APKs from
  `tests/fixtures/h3_apks.py` (published once through BuildService and signed v2/v3-only
  by a separate publisher key, so the H.3 output is re-signed as for any real app) and the
  CLI plan → validate → apply flow.
- `build-tests/run_phase_h3_validation.py all --write` — synthetic scenarios plus an
  `--apply` attempt for every H.2 class target of the 9-APK corpus; evidence in
  `artifacts/phase-h/` (see `H3-CONTROLLED-TRANSFORMATION.md`).

# Phase H.4 — Transformation Verification Hardening

H.4 establishes exactly what APKForge can prove about an H-TRANS-001 output, what it
cannot, how the toolchain noise floor is measured and how unexpected changes are detected.
It adds no transformation: H-TRANS-001 stays the only applicable one and H-TRANS-002 stays
planning-only (an H-TRANS-002 plan is `UNVERIFIED`).

## Three APKs, three legs

```text
A original ─── unmodified rebuild ──► B control       A -> B  toolchain / build noise
     └──────── H.3 transformation ──► C transformed   A -> C  complete observed change
                                                      B -> C  transformation signal
```

`ControlExperiment(service).run(apk, plan, work_dir)` produces B (`run_semantic_noop`, kept)
and C (H.3 with B as its noise floor) and verifies them;
`TransformationVerifier(service).verify(A, B, C, plan)` verifies any three APKs; the CLI is
`apkforge verify A C --plan PLAN.json --control B --built-locally` or `--build-control`.
H.3 remains responsible for applying, building, signing and its own post-transform checks;
H.4 is the hardened verification layer and shares H.3's functions (plan loading and id,
declared-change derivation, H.1 post-analysis) rather than re-implementing them. H.3 does
not call H.4: H.3 publishes only after its own checks, and H.4 needs a kept control APK,
which H.3's internal noise measurement discards (documented boundary, no duplicated logic).

APK bytes are compared but never used as evidence of change: independent rebuilds differ in
ZIP metadata (recorded per leg as `metadata_only_changes` and `entry_order_changed`), while
their entry contents are identical with one toolchain and key.

## Classification

Each A -> C difference is classified by Phase E against the noise fingerprint *measured* by
A -> B (content policy: exact content, signer, or path-only for v1 signature files), then
cross-checked:

| H.4 class | Condition |
|---|---|
| `NOISE` | Phase E `REBUILD_NOISE` and the control shows the same difference with the same content (v1 signature files: same path and kind), and B and C agree on it |
| `EXPECTED_TRANSFORMATION` | declared (Phase E `EXPECTED_MODIFICATION` / `PLANNED_ENTRY`) *and* present in the B -> C signal |
| `UNEXPECTED_CHANGE` | Phase E `UNEXPECTED`: not declared, not reproduced by the control |
| `UNKNOWN` | Phase E `UNKNOWN`, or the legs disagree (declared but not in the signal; noise the control does not reproduce; B and C differ where C equals A) |

Every difference records the leg, `in_control` (`same_content`, `different_content`,
`absent`), `in_signal`, the Phase E rule and the reason. An unexplained difference never
becomes `NOISE`; there is no ignore list. A change every rebuild makes (a faulty toolchain)
is not noise either: `classify_noop_diff` marks it unexpected, the control is
`NOT_EQUIVALENT` and the verification is `UNVERIFIED`.

The declared changes are re-derived from A and the plan with the H.3 functions (decode A,
class census, string-pool and API-reference attribution): the class, every DEX string and
framework API reference only the target contributes, and the planned `classesN.dex` entry.

## Invariants (H-TRANS-001)

`plan_integrity`, `control_rebuild_equivalent`, `target_defined_before` (A and B),
`target_absent_after` (C's DEX inventory and the H.1 re-analysis),
`exactly_one_class_removed` and `no_other_class_changed` on A -> C *and* B -> C,
`class_count` (−1), `h1_reference_state` (no structural or indirect reference, DEX
COMPLETE, nothing weakened), `declared_changes_observed` (both legs), `no_unexpected_change`,
`no_unclassified_difference`, `signature_verified` (apksigner, signer of B),
`original_unchanged`.

## Domains and completeness

| Domain | Phase E comparators | Extra | Level |
|---|---|---|---|
| dex | dex, strings | H.1 re-analysis | classes, methods (code hash), fields, string pool, API refs |
| manifest | identity, manifest, manifest_tree, permissions, components, intent_filters | | decoded tree |
| resources | resources, resource_table | | content hash (binary XML / arsc not decoded) |
| assets | assets | | content hash |
| native | native | | content hash + ELF metadata; code not analysed |
| archive | files, embedded | | path + content hash; ZIP metadata recorded as packaging |
| signing | certificate | apksigner verify of C | certificate identity with B |
| endpoints | network | | extracted URLs / hosts |

A domain's completeness is the weakest over its comparators on all three legs: complete →
`COMPLETE`; `partial` / `not_comparable` → `PARTIAL`; `undetermined` / missing → `UNKNOWN`;
leg not run → `NOT_ANALYZED`. DEX additionally needs a sufficient H.1 re-analysis, signing a
conclusive apksigner result. A re-encoded `resources.arsc` stays `PARTIAL` even when it is
byte-identical to the control's (H.4 is stricter than the Phase E matrix here: byte identity
with B is established, semantic identity with A is not).

## Status

| Status | Meaning |
|---|---|
| `VERIFIED` | every mandatory domain `COMPLETE`, every invariant passed, every difference `NOISE` or `EXPECTED_TRANSFORMATION` |
| `VERIFIED_WITH_LIMITATIONS` | as VERIFIED, but a mandatory domain is `PARTIAL`; `limitations` enumerates each one (`[domain] PARTIAL: reason`) |
| `UNVERIFIED` | not performed: invalid / foreign / planning-only plan, missing or invalid control or transformed APK, control not usable as noise floor, declared changes not derivable |
| `FAILED` | an `UNEXPECTED_CHANGE`, a failed invariant, or a changed original |
| `UNKNOWN` | performed, but a mandatory domain is `UNKNOWN` or a difference is unclassified |

Precedence: FAILED > UNVERIFIED > UNKNOWN > VERIFIED_WITH_LIMITATIONS > VERIFIED. There is
no numerical score. CLI exit codes: 0 VERIFIED, 4 VERIFIED_WITH_LIMITATIONS, 1 FAILED,
3 UNKNOWN / UNVERIFIED, 2 usage or toolchain error.

## Result schema

`TransformationVerificationResult` (`schema_version` 1, `phase` "H.4"): plan and target,
original SHA-256 before/after, `control_rebuild` / `transformed_rebuild` (SHA-256, entry-
content SHA-256, no-op result, baseline status, signature), `legs` (per-leg Phase E counts,
raw archive counts, packaging metadata), `noise_floor`, `declared_changes`,
`expected_changes` / `noise_changes` / `unexpected_changes` / `unknown_changes`, `domains`,
`invariants`, `post_analysis` (H.3 `PostAnalysis`), `completeness`, `status`,
`limitations`, `statement`. `comparable()` drops paths, rebuild archive bytes, ZIP metadata
and timings: two runs of the same plan give equal `comparable()` results.

## Verification (H.4)

- `tests/unit/test_phase_h4_verification.py` — attribution, completeness, status precedence,
  plan handling and CLI usage with simulated legs.
- `tests/integration/test_phase_h4_verification.py` — cases 1–8 on real APKs: clean,
  repeated, natural build noise, the H.3 faulty mutation, faults injected into the
  transformed build only (class, resource, manifest, native, asset), native modification
  without a plan, incomplete analysis, re-encoded resource table, CLI.
- `build-tests/run_phase_h4_validation.py all --write` — synthetic cases plus the corpus
  (H.2 eligibility and the noise-floor experiment per APK); evidence in
  `artifacts/phase-h/H4-TRANSFORMATION-VERIFICATION.md`.

---

# Phase H.6 — Controlled Call-Site Replacement (H-TRANS-003)

H.6 is the first transformation that edits live code instead of deleting a definition.
It rewrites the **method reference of exactly one invocation** and nothing else.

> **The contract.** One `invoke-static`, or one `invoke-direct` of a private instance
> method, is redirected to a predetermined replacement method declared in the same APK
> with the *identical* descriptor (and, for `invoke-direct`, in the same class, private and
> non-static). Opcode, operand registers and the consuming `move-result` are unchanged.
> There is no other edit operation: no instruction insertion, register rewriting,
> control-flow change, hook or generic smali patch.

A VERIFIED result means that this one static rewrite was performed and passed the
defined checks. It does not mean that behaviour or functionality is preserved, that the
replacement is semantically equivalent, or that the application is safer.

## Using it

```bash
# 1. plan (H.2): CALLER@INVOKED[#N] plus the replacement
apkforge transform app.apk -t H-TRANS-003 \
    --target 'com.x.A->run()Ljava/lang/String;@com.x.Source->getValue()Ljava/lang/String;' \
    --replacement 'com.x.Replacement->getValue()Ljava/lang/String;' --report plan.json
# 2. validate, then apply (explicit; no implicit plan+apply, no override flag)
apkforge transform app.apk --plan plan.json
apkforge transform app.apk --plan plan.json --apply -o out.apk
# 3. optional H.4 three-APK verification
apkforge verify app.apk out.apk --plan plan.json --build-control
```

`#N` selects the N-th invocation of INVOKED inside CALLER in source order; it is required
when CALLER invokes it more than once. `--replacement` is given once for all H-TRANS-003
targets or once per `--target`, and only with H-TRANS-003. The replacement is stored as
the plan parameter `replacement` (normalised to `com.x.R->name(proto)`), so it is part of
the plan id.

## Eligibility

| Requirement | Reason codes (state) |
|---|---|
| call site resolves to one invocation | `TARGET_NOT_FOUND` (caller), `CALL_SITE_NOT_FOUND`, `CALL_SITE_AMBIGUOUS`, `CALL_SITE_MULTIPLE_MATCHES`, `CALL_SITE_ALREADY_REPLACED` (REFUSED) |
| DEX and the caller's own file COMPLETE, registers recorded | `DEX_ANALYSIS_INCOMPLETE`, `CALLER_ANALYSIS_INCOMPLETE` (UNDETERMINED) |
| caller is not compiler-generated (bridge / synthetic) | `SYNTHETIC_METHOD` (UNSUPPORTED) |
| supported opcode | `POLYMORPHIC_INVOCATION` (virtual/super/interface), `CONSTRUCTOR_INVOCATION`, `INVOKE_POLYMORPHIC_UNSUPPORTED`, `INVOKE_CUSTOM_UNSUPPORTED`, `UNSUPPORTED_INVOKE_OPCODE` (UNSUPPORTED) |
| invoked method declared in the APK, flags match the opcode | `TARGET_METHOD_NOT_FOUND` (REFUSED), `TARGET_RELATIONSHIP_UNRESOLVED`, `TARGET_DEFINITION_INCOMPLETE` (UNDETERMINED) |
| replacement exists, ordinary concrete method | `PARAMETER_INVALID`, `REPLACEMENT_METHOD_NOT_FOUND`, `TARGET_AMBIGUOUS` (REFUSED); `ABSTRACT_METHOD`, `INTERFACE_METHOD`, `NATIVE_METHOD`, `SYNTHETIC_METHOD` (UNSUPPORTED) |
| replacement differs from the invoked method | `CALL_SITE_ALREADY_REPLACED` (REFUSED) |
| same invocation kind / receiver class | `REPLACEMENT_SIGNATURE_MISMATCH` (REFUSED) |
| identical parameter types; operand registers consistent with them (count, receiver, wide pairs) | `REGISTER_TYPE_MISMATCH` (REFUSED) |
| identical return type; `move-result*` consistent with it | `RESULT_TYPE_MISMATCH` (REFUSED) |
| replacement accessible from the caller | `REPLACEMENT_INACCESSIBLE` (REFUSED) |
| no reflection / dynamic loading / unanalysed native code | `REFLECTION_TARGET_PRESENT` (REFUSED); `REFLECTION_TARGET_UNKNOWN`, `REFLECTION_ANALYSIS_INCOMPLETE`, `DYNAMIC_CODE_LOADING_PRESENT`, `NATIVE_DEPENDENCY_UNKNOWN` (UNDETERMINED) |
| no overlapping request | `CONFLICTING_TRANSFORMATION` (REFUSED): another call site in the same caller method, or a class / method removal of the caller, invoked or replacement |

Existing codes are reused where the concept already existed: the requested
`NATIVE_ANALYSIS_INCOMPLETE` is `NATIVE_DEPENDENCY_UNKNOWN`, `REFLECTION_ANALYSIS_INCOMPLETE`
and `ANALYSIS_INCOMPLETE` keep their H.2 meaning. Compatibility is never inferred from a
method name; subtyping is not considered (only identical types are compatible).

## Plan

`planned_changes` holds one `replace_call_site` change (artifact: the caller's smali file)
whose `details` carry everything needed to apply and check it without rescanning the APK:
`dex`, `caller_class`, `caller_method`, `source_line`, `evidence_id` (the H.1 record),
`opcode`, `registers`, `register_count`, `result_instruction`, `result_register`,
`original` and `replacement` (smali references), `occurrence`, `occurrences_in_caller`,
`invocations_in_caller` and `expected_mutation_count` (`1`). The plan id is the usual
hash of APK SHA-256, transformation id, normalised target, parameters (the normalised
replacement) and schema versions.

## Application

The executor (shared with H.3/H.5, dispatching on the plan's target kind) loads the plan,
checks the source SHA-256, the recomputed plan id, eligibility, re-runs H.1 + H.2 and
requires an identical plan. It then declares the expected Phase E changes from the
original APK — the caller class `modified` with exactly the caller method's code changed,
plus the framework-API-reference and string-pool consequences of swapping one reference
(predicted per instruction from the original DEX, exactly as Phase E extracts them) —
and runs the Phase D pipeline with `ReplaceCallSiteModifier`:

- `plan`: the caller is defined once, where planned; the invocation at the planned line
  re-parsed with the H.1 parser has the planned opcode, registers, result and occurrence;
  the line has the single-reference form.
- `apply`: rewrites that one line, then proves before any build that exactly that line
  changed, exactly one invocation record changed (original -> replacement, same opcode,
  registers and result), no other evidence of the file changed, no other smali file
  changed and the class census is unchanged; otherwise `UNEXPECTED_MUTATION` (FAILED,
  nothing built or published). The `MutationRecord` (`REPLACE_CALL_SITE`) records the
  line, the instruction before/after, changed lines and the invocation diff.
- after the build: Phase E must show exactly the declared changes; the H.1 re-analysis of
  the output (`CallSitePostAnalysis`) must show the caller's invocation sequence changed at
  exactly the planned position, no other reference in the APK changed and no declaration
  changed. Only then is the output published (atomically).

The 15-row verification matrix adds *Original invocation before/after*, *Replacement
invocation after* and *Call sites changed* to the H.3 rows.

## H.4 verification

`TransformationVerifier` accepts H-TRANS-003 plans with the same A / B / C experiment. It
re-derives the declared changes from the original APK, and adds the invariants
`caller_class_retained`, `exactly_one_method_body_changed[leg]` and `no_other_change[leg]`
(no declaration, other class or DEX file change on either transformation leg) and
`h1_call_site_state` (from `CallSitePostAnalysis`). Everything else — noise floor from the
control rebuild, cross-leg attribution, domains, completeness, status — is H.4 unchanged.

## Determinism and reproducibility

The same APK, target, replacement and schema produce the same plan (byte-identical JSON)
and plan id. Two applications of one plan produce identical mutation records, identical
post-analyses, identical `comparable()` results and identical APK *entry contents*
(`output_content_sha256`). Outer APK bytes may differ between runs (ZIP metadata /
signing); that is packaging, not content, and is not required to match.

## Limitations

- Type-level compatibility only; no semantic equivalence or behaviour preservation claim.
- Only `invoke-static` and `invoke-direct` of private instance methods; both methods must be
  declared in the APK. Framework/library targets and replacements are not resolved.
- Requires COMPLETE DEX analysis, no unresolved reflection, no dynamic code loading and no
  unanalysed native code — real apps typically fail one of these (see the corpus results).
- The post-analysis compares the original's and the output's decoded smali; an APK whose
  decode is not a rebuild fixed point would fail verification (conservatively).

## Verification (H.6)

- `tests/unit/test_phase_h6_call_site.py` — schema 3, target parsing, every decision class,
  tampered register/result evidence, conflicts, the single-line rewrite and mutation
  comparison, plan loading, integrity, CLI usage, reports.
- `tests/integration/test_phase_h6_call_site_transformation.py` — real APKs: four positive
  shapes (H.6 VERIFIED, H.4 VERIFIED/COMPLETE), refusals, an already transformed APK, a
  conflicting set, mutation faults, build-time faults, integrity, reproducibility, CLI.
- `build-tests/run_phase_h6_validation.py all --write` — synthetic matrix plus the read-only
  corpus run; evidence in `artifacts/phase-h/H6-CONTROLLED-CALL-SITE-TRANSFORMATION.md`.
