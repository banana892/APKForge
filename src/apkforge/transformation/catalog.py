"""Phase H.2 transformation catalog (planning definitions only, no executors)."""

from __future__ import annotations

from apkforge.modification.models import ModificationRisk, Reversibility
from apkforge.transformation.models import TargetKind, TransformationSpec

__all__ = ["CATALOG", "H_TRANS_001", "H_TRANS_002", "H_TRANS_003", "get_spec", "list_specs"]

_COMMON_VERIFICATION = [
    "input APK SHA-256 unchanged (the transformation writes a new APK only)",
    "transformed APK rebuilds, aligns and signs with the existing BuildService",
    "H.1 re-analysis of the transformed APK reaches at least the same component states",
    "Phase E diff of original vs transformed shows only the planned DEX change "
    "(no manifest, resource or native-library differences)",
]
_COMMON_COMPATIBILITY = [
    "the transformed APK is re-signed with a different key and cannot update an install "
    "signed with the original key",
    "evaluated against the original APK only: other requested transformations are not "
    "assumed to have been applied",
]
_COMMON_LIMITATIONS = [
    "Static evidence only (H.1 scope): runtime behaviour, server-driven code paths and "
    "code loaded at runtime are not observed.",
    "Eligibility establishes that the static evidence supports the transformation; it "
    "does not establish that the target is malicious, unnecessary or safe to remove at "
    "runtime.",
]

H_TRANS_001 = TransformationSpec(
    id="H-TRANS-001",
    name="Remove isolated class",
    description=(
        "Remove one class definition that no other code, manifest entry, resource, "
        "reflection call or native boundary is observed to reference."
    ),
    category="dex_class_removal",
    target_type=TargetKind.CLASS,
    required_evidence=[
        "class definition (H.1 defined_classes)",
        "class / type / method / field / constructor / const-class references",
        "string mentions of the class name",
        "reflection and dynamic-code-loading indicators",
        "native methods, library loads and native_code state",
        "manifest references",
        "resource and asset references",
        "component analysis states (dex, reflection, native, manifest, resources, assets)",
    ],
    preconditions=[
        "class_exists",
        "dex_analysis_complete",
        "no_callers",
        "no_type_references",
        "no_member_references",
        "no_constructor_references",
        "no_const_class_references",
        "no_string_references",
        "no_reflection_target",
        "no_dynamic_code_loading",
        "no_native_dependency",
        "no_manifest_reference",
        "no_resource_reference",
        "no_conflicting_transformation",
    ],
    eligibility_rules=[
        "class not defined (or defined more than once / not fully qualified) -> REFUSED",
        "dex analysis not COMPLETE -> UNDETERMINED (DEX_ANALYSIS_INCOMPLETE)",
        "any structural code reference from another class -> REFUSED",
        "manifest component (activity, activity-alias, service, receiver, provider) "
        "names the class -> REFUSED (MANIFEST_COMPONENT_REFERENCE)",
        "structural resource/asset reference -> REFUSED; textual match or incomplete "
        "resource analysis -> UNDETERMINED",
        "reflection resolved to the class -> REFUSED; unresolved reflection -> UNDETERMINED",
        "class declares native methods -> UNSUPPORTED; native code present but not "
        "analysed -> UNDETERMINED (NATIVE_DEPENDENCY_UNKNOWN)",
        "dynamic code loading present -> UNDETERMINED",
        "string naming the class -> UNDETERMINED (indirect, never a direct reference)",
        "overlapping request in the same set -> REFUSED (CONFLICTING_TRANSFORMATION)",
    ],
    planned_changes=["remove_class: delete the class definition from its DEX"],
    verification_requirements=[
        "the class is no longer defined in the transformed APK",
        "no remaining code reference to the class (H.1 query on the transformed APK)",
        "every other class definition is unchanged",
        *_COMMON_VERIFICATION,
    ],
    risk=ModificationRisk.HIGH,
    reversibility=Reversibility.REVERSIBLE,
    compatibility_constraints=[
        "DEX layout (class order, string/type pools) changes in the affected DEX",
        *_COMMON_COMPATIBILITY,
    ],
    limitations=[
        "Classes are evaluated one at a time: a group of classes that only reference each "
        "other is refused (each is referenced by another member of the group).",
        "Nested/inner classes referencing the target count as references.",
        *_COMMON_LIMITATIONS,
    ],
)

H_TRANS_002 = TransformationSpec(
    id="H-TRANS-002",
    name="Remove isolated method",
    description=(
        "Remove one ordinary concrete method that no call site, override relationship, "
        "reflection call, annotation-driven framework or native boundary is observed to "
        "reach."
    ),
    category="dex_method_removal",
    target_type=TargetKind.METHOD,
    required_evidence=[
        "method declaration with access flags (H.1 defined_classes[].methods)",
        "class hierarchy of defined classes (superclass, interfaces, subclasses)",
        "method references to the class and its defined subclasses",
        "reflection indicators naming the method or enumerating the class's methods",
        "native methods, library loads and native_code state",
        "component analysis states (dex, reflection, native)",
    ],
    preconditions=[
        "method_exists",
        "dex_analysis_complete",
        "ordinary_method",
        "no_call_sites",
        "no_override_relationship",
        "no_reflection_target",
        "no_dynamic_invocation",
        "no_native_boundary",
        "no_annotation_driven_access",
        "no_resource_method_reference",
        "no_string_references",
        "metadata_consistency",
        "no_conflicting_transformation",
    ],
    eligibility_rules=[
        "method not declared (or overloads without a signature) -> REFUSED",
        "constructor, class initializer, abstract, interface, native, bridge/synthetic, "
        "enum values()/valueOf(), serialization hooks -> UNSUPPORTED",
        "call site to the class or a defined subclass -> REFUSED (METHOD_CALLER_PRESENT)",
        "overrides / is overridden within defined classes -> UNSUPPORTED; supertype not "
        "defined in the APK for a virtual method -> UNDETERMINED",
        "reflection resolved to the method (or enumerating the class's methods) -> "
        "REFUSED; unresolved reflection -> UNDETERMINED",
        "native code present but not analysed -> UNDETERMINED (NATIVE_DEPENDENCY_UNKNOWN)",
        "runtime annotations on the method -> UNDETERMINED",
        "public (Landroid/view/View;)V method -> UNDETERMINED (android:onClick is not "
        "analysed by H.1)",
        "class carries kotlin.Metadata -> CONDITIONALLY_ELIGIBLE (KOTLIN_METADATA_UPDATE_REQUIRED)",
    ],
    planned_changes=["remove_method: delete the method definition from its class"],
    verification_requirements=[
        "the method is no longer declared in the transformed APK",
        "no remaining invocation of the method (H.1 query on the transformed APK)",
        "every other method of the class is unchanged",
        *_COMMON_VERIFICATION,
    ],
    risk=ModificationRisk.HIGH,
    reversibility=Reversibility.REVERSIBLE,
    compatibility_constraints=[
        "the class's method table changes; code outside this APK cannot call it",
        *_COMMON_COMPATIBILITY,
    ],
    limitations=[
        "Overrides of framework/library methods cannot be resolved without the "
        "supertype definitions; such virtual methods stay UNDETERMINED.",
        "Method names referenced from resources (android:onClick) are not indexed by "
        "H.1; matching handler shapes stay UNDETERMINED.",
        *_COMMON_LIMITATIONS,
    ],
)

H_TRANS_003 = TransformationSpec(
    id="H-TRANS-003",
    name="Controlled call-site replacement",
    description=(
        "Replace the method reference of exactly one direct invocation (invoke-static, or "
        "invoke-direct of a private instance method) with a predetermined replacement "
        "method declared in the APK with the identical descriptor. The opcode, the "
        "operand registers and the consumption of the result are unchanged; no other "
        "instruction is touched."
    ),
    category="dex_call_site_replacement",
    target_type=TargetKind.CALL_SITE,
    required_evidence=[
        "invocation records of the caller method with opcode, operand registers and the "
        "consuming move-result (H.1 schema 3)",
        "declarations and access flags of the caller, invoked and replacement methods and "
        "their classes (H.1 defined_classes)",
        "reflection indicators naming the caller, invoked or replacement method",
        "dynamic-code-loading indicators",
        "native_indicators / native_code state",
        "component analysis states (dex, reflection, native) and the caller file's state",
    ],
    preconditions=[
        "call_site_exists",
        "dex_analysis_complete",
        "caller_analysis_complete",
        "caller_modifiable",
        "supported_invoke_opcode",
        "target_method_resolved",
        "replacement_method_resolved",
        "replacement_differs",
        "invocation_kind_compatible",
        "argument_types_compatible",
        "return_type_compatible",
        "register_mapping_consistent",
        "result_mapping_consistent",
        "replacement_accessible",
        "no_reflection_target",
        "no_dynamic_invocation",
        "no_native_boundary",
        "no_conflicting_transformation",
    ],
    eligibility_rules=[
        "caller class/method not defined -> REFUSED (TARGET_NOT_FOUND); caller method "
        "overloads without a proto -> REFUSED (CALL_SITE_AMBIGUOUS)",
        "no invocation of the invoked method in the caller -> REFUSED (CALL_SITE_NOT_FOUND), "
        "or CALL_SITE_ALREADY_REPLACED when the caller already invokes the replacement; "
        "caller file not COMPLETE -> UNDETERMINED (CALLER_ANALYSIS_INCOMPLETE); a "
        "compiler-generated (bridge / synthetic) caller -> UNSUPPORTED (SYNTHETIC_METHOD)",
        "several invocations and no #N -> REFUSED (CALL_SITE_MULTIPLE_MATCHES); invoked "
        "method without a proto matching several overloads -> REFUSED (CALL_SITE_AMBIGUOUS)",
        "invoke-virtual / -super / -interface -> UNSUPPORTED (POLYMORPHIC_INVOCATION); "
        "constructor -> UNSUPPORTED (CONSTRUCTOR_INVOCATION); invoke-polymorphic / "
        "invoke-custom -> UNSUPPORTED",
        "invoked method's class not defined in the APK -> REFUSED (TARGET_METHOD_NOT_FOUND); "
        "defined but the method not declared by it, or its flags disagree with the opcode "
        "-> UNDETERMINED (TARGET_RELATIONSHIP_UNRESOLVED)",
        "replacement missing / malformed -> REFUSED (REPLACEMENT_METHOD_NOT_FOUND, "
        "PARAMETER_INVALID); constructor, abstract, interface, native, synthetic "
        "replacement -> REFUSED / UNSUPPORTED",
        "static-ness / receiver class differ -> REFUSED (REPLACEMENT_SIGNATURE_MISMATCH); "
        "parameter types differ -> REFUSED (REGISTER_TYPE_MISMATCH); return type differs "
        "-> REFUSED (RESULT_TYPE_MISMATCH)",
        "operand registers inconsistent with the descriptor, or the move-result opcode "
        "inconsistent with the return type -> REFUSED (REGISTER_TYPE_MISMATCH / "
        "RESULT_TYPE_MISMATCH)",
        "replacement not accessible from the caller -> REFUSED (REPLACEMENT_INACCESSIBLE)",
        "reflection resolved to the caller / invoked / replacement method -> REFUSED; "
        "unresolved reflection or dynamic code loading -> UNDETERMINED",
        "native code present but not analysed -> UNDETERMINED (NATIVE_DEPENDENCY_UNKNOWN)",
        "overlapping request in the same set (same caller method, or a class/method removal "
        "of the caller, invoked or replacement) -> REFUSED (CONFLICTING_TRANSFORMATION)",
    ],
    planned_changes=[
        "replace_call_site: rewrite the method reference of one invocation in the caller's "
        "smali (opcode, registers and result handling unchanged)"
    ],
    verification_requirements=[
        "the original invocation is gone from the planned location and the replacement "
        "invocation is there, with the same opcode, registers and result handling",
        "every other invocation and reference of the APK is unchanged (H.1 re-analysis)",
        "every class and method declaration is unchanged; only the caller method's code "
        "differs (Phase E DEX diff)",
        *_COMMON_VERIFICATION,
    ],
    risk=ModificationRisk.HIGH,
    reversibility=Reversibility.REVERSIBLE,
    compatibility_constraints=[
        "the caller method's code changes; behaviour at that call site becomes the "
        "replacement method's behaviour",
        *_COMMON_COMPATIBILITY,
    ],
    limitations=[
        "Compatibility is the identical descriptor and invocation kind only: the replacement "
        "is not shown to be semantically equivalent to the original method, and no claim is "
        "made that behaviour or functionality is preserved.",
        "Only invoke-static and invoke-direct of private instance methods are supported; "
        "virtual, interface, super, constructor, polymorphic and custom invocations are not.",
        "Both the invoked and the replacement method must be declared in the APK; framework "
        "and library methods are not resolved.",
        *_COMMON_LIMITATIONS,
    ],
)

CATALOG: dict[str, TransformationSpec] = {s.id: s for s in (H_TRANS_001, H_TRANS_002, H_TRANS_003)}


def get_spec(transformation_id: str) -> TransformationSpec | None:
    return CATALOG.get(transformation_id.strip().upper())


def list_specs() -> list[TransformationSpec]:
    return [CATALOG[k] for k in sorted(CATALOG)]
