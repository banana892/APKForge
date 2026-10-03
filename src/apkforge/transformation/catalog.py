"""Phase H.2 transformation catalog (planning definitions only, no executors)."""

from __future__ import annotations

from apkforge.modification.models import ModificationRisk, Reversibility
from apkforge.transformation.models import TargetKind, TransformationSpec

__all__ = ["CATALOG", "H_TRANS_001", "H_TRANS_002", "get_spec", "list_specs"]

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

CATALOG: dict[str, TransformationSpec] = {s.id: s for s in (H_TRANS_001, H_TRANS_002)}


def get_spec(transformation_id: str) -> TransformationSpec | None:
    return CATALOG.get(transformation_id.strip().upper())


def list_specs() -> list[TransformationSpec]:
    return [CATALOG[k] for k in sorted(CATALOG)]
