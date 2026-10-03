"""Phase G modifiers implementing the APKModifier contract.

Provides:
- RemovePermissionModifier: removes an exact <uses-permission> element.
- DisableComponentModifier: sets android:enabled="false" on an activity,
  service, receiver, or provider.
- remediation_modifier_catalog(): returns a ModifierCatalog containing the
  remediation modifiers alongside Phase D builtin modifiers.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, ClassVar
from xml.sax.saxutils import escape

from apkforge.diff.expectations import ExpectedChange
from apkforge.modification.builtin.boot_receiver import BootReceiverModifier
from apkforge.modification.builtin.marker_asset import MarkerAssetModifier
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.contract import (
    MANIFEST,
    APKModifier,
    ApplyOutcome,
    FileAction,
    ModifierPlan,
    PlannedFileChange,
    PlanReadiness,
    PlanTarget,
    Precondition,
    ProjectContext,
    TargetAccess,
    VerificationEvidence,
    VerificationOutcome,
)
from apkforge.modification.edits import SourceEdit, manifest_edits, same_edits
from apkforge.modification.models import ModificationRisk

__all__ = [
    "DisableComponentModifier",
    "RemovePermissionModifier",
    "remediation_modifier_catalog",
]

_A = "{http://schemas.android.com/apk/res/android}"
REMOVE_PERMISSION_MODIFIER_ID = "remediation.remove_permission"
DISABLE_COMPONENT_MODIFIER_ID = "remediation.disable_component"


def _fqcn(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


class RemovePermissionModifier(APKModifier):
    """Removes an exact <uses-permission> element from AndroidManifest.xml."""

    id: ClassVar[str] = REMOVE_PERMISSION_MODIFIER_ID
    name: ClassVar[str] = "Remove permission declaration"
    description: ClassVar[str] = (
        "Removes a specific <uses-permission> declaration from AndroidManifest.xml. Manifest only."
    )
    version: ClassVar[str] = "1"
    risk: ClassVar[ModificationRisk] = ModificationRisk.MEDIUM
    supported_conditions: ClassVar[list[str]] = [
        "target permission is declared in AndroidManifest.xml",
    ]
    prerequisites: ClassVar[list[str]] = ["Apktool-decoded AndroidManifest.xml"]
    parameters: ClassVar[dict[str, str]] = {
        "permission": "Permission name to remove (e.g. android.permission.INTERNET)",
    }

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        root = ET.fromstring(project.manifest_text())  # noqa: S314
        decls = [
            el.get(f"{_A}name")
            for el in root
            if el.tag in ("uses-permission", "uses-permission-sdk-23") and el.get(f"{_A}name")
        ]
        return {"declared_permissions": [p for p in decls if p is not None]}

    def plan(
        self,
        project: ProjectContext,
        findings: dict[str, Any],
        parameters: dict[str, str],
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        permission = parameters.get("permission", "").strip()

        if not permission:
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "missing_parameter"
            plan.problems.append("Parameter 'permission' is required.")
            return plan

        declared = findings.get("declared_permissions", [])
        has_perm = permission in declared

        plan.preconditions = [
            Precondition(
                name="permission_declared",
                satisfied=has_perm,
                expected=f"<uses-permission> for {permission}",
                actual="declared" if has_perm else "not declared in manifest",
            )
        ]

        if not has_perm:
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "target_missing"
            plan.problems.append(
                f"Permission '{permission}' is not declared in AndroidManifest.xml."
            )
            return plan

        plan.targets = [
            PlanTarget(
                kind="permission",
                identifier=permission,
                access=TargetAccess.REMOVE,
                description=f"remove uses-permission {permission}",
            )
        ]
        plan.changes = [f"remove <uses-permission android:name={permission}>"]
        plan.file_changes = [PlannedFileChange(path=MANIFEST, action=FileAction.MODIFY)]
        plan.manifest_edits = [
            SourceEdit(
                kind="remove_element",
                element=f"manifest/uses-permission[name={permission}]",
            )
        ]
        plan.expected_changes = [
            ExpectedChange(
                category="uses_permission",
                kind="removed",
                identifier=permission,
                description=f"{permission} removed",
            )
        ]
        plan.verification = [f"re-analysis confirms {permission} absent from rebuilt manifest"]
        plan.details = {"permission": permission}
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        permission = plan.details.get("permission", plan.parameters.get("permission", ""))
        original_xml = project.manifest_text()

        # Regex targeting uses-permission or uses-permission-sdk-23 tag
        pattern = re.compile(
            r"^[ \t]*<uses-permission(?:-sdk-23)?\b[^>]*?\sandroid:name=\""
            + re.escape(escape(permission, {'"': "&quot;"}))
            + r"\"[^>]*?/>[ \t]*\r?\n?",
            re.M,
        )

        modified_xml, count = pattern.subn("", original_xml)
        if count == 0:
            return ApplyOutcome(
                applied=False,
                errors=[f"Could not find <uses-permission> line matching '{permission}'."],
            )

        observed = manifest_edits(original_xml, modified_xml)
        matches = same_edits(observed, plan.manifest_edits)
        if not matches:
            return ApplyOutcome(
                applied=False,
                errors=[
                    f"Observed manifest edits ({observed}) do not match "
                    f"planned ({plan.manifest_edits})."
                ],
            )

        project.manifest_path.write_text(modified_xml, encoding="utf-8")
        return ApplyOutcome(
            applied=True,
            message=f"Removed <uses-permission android:name='{permission}'>",
            details={"removed_permission": permission, "count": count},
        )

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        permission = plan.details.get("permission", plan.parameters.get("permission", ""))
        diff = evidence.diff
        removed = permission in diff.permissions.removed
        return VerificationOutcome.from_checks(
            [
                Precondition(
                    name="permission_removed",
                    satisfied=removed,
                    expected=f"{permission} absent from rebuilt APK",
                    actual="absent" if removed else "still requested (or never was)",
                )
            ]
        )


class DisableComponentModifier(APKModifier):
    """Sets android:enabled='false' on an activity, service, receiver, or provider."""

    id: ClassVar[str] = DISABLE_COMPONENT_MODIFIER_ID
    name: ClassVar[str] = "Disable manifest component"
    description: ClassVar[str] = (
        "Sets android:enabled='false' on a specified manifest component "
        "(activity, service, receiver, or provider). Manifest only."
    )
    version: ClassVar[str] = "1"
    risk: ClassVar[ModificationRisk] = ModificationRisk.MEDIUM
    supported_conditions: ClassVar[list[str]] = [
        "target component is declared in AndroidManifest.xml",
        "target component is currently enabled (android:enabled is true or absent)",
    ]
    prerequisites: ClassVar[list[str]] = ["Apktool-decoded AndroidManifest.xml"]
    parameters: ClassVar[dict[str, str]] = {
        "component": "Component name (raw or fully qualified) to disable.",
        "component_type": "Optional component type: activity | service | receiver | provider.",
    }

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        root = ET.fromstring(project.manifest_text())  # noqa: S314
        pkg = root.get("package", "")
        app = root.find("application")
        components: list[dict[str, Any]] = []

        if app is not None:
            for tag in ("activity", "service", "receiver", "provider"):
                for el in app.findall(tag):
                    raw_name = el.get(f"{_A}name", "")
                    fqcn = _fqcn(raw_name, pkg)
                    enabled_val = el.get(f"{_A}enabled")
                    components.append(
                        {
                            "type": tag,
                            "raw_name": raw_name,
                            "fqcn": fqcn,
                            "enabled_raw": enabled_val,
                        }
                    )

        return {"package": pkg, "components": components}

    def plan(
        self,
        project: ProjectContext,
        findings: dict[str, Any],
        parameters: dict[str, str],
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        target_name = parameters.get("component", "").strip()
        comp_type_hint = parameters.get("component_type", "").strip().lower()

        if not target_name:
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "missing_parameter"
            plan.problems.append("Parameter 'component' is required.")
            return plan

        components = findings.get("components", [])
        matched = [
            c
            for c in components
            if (c["fqcn"] == target_name or c["raw_name"] == target_name)
            and (not comp_type_hint or c["type"] == comp_type_hint)
        ]

        if not matched:
            plan.preconditions = [
                Precondition(
                    name="component_exists",
                    satisfied=False,
                    expected=f"component '{target_name}' in manifest",
                    actual="not found",
                )
            ]
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "target_missing"
            plan.problems.append(f"Component '{target_name}' not found in manifest.")
            return plan

        if len(matched) > 1:
            plan.preconditions = [
                Precondition(
                    name="component_unique",
                    satisfied=False,
                    expected="exactly one matching component",
                    actual=f"found {len(matched)} matches",
                )
            ]
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "ambiguous_target"
            plan.problems.append(
                f"Multiple components match '{target_name}'; specify 'component_type'."
            )
            return plan

        target = matched[0]
        state = target["enabled_raw"]
        is_enabled = state in ("true", None)

        plan.preconditions = [
            Precondition(
                name="component_exists",
                satisfied=True,
                expected=f"component '{target_name}' in manifest",
                actual=f"found {target['type']} {target['fqcn']}",
            ),
            Precondition(
                name="component_currently_enabled",
                satisfied=is_enabled,
                expected="android:enabled is true or absent",
                actual=f"android:enabled={state!r}",
            ),
        ]

        if not is_enabled:
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = "unsupported"
            plan.problems.append(f"Component '{target['fqcn']}' is already disabled.")
            return plan

        tag = target["type"]
        raw = target["raw_name"]
        fqcn = target["fqcn"]

        plan.targets = [
            PlanTarget(
                kind="component",
                identifier=fqcn,
                access=TargetAccess.MODIFY,
                description="android:enabled -> false",
            )
        ]
        plan.changes = [f'set android:enabled="false" on <{tag} {fqcn}>']
        plan.file_changes = [PlannedFileChange(path=MANIFEST, action=FileAction.MODIFY)]
        plan.manifest_edits = [
            SourceEdit(
                kind="set_attribute",
                element=f"manifest/application[0]/{tag}[name={raw}]",
                attribute="android:enabled",
                before=state,
                after="false",
            )
        ]

        before_bool = True if state == "true" else None
        plan.expected_changes = [
            ExpectedChange(
                category="component",
                kind="modified",
                identifier=fqcn,
                detail={"component_type": tag, "enabled": [before_bool, False]},
                description=f"{fqcn} disabled (enabled -> false)",
            )
        ]
        plan.verification = [f"re-analysis reports {fqcn} with enabled=false"]
        plan.details = {"target": target}
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        target = plan.details.get("target")
        if not target:
            return ApplyOutcome(applied=False, errors=["Missing target in plan details."])

        tag = target["type"]
        raw = target["raw_name"]
        original_xml = project.manifest_text()

        # Find the start tag of the component
        start = re.compile(
            rf"<{tag}\b[^>]*?\sandroid:name=\""
            + re.escape(escape(raw, {'"': "&quot;"}))
            + r"\"[^>]*>"
        )
        matches = list(start.finditer(original_xml))
        if len(matches) != 1:
            return ApplyOutcome(
                applied=False,
                errors=[f"Expected exactly 1 <{tag}> start tag for '{raw}', found {len(matches)}"],
            )

        m = matches[0]
        tag_str = m.group(0)
        if re.search(r"\sandroid:enabled=\"[^\"]*\"", tag_str):
            new_tag = re.sub(r"(\sandroid:enabled=)\"[^\"]*\"", r'\1"false"', tag_str, count=1)
        else:
            new_tag = tag_str.replace(f"<{tag}", f'<{tag} android:enabled="false"', 1)

        modified_xml = original_xml[: m.start()] + new_tag + original_xml[m.end() :]
        observed = manifest_edits(original_xml, modified_xml)

        if not same_edits(observed, plan.manifest_edits):
            return ApplyOutcome(
                applied=False,
                errors=[
                    f"Observed manifest edits ({observed}) do not match "
                    f"planned ({plan.manifest_edits})."
                ],
            )

        project.manifest_path.write_text(modified_xml, encoding="utf-8")
        return ApplyOutcome(
            applied=True,
            message=f"Disabled component <{tag} name='{raw}'> (android:enabled='false')",
            details={"disabled_component": target["fqcn"]},
        )

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        target = plan.details.get("target")
        if not target:
            return VerificationOutcome(passed=False, message="Missing target in plan details.")

        fqcn = target["fqcn"]
        diff = evidence.diff

        # Look in the corresponding component list
        all_comps = (
            diff.components.activities
            + diff.components.services
            + diff.components.receivers
            + diff.components.providers
        )
        change = next((c for c in all_comps if c.name == fqcn), None)
        enabled_after = change.enabled_after if change is not None else "unchanged"

        return VerificationOutcome.from_checks(
            [
                Precondition(
                    name="component_disabled",
                    satisfied=change is not None and change.enabled_after is False,
                    expected=f"{fqcn} enabled=false in rebuilt APK",
                    actual=f"enabled={enabled_after}",
                )
            ]
        )


def remediation_modifier_catalog() -> ModifierCatalog:
    """Returns a ModifierCatalog containing standard modifiers plus Phase G modifiers."""
    return ModifierCatalog(
        [
            BootReceiverModifier(),
            MarkerAssetModifier(),
            RemovePermissionModifier(),
            DisableComponentModifier(),
        ]
    )
