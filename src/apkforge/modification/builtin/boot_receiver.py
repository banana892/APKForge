"""The C.5 boot-receiver modification as a Phase D modifier.

An adapter only: discovery, planning, the manifest edit and its refusal rules are the
unchanged C.5 functions in :mod:`apkforge.modification.boot_receiver`. This class maps
them onto the :class:`~apkforge.modification.contract.APKModifier` contract and adds a
post-build verification of the re-analysed APK.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.modification.boot_receiver import (
    BOOT_ACTIONS,
    BOOT_PERMISSION,
    MODIFIER_ID,
    ApplyResult,
    BootReceiverPlan,
    BootTargetDiscovery,
    apply_plan,
    discover,
    plan_disable_boot_receiver,
)
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
    TargetAccess,
    VerificationOutcome,
)
from apkforge.modification.models import ModificationRisk

if TYPE_CHECKING:
    from apkforge.modification.contract import ProjectContext, VerificationEvidence

__all__ = ["BootReceiverModifier"]

#: Expected state for each C.5 precondition (C.5 records only the observed detail).
_EXPECTED = {
    "permission_declared_once": f"exactly one <uses-permission> for {BOOT_PERMISSION}",
    "boot_receiver_identified": "exactly one boot receiver, or the requested one",
    "receiver_currently_enabled": "android:enabled is true or absent",
}


class BootReceiverModifier(APKModifier):
    id: ClassVar[str] = MODIFIER_ID
    name: ClassVar[str] = "Disable boot receiver"
    description: ClassVar[str] = (
        "Remove the RECEIVE_BOOT_COMPLETED uses-permission and disable the receiver that "
        "handles the boot broadcast (android:enabled=false). Manifest only."
    )
    version: ClassVar[str] = "1"
    risk: ClassVar[ModificationRisk] = ModificationRisk.MEDIUM
    supported_conditions: ClassVar[list[str]] = [
        f"{BOOT_PERMISSION} declared once as <uses-permission>",
        "exactly one <receiver> handles a boot action (or one is named)",
        "that receiver's android:enabled is true or absent",
        f"boot actions: {', '.join(BOOT_ACTIONS)}",
    ]
    prerequisites: ClassVar[list[str]] = ["Apktool-decoded AndroidManifest.xml"]
    parameters: ClassVar[dict[str, str]] = {
        "receiver": "Fully qualified boot receiver to disable; required when several "
        "receivers handle boot actions.",
    }

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        return discover(project.manifest_text()).model_dump(mode="json")

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        native = plan_disable_boot_receiver(
            BootTargetDiscovery.model_validate(findings),
            target_apk=str(project.original_apk),
            target_sha256=project.original_sha256,
            receiver=parameters.get("receiver"),
        )
        plan = self.new_plan(project, parameters)
        plan.preconditions = [
            Precondition(
                name=p.name,
                satisfied=p.satisfied,
                expected=_EXPECTED.get(p.name, ""),
                actual=p.detail,
            )
            for p in native.preconditions
        ]
        plan.consequences = list(native.consequences)
        plan.limitations = list(native.limitations)
        plan.problems = list(native.problems)
        plan.details = {"boot_receiver_plan": native.model_dump(mode="json")}
        if not native.ready or native.receiver is None:
            plan.readiness = PlanReadiness.PRECONDITION_FAILED
            plan.refusal_code = str(native.status)
            return plan

        plan.targets = [
            PlanTarget(kind="permission", identifier=BOOT_PERMISSION, access=TargetAccess.REMOVE),
            PlanTarget(
                kind="component",
                identifier=native.receiver,
                access=TargetAccess.MODIFY,
                description="android:enabled -> false",
            ),
        ]
        plan.changes = [
            f"remove <uses-permission android:name={BOOT_PERMISSION}>",
            f'set android:enabled="false" on <receiver {native.receiver}>',
        ]
        plan.file_changes = [PlannedFileChange(path=MANIFEST, action=FileAction.MODIFY)]
        plan.manifest_edits = list(native.source_edits)
        plan.expected_changes = list(native.expected_changes)
        plan.verification = [
            f"re-analysis of the rebuilt APK no longer lists {BOOT_PERMISSION}",
            f"re-analysis reports {native.receiver} with enabled=false",
        ]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        native = BootReceiverPlan.model_validate(plan.details["boot_receiver_plan"])
        res: ApplyResult = apply_plan(native, project.manifest_path)
        return ApplyOutcome(
            applied=res.applied,
            message="; ".join(plan.changes) if res.applied else "",
            errors=list(res.errors),
            details={"apply_result": res.model_dump(mode="json")},
        )

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        receiver = BootReceiverPlan.model_validate(plan.details["boot_receiver_plan"]).receiver
        diff = evidence.diff
        removed = BOOT_PERMISSION in diff.permissions.removed
        change = next((c for c in diff.components.receivers if c.name == receiver), None)
        enabled_after = change.enabled_after if change is not None else "unchanged"
        return VerificationOutcome.from_checks(
            [
                Precondition(
                    name="permission_removed",
                    satisfied=removed,
                    expected=f"{BOOT_PERMISSION} absent from the rebuilt APK",
                    actual="absent" if removed else "still requested (or never was)",
                ),
                Precondition(
                    name="receiver_disabled",
                    satisfied=change is not None and change.enabled_after is False,
                    expected=f"{receiver} enabled=false in the rebuilt APK",
                    actual=f"enabled={enabled_after}",
                ),
            ]
        )
