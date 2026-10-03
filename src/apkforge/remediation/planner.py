"""Remediation Planner for Phase G.

Constructs deterministic, machine-readable RemediationPlans by analyzing
the target APK, matching findings to candidate remediations, checking
preconditions, and declaring expected diffs and verification requirements.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.privacy.models import EvidenceState, PrivacyFinding, PrivacyResult
from apkforge.privacy.service import PrivacyAnalysisService
from apkforge.remediation.catalog import (
    RemediationCatalog,
    default_remediation_catalog,
)
from apkforge.remediation.mapping import map_finding_to_remediations
from apkforge.remediation.models import (
    PreconditionCheck,
    RemediationPlan,
    RemediationState,
)

if TYPE_CHECKING:
    from apkforge.remediation.mapping import RemediationCandidate

__all__ = ["RemediationPlanner"]

_A = "{http://schemas.android.com/apk/res/android}"


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class RemediationPlanner:
    """Plans controlled remediations for evidence-backed findings."""

    def __init__(self, catalog: RemediationCatalog | None = None) -> None:
        self.catalog = catalog or default_remediation_catalog()

    def plan(
        self,
        apk_path: str | Path,
        finding_id: str,
        *,
        remediation_id: str | None = None,
        parameters: dict[str, str] | None = None,
        pre_analysis: PrivacyResult | None = None,
        finding_override: PrivacyFinding | None = None,
    ) -> RemediationPlan:
        """Create a deterministic remediation plan for a finding."""
        path = Path(apk_path)
        apk_sha256 = sha256_file(path)
        params = dict(parameters or {})

        # Run Phase F analysis if not supplied
        analysis = pre_analysis or PrivacyAnalysisService.analyze(path)

        # Locate target finding
        target_finding: PrivacyFinding | None = finding_override
        if target_finding is None:
            for f in analysis.findings:
                if f.id == finding_id:
                    target_finding = f
                    break

        if target_finding is None:
            return RemediationPlan(
                plan_id=f"plan-missing-{finding_id}",
                source_apk_path=str(path),
                source_apk_sha256=apk_sha256,
                package_name=analysis.package_name,
                finding_id=finding_id,
                finding_category="unknown",
                finding_title=f"Finding '{finding_id}' not found",
                remediation_id=remediation_id or "NONE",
                remediation_name="No Remediation",
                state=RemediationState.SKIPPED,
                preconditions=[
                    PreconditionCheck(
                        name="finding_exists",
                        satisfied=False,
                        expected=f"finding '{finding_id}' observed in APK",
                        actual="not found in static findings",
                        reason=f"Target finding '{finding_id}' is not observed in this APK.",
                    )
                ],
                warnings=[f"Finding '{finding_id}' was not observed in APK."],
                limitations=["Cannot plan remediation for a non-existent finding."],
            )

        # Incomplete or undetermined finding evidence
        ev_state = target_finding.evidence_state
        if ev_state == EvidenceState.UNKNOWN or (
            ev_state == EvidenceState.PARTIAL and not target_finding.evidence_values
        ):
            return RemediationPlan(
                plan_id=f"plan-undetermined-{finding_id}",
                source_apk_path=str(path),
                source_apk_sha256=apk_sha256,
                package_name=analysis.package_name,
                finding_id=finding_id,
                finding_category=target_finding.category,
                finding_title=target_finding.title,
                finding_state=str(target_finding.evidence_state),
                remediation_id=remediation_id or "UNDETERMINED",
                remediation_name="Undetermined Remediation",
                state=RemediationState.UNDETERMINED,
                preconditions=[
                    PreconditionCheck(
                        name="evidence_complete",
                        satisfied=False,
                        expected="complete evidence supporting finding",
                        actual=f"evidence state is {target_finding.evidence_state}",
                        reason="Evidence supporting this finding is incomplete or unknown.",
                    )
                ],
                warnings=[f"Finding evidence is {ev_state}; cannot plan remediation safely."],
                limitations=["Incomplete evidence prevents deterministic planning."],
            )

        # Map finding to eligible candidates
        candidates = map_finding_to_remediations(target_finding, self.catalog)
        if remediation_id:
            candidates = [c for c in candidates if c.remediation.id == remediation_id]

        if not candidates:
            return RemediationPlan(
                plan_id=f"plan-unsupported-{finding_id}",
                source_apk_path=str(path),
                source_apk_sha256=apk_sha256,
                package_name=analysis.package_name,
                finding_id=finding_id,
                finding_category=target_finding.category,
                finding_title=target_finding.title,
                finding_state=str(target_finding.evidence_state),
                remediation_id="NO_SUPPORTED_REMEDIATION",
                remediation_name="No Supported Remediation",
                state=RemediationState.REFUSED,
                preconditions=[
                    PreconditionCheck(
                        name="supported_remediation_available",
                        satisfied=False,
                        expected="supported remediation definition",
                        actual="none available",
                        reason="No safe supported remediation exists for this finding.",
                    )
                ],
                warnings=["NO_SUPPORTED_REMEDIATION: Finding has no safe supported remediation."],
                limitations=["Automated modification of this finding is currently unsupported."],
            )

        selected_cand: RemediationCandidate = candidates[0]
        rem_def = selected_cand.remediation

        if not selected_cand.is_supported:
            return RemediationPlan(
                plan_id=f"plan-unsupported-{finding_id}",
                source_apk_path=str(path),
                source_apk_sha256=apk_sha256,
                package_name=analysis.package_name,
                finding_id=finding_id,
                finding_category=target_finding.category,
                finding_title=target_finding.title,
                finding_state=str(target_finding.evidence_state),
                remediation_id=rem_def.id,
                remediation_name=rem_def.name,
                state=RemediationState.REFUSED,
                preconditions=[
                    PreconditionCheck(
                        name="remediation_supported",
                        satisfied=False,
                        expected="supported remediation",
                        actual=f"unsupported: {selected_cand.unsupported_reason}",
                        reason=selected_cand.unsupported_reason,
                    )
                ],
                warnings=[f"UNSUPPORTED_REMEDIATION: {selected_cand.unsupported_reason}"],
                limitations=[selected_cand.unsupported_reason],
            )

        # Merge parameters
        final_params = dict(selected_cand.parameters)
        final_params.update(params)

        # Machine-checkable preconditions & modifier requests
        preconditions: list[PreconditionCheck] = []
        mod_requests: list[dict[str, Any]] = []
        planned_changes: list[str] = []
        expected_diff: list[str] = []
        targets: list[str] = []

        if rem_def.id == "G-REM-001":
            # G-REM-001: Disable Boot Receiver
            # Check manifest for RECEIVE_BOOT_COMPLETED & receivers
            decl_perms = analysis.permissions.declared_permissions
            has_boot_perm = "android.permission.RECEIVE_BOOT_COMPLETED" in decl_perms
            preconditions.append(
                PreconditionCheck(
                    name="permission_declared",
                    satisfied=has_boot_perm,
                    expected="RECEIVE_BOOT_COMPLETED declared in manifest",
                    actual="declared" if has_boot_perm else "absent",
                    reason="Target app must declare RECEIVE_BOOT_COMPLETED.",
                )
            )

            rec_param = final_params.get("receiver") or target_finding.source_component
            if not rec_param:
                for loc in target_finding.evidence_locations:
                    if loc.startswith("receiver:"):
                        parts = loc.split(":")
                        if len(parts) > 1:
                            rec_param = parts[1]
                            break

            has_rec = bool(rec_param)

            preconditions.append(
                PreconditionCheck(
                    name="boot_receiver_identified",
                    satisfied=has_rec,
                    expected=f"boot receiver '{rec_param or 'unique'}' identified",
                    actual=rec_param or "not identified",
                    reason="Boot receiver must be identified.",
                )
            )
            preconditions.append(
                PreconditionCheck(
                    name="receiver_currently_enabled",
                    satisfied=has_rec,
                    expected="receiver is currently enabled",
                    actual="enabled" if has_rec else "not found",
                    reason="Receiver must currently be enabled to disable it.",
                )
            )

            mod_requests.append(
                {
                    "modifier_id": "c5.disable_boot_receiver",
                    "parameters": {"receiver": rec_param} if rec_param else {},
                }
            )
            rec_name = rec_param or "BootReceiver"
            targets.append(f"component:{rec_name}")
            targets.append("permission:android.permission.RECEIVE_BOOT_COMPLETED")
            planned_changes.append(f'set android:enabled="false" on <receiver {rec_name}>')
            planned_changes.append(
                "remove <uses-permission android:name=android.permission.RECEIVE_BOOT_COMPLETED>"
            )
            expected_diff.append("permission removed: android.permission.RECEIVE_BOOT_COMPLETED")
            expected_diff.append(f"component modified: {rec_name} enabled -> false")

        elif rem_def.id == "G-REM-002":
            # G-REM-002: Remove Specific Permission
            perm_to_remove = final_params.get("permission", "")
            if not perm_to_remove and target_finding.related_permissions:
                perm_to_remove = target_finding.related_permissions[0]
            has_perm = perm_to_remove in analysis.permissions.declared_permissions
            preconditions.append(
                PreconditionCheck(
                    name="permission_declared",
                    satisfied=has_perm,
                    expected=f"permission '{perm_to_remove}' declared in manifest",
                    actual="declared" if has_perm else "absent",
                    reason=(
                        f"Target permission '{perm_to_remove}' must be "
                        "declared in AndroidManifest.xml."
                    ),
                )
            )
            mod_requests.append(
                {
                    "modifier_id": "remediation.remove_permission",
                    "parameters": {"permission": perm_to_remove},
                }
            )
            targets.append(f"permission:{perm_to_remove}")
            planned_changes.append(f"remove <uses-permission android:name={perm_to_remove}>")
            expected_diff.append(f"permission removed: {perm_to_remove}")

        elif rem_def.id == "G-REM-003":
            # G-REM-003: Disable Manifest Component
            comp_to_disable = final_params.get("component") or target_finding.source_component
            if not comp_to_disable:
                for loc in target_finding.evidence_locations:
                    if any(
                        loc.startswith(p)
                        for p in ("component:", "activity:", "service:", "receiver:", "provider:")
                    ):
                        parts = loc.split(":")
                        if len(parts) > 1:
                            comp_to_disable = parts[1]
                            break

            has_comp = bool(comp_to_disable)
            preconditions.append(
                PreconditionCheck(
                    name="component_exists",
                    satisfied=has_comp,
                    expected=f"component '{comp_to_disable or 'target'}' declared in manifest",
                    actual="declared" if has_comp else "not found",
                    reason=(
                        f"Target component '{comp_to_disable}' must be "
                        "declared in AndroidManifest.xml."
                    ),
                )
            )
            preconditions.append(
                PreconditionCheck(
                    name="component_currently_enabled",
                    satisfied=has_comp,
                    expected="component is currently enabled",
                    actual="enabled" if has_comp else "not found",
                    reason="Component must be enabled to disable it.",
                )
            )
            mod_requests.append(
                {
                    "modifier_id": "remediation.disable_component",
                    "parameters": {"component": comp_to_disable or ""},
                }
            )
            targets.append(f"component:{comp_to_disable}")
            planned_changes.append(f'set android:enabled="false" on component {comp_to_disable}')
            expected_diff.append(f"component modified: {comp_to_disable} enabled -> false")

        all_satisfied = bool(preconditions) and all(p.satisfied for p in preconditions)
        state = RemediationState.PLANNED if all_satisfied else RemediationState.SKIPPED

        param_str = "-".join(f"{k}={v}" for k, v in sorted(final_params.items()))
        raw_key = f"{apk_sha256}:{finding_id}:{rem_def.id}:{param_str}"
        plan_id = f"plan-{hashlib.sha256(raw_key.encode()).hexdigest()[:12]}"

        return RemediationPlan(
            plan_id=plan_id,
            source_apk_path=str(path),
            source_apk_sha256=apk_sha256,
            package_name=analysis.package_name,
            finding_id=finding_id,
            finding_category=target_finding.category,
            finding_title=target_finding.title,
            finding_evidence_locations=list(target_finding.evidence_locations),
            finding_evidence_values=list(target_finding.evidence_values),
            finding_state=str(target_finding.evidence_state),
            remediation_id=rem_def.id,
            remediation_name=rem_def.name,
            state=state,
            preconditions=preconditions,
            targets=targets,
            planned_changes=planned_changes,
            expected_diff=expected_diff,
            verification_plan=list(rem_def.verification_requirements),
            warnings=list(rem_def.compatibility_notes),
            compatibility_notes=list(rem_def.compatibility_notes),
            limitations=list(rem_def.limitations),
            modifier_requests=mod_requests,
            created_at=datetime.now(UTC).isoformat(),
        )
