"""Post-remediation comparison and finding resolution classifier.

Compares pre-remediation and post-remediation Phase F privacy intelligence,
classifying finding transitions and establishing whether the target finding is
REMEDIATED, PARTIALLY_REMEDIATED, STILL_PRESENT, NO_LONGER_COMPARABLE, or UNKNOWN.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.models import AnalysisStatus
from apkforge.remediation.models import (
    BeforeAfterComparison,
    FindingResolution,
    TargetFindingComparison,
)

if TYPE_CHECKING:
    from apkforge.privacy.models import PrivacyFinding, PrivacyResult

__all__ = ["compare_privacy_before_after"]


def compare_privacy_before_after(
    before: PrivacyResult,
    after: PrivacyResult,
    target_finding_id: str,
    remediation_id: str,
    parameters: dict[str, str] | None = None,
) -> BeforeAfterComparison:
    """Compare privacy analysis results before and after a remediation."""
    params = parameters or {}
    before_by_id: dict[str, PrivacyFinding] = {f.id: f for f in before.findings}
    after_by_id: dict[str, PrivacyFinding] = {f.id: f for f in after.findings}

    before_ids = set(before_by_id.keys())
    after_ids = set(after_by_id.keys())

    removed = sorted(before_ids - after_ids)
    retained = sorted(before_ids & after_ids)
    introduced = sorted(after_ids - before_ids)

    changed: list[str] = []
    for fid in retained:
        b_f = before_by_id[fid]
        a_f = after_by_id[fid]
        if (
            b_f.severity != a_f.severity
            or b_f.confidence != a_f.confidence
            or set(b_f.evidence_values) != set(a_f.evidence_values)
        ):
            changed.append(fid)

    # Permission changes
    before_perms = set(before.declared_permissions)
    after_perms = set(after.declared_permissions)
    perm_changes = {
        "removed": sorted(before_perms - after_perms),
        "retained": sorted(before_perms & after_perms),
        "added": sorted(after_perms - before_perms),
    }

    # SDK changes
    before_sdks = {s.id for s in before.detected_sdks}
    after_sdks = {s.id for s in after.detected_sdks}
    sdk_changes = {
        "removed": sorted(before_sdks - after_sdks),
        "retained": sorted(before_sdks & after_sdks),
        "added": sorted(after_sdks - before_sdks),
    }

    # Endpoint changes
    before_urls = {e.endpoint for e in before.endpoints.classified_endpoints}
    after_urls = {e.endpoint for e in after.endpoints.classified_endpoints}
    endpoint_changes = {
        "removed_count": len(before_urls - after_urls),
        "retained_count": len(before_urls & after_urls),
        "added_count": len(after_urls - before_urls),
    }

    # Component changes
    disabled_comps: list[str] = []
    if remediation_id == "G-REM-001":
        rec = params.get("receiver", "")
        if rec:
            disabled_comps.append(rec)
    elif remediation_id == "G-REM-003":
        comp = params.get("component", "")
        if comp:
            disabled_comps.append(comp)

    comp_changes = {"disabled": disabled_comps}

    # Target finding resolution analysis
    target_before = before_by_id.get(target_finding_id)
    target_after = after_by_id.get(target_finding_id)

    before_ev = (
        [
            f"{loc}={val}"
            for loc, val in zip(
                target_before.evidence_locations,
                target_before.evidence_values,
                strict=False,
            )
        ]
        if target_before
        else []
    )
    after_ev = (
        [
            f"{loc}={val}"
            for loc, val in zip(
                target_after.evidence_locations,
                target_after.evidence_values,
                strict=False,
            )
        ]
        if target_after
        else []
    )

    resolution: FindingResolution
    explanation: str

    if after.status == AnalysisStatus.FAILED:
        resolution = FindingResolution.UNKNOWN
        explanation = (
            f"Post-remediation analysis status is {after.status}; cannot determine resolution."
        )
    elif target_before is None:
        resolution = FindingResolution.UNKNOWN
        explanation = f"Target finding '{target_finding_id}' was not present in the original APK."
    elif target_after is not None:
        resolution = FindingResolution.STILL_PRESENT
        explanation = (
            f"Target finding '{target_finding_id}' remains present in post-remediation analysis."
        )
    else:
        # Target finding is absent from post-remediation findings list.
        # Check if the remediation was permission removal (G-REM-002)
        if remediation_id == "G-REM-002":
            target_perm = params.get("permission", "")
            # Check if DEX code references still remain in after analysis
            has_dex_reference = False
            dex_ref_details: list[str] = []

            for f in after.findings:
                if target_perm in f.related_permissions:
                    has_dex_reference = True
                    dex_ref_details.append(f.id)
                # Check category correlation
                match_cat = target_before and f.category == target_before.category
                if (
                    match_cat
                    and f.id != target_finding_id
                    and any("api:" in loc for loc in f.evidence_locations)
                ):
                    has_dex_reference = True
                    dex_ref_details.append(f"{f.id} ({f.title})")

            if has_dex_reference:
                resolution = FindingResolution.PARTIALLY_REMEDIATED
                explanation = (
                    f"Manifest permission '{target_perm}' was removed, but static DEX "
                    f"code references to the associated API remain: "
                    f"{', '.join(dex_ref_details[:3])}."
                )
            else:
                resolution = FindingResolution.REMEDIATED
                explanation = (
                    f"Manifest permission '{target_perm}' was removed and no remaining static code "
                    "references were observed."
                )
        elif remediation_id == "G-REM-001":
            # Boot receiver disabled
            resolution = FindingResolution.REMEDIATED
            explanation = (
                "Boot receiver was disabled and RECEIVE_BOOT_COMPLETED removed; "
                "persistence finding eliminated."
            )
        elif remediation_id == "G-REM-003":
            resolution = FindingResolution.REMEDIATED
            target_comp = params.get("component", "")
            explanation = f"Component '{target_comp}' was disabled; component finding eliminated."
        else:
            resolution = FindingResolution.REMEDIATED
            explanation = f"Target finding '{target_finding_id}' was eliminated post-remediation."

    target_comparison = TargetFindingComparison(
        finding_id=target_finding_id,
        resolution=resolution,
        before_evidence=before_ev,
        after_evidence=after_ev,
        explanation=explanation,
    )

    limitations: list[str] = list(after.limitations)
    if resolution == FindingResolution.PARTIALLY_REMEDIATED:
        limitations.append(
            "Target capability is PARTIALLY_REMEDIATED: manifest declaration was removed, "
            "but static DEX bytecode references remain."
        )

    return BeforeAfterComparison(
        target_finding=target_comparison,
        findings_removed=removed,
        findings_retained=retained,
        findings_changed=changed,
        findings_introduced=introduced,
        sdk_changes=sdk_changes,
        endpoint_changes=endpoint_changes,
        permission_changes=perm_changes,
        component_changes=comp_changes,
        limitations=limitations,
    )
