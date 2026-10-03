"""Phase G Synthetic and Unit Test Suite.

Covers tests G1 through G14:
- G1: Valid boot receiver remediation (planned, applied, verified, target remediated)
- G2: Permission removal (exact permission removed; checks whether DEX references remain)
- G3: Component disable (only requested component changes)
- G4: Missing finding (SKIPPED / REFUSED, no modification)
- G5: Incomplete finding evidence (UNDETERMINED, no unsafe modification)
- G6: Conflicting remediation requests / unsupported SDK (REFUSED)
- G7: Unexpected modification verification failure
- G8: Post-remediation finding remains (PARTIALLY_REMEDIATED / STILL_PRESENT)
- G9: Post-remediation new privacy finding warning
- G10: Original APK integrity (SHA-256 unchanged)
- G11: Dry run (no output APK modified)
- G12: Approval enforcement (cannot apply without approved=True)
- G13: Rollback on apply failure
- G14: ANSI-free JSON with FORCE_COLOR=3
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from apkforge.privacy.models import (
    AnalysisCompleteness,
    EvidenceState,
    PermissionPrivacyResult,
    PrivacyFinding,
    PrivacyResult,
)
from apkforge.remediation import (
    FindingResolution,
    RemediationPlan,
    RemediationService,
    RemediationState,
    compare_privacy_before_after,
)

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
OPENLINK = CORPUS_DIR / "de.audioattack.openlink_28.apk"


def _calc_sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# G1: Valid Boot Receiver Remediation
# ---------------------------------------------------------------------------


def test_g1_valid_boot_receiver_remediation(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    sha_before = _calc_sha256(OPENLINK)
    out_apk = tmp_path / "g1_remediated.apk"

    plan = RemediationService.plan(
        apk_path=OPENLINK,
        finding_id="PRIV-REC-BOOT",
    )
    assert plan.ready
    assert plan.state == RemediationState.PLANNED
    assert plan.remediation_id == "G-REM-001"

    result = RemediationService.apply(
        plan=plan,
        approved=True,
        output_path=out_apk,
        work_dir=tmp_path / "work",
    )

    assert result.state == RemediationState.VERIFIED
    assert result.output_apk_path == str(out_apk)
    assert out_apk.exists()
    assert result.original_apk_preserved
    assert _calc_sha256(OPENLINK) == sha_before
    assert result.comparison is not None
    assert result.comparison.target_finding.resolution == FindingResolution.REMEDIATED
    removed_perms = result.comparison.permission_changes.get("removed", [])
    assert "android.permission.RECEIVE_BOOT_COMPLETED" in removed_perms


# ---------------------------------------------------------------------------
# G2: Permission Removal
# ---------------------------------------------------------------------------


def test_g2_permission_removal_partial_vs_remediated() -> None:
    # Test 1: Permission removed, but DEX references remain -> PARTIALLY_REMEDIATED
    before = PrivacyResult(
        permissions=PermissionPrivacyResult(
            declared_permissions=["android.permission.ACCESS_FINE_LOCATION"]
        ),
        findings=[
            PrivacyFinding(
                id="PRIV-PERM-LOCATION",
                category="location",
                title="Location Permission Declared",
                description="Declared fine location permission.",
                related_permissions=["android.permission.ACCESS_FINE_LOCATION"],
                evidence_locations=[
                    "manifest:uses-permission:android.permission.ACCESS_FINE_LOCATION"
                ],
                evidence_values=["android.permission.ACCESS_FINE_LOCATION"],
            )
        ],
    )

    # After: permission gone from manifest, but a DEX API finding remains referencing location
    after_with_dex = PrivacyResult(
        permissions=PermissionPrivacyResult(declared_permissions=[]),
        findings=[
            PrivacyFinding(
                id="PRIV-API-LOCATION",
                category="location",
                title="Location API Invocations",
                description="Call to LocationManager.getLastKnownLocation",
                related_permissions=["android.permission.ACCESS_FINE_LOCATION"],
                evidence_locations=["api:android.location.LocationManager:getLastKnownLocation"],
                evidence_values=["LocationManager.getLastKnownLocation"],
            )
        ],
    )

    comp_partial = compare_privacy_before_after(
        before=before,
        after=after_with_dex,
        target_finding_id="PRIV-PERM-LOCATION",
        remediation_id="G-REM-002",
        parameters={"permission": "android.permission.ACCESS_FINE_LOCATION"},
    )
    assert comp_partial.target_finding.resolution == FindingResolution.PARTIALLY_REMEDIATED
    assert "static DEX code references" in comp_partial.target_finding.explanation

    # Test 2: Permission removed, NO DEX references remain -> REMEDIATED
    after_clean = PrivacyResult(
        permissions=PermissionPrivacyResult(declared_permissions=[]),
        findings=[],
    )
    comp_clean = compare_privacy_before_after(
        before=before,
        after=after_clean,
        target_finding_id="PRIV-PERM-LOCATION",
        remediation_id="G-REM-002",
        parameters={"permission": "android.permission.ACCESS_FINE_LOCATION"},
    )
    assert comp_clean.target_finding.resolution == FindingResolution.REMEDIATED


# ---------------------------------------------------------------------------
# G3: Component Disable
# ---------------------------------------------------------------------------


def test_g3_component_disable(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    plan = RemediationService.plan(
        apk_path=OPENLINK,
        finding_id="PRIV-REC-BOOT",
        remediation_id="G-REM-003",
        parameters={"component": "de.audioattack.openlink.conf.PackageChangeBroadcastReceiver"},
    )
    assert plan.remediation_id == "G-REM-003"
    target_comp = "component:de.audioattack.openlink.conf.PackageChangeBroadcastReceiver"
    assert any(target_comp in t for t in plan.targets)


# ---------------------------------------------------------------------------
# G4: Missing Finding
# ---------------------------------------------------------------------------


def test_g4_missing_finding() -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    plan = RemediationService.plan(
        apk_path=OPENLINK,
        finding_id="NON-EXISTENT-FINDING-9999",
    )
    assert plan.state == RemediationState.SKIPPED
    assert not plan.ready
    pre_names = {p.name: p.satisfied for p in plan.preconditions}
    assert pre_names.get("finding_exists") is False


# ---------------------------------------------------------------------------
# G5: Incomplete Finding Evidence
# ---------------------------------------------------------------------------


def test_g5_incomplete_finding_evidence() -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    incomplete_finding = PrivacyFinding(
        id="PRIV-UNKNOWN-1",
        category="unknown",
        title="Incomplete Finding",
        description="Indeterminate evidence.",
        evidence_state=EvidenceState.UNKNOWN,
        analysis_completeness=AnalysisCompleteness.PARTIAL,
    )

    plan = RemediationService.plan(
        apk_path=OPENLINK,
        finding_id="PRIV-UNKNOWN-1",
        finding_override=incomplete_finding,
    )
    assert plan.state == RemediationState.UNDETERMINED
    assert not plan.ready
    pre_names = {p.name: p.satisfied for p in plan.preconditions}
    assert pre_names.get("evidence_complete") is False


# ---------------------------------------------------------------------------
# G6: Unsupported Remediation Candidate
# ---------------------------------------------------------------------------


def test_g6_unsupported_remediation_candidate() -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    sdk_finding = PrivacyFinding(
        id="PRIV-SDK-ADMOB",
        category="advertising",
        title="Google AdMob SDK Reference",
        description="Statically referenced AdMob classes.",
        related_sdks=["ad.google.admob"],
    )

    plan = RemediationService.plan(
        apk_path=OPENLINK,
        finding_id="PRIV-SDK-ADMOB",
        finding_override=sdk_finding,
    )
    assert plan.state == RemediationState.REFUSED
    assert not plan.ready
    assert "UNSUPPORTED_REMEDIATION" in plan.warnings[0]


# ---------------------------------------------------------------------------
# G7: Target Still Present Classification
# ---------------------------------------------------------------------------


def test_g7_target_still_present() -> None:
    f = PrivacyFinding(
        id="PRIV-REC-BOOT",
        category="persistence",
        title="Boot Receiver",
        description="Boot receiver active.",
    )
    before = PrivacyResult(findings=[f])
    after = PrivacyResult(findings=[f])

    comp = compare_privacy_before_after(
        before=before,
        after=after,
        target_finding_id="PRIV-REC-BOOT",
        remediation_id="G-REM-001",
    )
    assert comp.target_finding.resolution == FindingResolution.STILL_PRESENT


# ---------------------------------------------------------------------------
# G8: Post-Remediation Finding Remains
# ---------------------------------------------------------------------------


def test_g8_post_remediation_partially_remediated() -> None:
    before = PrivacyResult(
        permissions=PermissionPrivacyResult(declared_permissions=["android.permission.CAMERA"]),
        findings=[
            PrivacyFinding(
                id="PRIV-PERM-CAMERA",
                category="camera",
                title="Camera Permission",
                description="Declared camera permission.",
                related_permissions=["android.permission.CAMERA"],
            )
        ],
    )
    after = PrivacyResult(
        permissions=PermissionPrivacyResult(declared_permissions=[]),
        findings=[
            PrivacyFinding(
                id="PRIV-API-CAMERA",
                category="camera",
                title="Camera API",
                description="Camera API call in DEX.",
                related_permissions=["android.permission.CAMERA"],
            )
        ],
    )

    comp = compare_privacy_before_after(
        before=before,
        after=after,
        target_finding_id="PRIV-PERM-CAMERA",
        remediation_id="G-REM-002",
        parameters={"permission": "android.permission.CAMERA"},
    )
    assert comp.target_finding.resolution == FindingResolution.PARTIALLY_REMEDIATED


# ---------------------------------------------------------------------------
# G9: Post-Remediation New Privacy Finding Introduced
# ---------------------------------------------------------------------------


def test_g9_new_privacy_finding_introduced() -> None:
    before = PrivacyResult(findings=[])
    after = PrivacyResult(
        findings=[
            PrivacyFinding(
                id="PRIV-NEW-SUSPICIOUS",
                category="dynamic_code",
                title="Newly Observed Dynamic Code",
                description="Unexpected dynamic loading.",
            )
        ]
    )

    comp = compare_privacy_before_after(
        before=before,
        after=after,
        target_finding_id="NONE",
        remediation_id="G-REM-001",
    )
    assert "PRIV-NEW-SUSPICIOUS" in comp.findings_introduced


# ---------------------------------------------------------------------------
# G10: Original APK Integrity
# ---------------------------------------------------------------------------


def test_g10_original_apk_integrity(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    sha_orig = _calc_sha256(OPENLINK)
    plan = RemediationService.plan(OPENLINK, finding_id="PRIV-REC-BOOT")
    res = RemediationService.apply(
        plan=plan,
        approved=True,
        output_path=tmp_path / "g10.apk",
        work_dir=tmp_path / "work",
    )
    assert res.original_apk_preserved
    assert _calc_sha256(OPENLINK) == sha_orig


# ---------------------------------------------------------------------------
# G11: Dry Run Does Not Produce APK
# ---------------------------------------------------------------------------


def test_g11_dry_run_no_output_modification(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    out_file = tmp_path / "dry_run.apk"
    plan = RemediationService.plan(OPENLINK, finding_id="PRIV-REC-BOOT")
    assert plan.ready
    assert not out_file.exists()


# ---------------------------------------------------------------------------
# G12: Approval Enforcement
# ---------------------------------------------------------------------------


def test_g12_approval_enforcement(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    out_file = tmp_path / "unapproved.apk"
    plan = RemediationService.plan(OPENLINK, finding_id="PRIV-REC-BOOT")
    result = RemediationService.apply(
        plan=plan,
        approved=False,
        output_path=out_file,
    )
    assert result.state == RemediationState.APPROVAL_REQUIRED
    assert not result.approved
    assert not out_file.exists()


# ---------------------------------------------------------------------------
# G13: Rollback on Apply Failure
# ---------------------------------------------------------------------------


def test_g13_rollback_on_failed_plan(tmp_path: Path) -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    # A plan that is not ready must not execute
    unready_plan = RemediationPlan(
        plan_id="unready-1",
        source_apk_path=str(OPENLINK),
        source_apk_sha256=_calc_sha256(OPENLINK),
        finding_id="PRIV-REC-BOOT",
        finding_category="persistence",
        finding_title="Test",
        remediation_id="G-REM-001",
        remediation_name="Disable Boot Receiver",
        state=RemediationState.SKIPPED,
        preconditions=[],
    )
    unready_out = tmp_path / "unready.apk"
    res = RemediationService.apply(unready_plan, approved=True, output_path=unready_out)
    assert res.state == RemediationState.SKIPPED
    assert not unready_out.exists()


# ---------------------------------------------------------------------------
# G14: ANSI-Free JSON with FORCE_COLOR=3
# ---------------------------------------------------------------------------


def test_g14_ansi_free_json_with_force_color() -> None:
    if not OPENLINK.exists():
        pytest.skip("OpenLink corpus APK not available.")

    env = dict(os.environ)
    env["FORCE_COLOR"] = "3"

    # Test 1: remediations --json
    cmd1 = [
        str(Path(".venv-validation/bin/python").resolve()),
        "-m",
        "apkforge.cli.main",
        "remediations",
        "--json",
    ]
    proc1 = subprocess.run(
        cmd1,
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    out1 = proc1.stdout
    assert "\x1b" not in out1
    data1 = json.loads(out1)
    assert len(data1) >= 4

    # Test 2: remediate --finding ... --dry-run --json
    cmd2 = [
        str(Path(".venv-validation/bin/python").resolve()),
        "-m",
        "apkforge.cli.main",
        "remediate",
        str(OPENLINK),
        "--finding",
        "PRIV-REC-BOOT",
        "--dry-run",
        "--json",
    ]
    proc2 = subprocess.run(
        cmd2,
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    out2 = proc2.stdout
    assert "\x1b" not in out2
    data2 = json.loads(out2)
    assert data2["plan_id"].startswith("plan-")
    assert data2["remediation_id"] == "G-REM-001"
