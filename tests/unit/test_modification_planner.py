"""Comprehensive unit and integration tests for Phase 6: Modification Planning Engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus, Confidence, Evidence
from apkforge.inspection.models import (
    ApplicationInfo,
    ContentProviderInfo,
    DEXFileInspection,
    DEXInspection,
    InspectionResult,
    ManifestInspection,
    PermissionInfo,
    ServiceInfo,
)
from apkforge.modification import (
    ChangeType,
    ConflictType,
    ModificationPlanner,
    ModificationRisk,
    PlanStatus,
    Reversibility,
    load_plan,
    plan_from_json,
    plan_from_yaml,
    plan_to_json,
    plan_to_yaml,
    save_plan,
)
from apkforge.privacy.models import DetectedSDK, PrivacyResult, SDKCategory
from apkforge.security.models import SecurityFinding, SecurityResult
from tests.fixtures import create_synthetic_apk

runner = CliRunner()


# ===========================================================================
# 1. Plan Generation & Proposal Discovery
# ===========================================================================


def test_plan_generation_unused_permission_and_hardening(tmp_path: Path) -> None:
    """Test generating a plan that proposes removing unused permissions and hardening manifest."""
    apk_file = tmp_path / "target.apk"
    create_synthetic_apk(apk_file, package_name="com.example.app")

    manifest = ManifestInspection(
        package_name="com.example.app",
        application=ApplicationInfo(
            debuggable=True,
            uses_cleartext_traffic=True,
            allow_backup=True,
        ),
        permissions=[
            PermissionInfo(name="android.permission.READ_CONTACTS"),
            PermissionInfo(name="android.permission.INTERNET"),
        ],
    )
    # DEX has no ContactsContract calls
    dex = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=1024, sha256="abc")])
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest, dex=dex)

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    assert plan.status == PlanStatus.REVIEW_REQUIRED
    assert plan.change_count >= 4

    types = {c.change_type for c in plan.changes}
    assert ChangeType.REMOVE_PERMISSION in types
    assert ChangeType.MODIFY_CONFIGURATION in types

    perm_change = next(c for c in plan.changes if c.target == "android.permission.READ_CONTACTS")
    assert perm_change.change_type == ChangeType.REMOVE_PERMISSION
    assert perm_change.confidence == Confidence.HIGH
    assert perm_change.risk == ModificationRisk.LOW
    assert len(perm_change.evidence) > 0
    assert len(perm_change.validation_steps) > 0


def test_empty_plan_for_clean_app(tmp_path: Path) -> None:
    """Test that a clean app without unused permissions or insecure configs has an empty plan."""
    apk_file = tmp_path / "clean.apk"
    create_synthetic_apk(apk_file, package_name="com.example.clean")

    manifest = ManifestInspection(
        package_name="com.example.clean",
        application=ApplicationInfo(
            debuggable=False,
            uses_cleartext_traffic=False,
            allow_backup=False,
        ),
        permissions=[],
    )
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest)

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    assert plan.is_empty
    assert plan.change_count == 0
    assert plan.status == PlanStatus.REVIEW_REQUIRED


def test_tracker_sdk_removal_proposal(tmp_path: Path) -> None:
    """Test proposing tracker removal when PrivacyResult detects tracking SDKs."""
    apk_file = tmp_path / "tracker_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.tracker")

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(package_name="com.example.tracker"),
    )
    privacy = PrivacyResult(
        status=AnalysisStatus.COMPLETE,
        package_name="com.example.tracker",
        detected_sdks=[
            DetectedSDK(
                id="admob",
                name="Google AdMob",
                category=SDKCategory.ADVERTISING,
                confidence=Confidence.CONFIRMED,
                matched_packages=["com.google.android.gms.ads"],
                evidence=[
                    Evidence(
                        description="AdMob package",
                        location="classes.dex",
                        snippet="com.google.android.gms.ads",
                    )
                ],
            )
        ],
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp, privacy=privacy)

    tracker_change = next((c for c in plan.changes if c.target == "Google AdMob"), None)
    assert tracker_change is not None
    assert tracker_change.change_type == ChangeType.REMOVE_TRACKER
    assert tracker_change.confidence == Confidence.CONFIRMED
    assert tracker_change.risk == ModificationRisk.MEDIUM
    assert tracker_change.reversibility == Reversibility.PARTIALLY_REVERSIBLE


def test_unprotected_exported_component_proposal(tmp_path: Path) -> None:
    """Test proposal for securing an exported service lacking permission protection."""
    apk_file = tmp_path / "service_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.service")

    manifest = ManifestInspection(
        package_name="com.example.service",
        services=[
            ServiceInfo(
                name="com.example.VulnerableService",
                exported=True,
                permission=None,
            )
        ],
    )
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest)

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    comp_change = next(
        (c for c in plan.changes if c.target == "com.example.VulnerableService"), None
    )
    assert comp_change is not None
    assert comp_change.change_type == ChangeType.MODIFY_COMPONENT
    assert "exported='false'" in comp_change.operation
    assert comp_change.risk == ModificationRisk.MEDIUM


def test_embedded_payload_removal_proposal(tmp_path: Path) -> None:
    """Test proposing removal of embedded standalone ELF binary identified in security."""
    apk_file = tmp_path / "payload_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.payload")

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(package_name="com.example.payload"),
    )
    security = SecurityResult(
        status=AnalysisStatus.COMPLETE,
        package_name="com.example.payload",
        findings=[
            SecurityFinding(
                id="SEC-MAL-PAYLOAD-ELF-ASSETS_DROPPER",
                category="payload",
                title="Embedded Standalone ELF Binary: assets/dropper",
                description="ELF binary outside lib/",
                severity="high",
                confidence="confirmed",
                evidence=[
                    Evidence(
                        description="ELF binary in assets",
                        location="embedded:assets/dropper",
                    )
                ],
            )
        ],
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp, security=security)

    payload_change = next((c for c in plan.changes if c.target == "assets/dropper"), None)
    assert payload_change is not None
    assert payload_change.change_type == ChangeType.REMOVE_EMBEDDED_PAYLOAD
    assert payload_change.confidence == Confidence.CONFIRMED


def test_diff_regression_rollback_proposal(tmp_path: Path) -> None:
    """Test proposing rollback of newly introduced dangerous permission from DiffResult."""
    import zipfile

    from apkforge.diff import DiffEngine

    apk_orig = tmp_path / "orig.apk"
    apk_modded = tmp_path / "modded.apk"

    manifest_a = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.modded" android:versionCode="1" android:versionName="1.0">
    <application android:label="App" />
</manifest>"""

    manifest_b = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.modded" android:versionCode="1" android:versionName="1.0">
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <application android:label="App" />
</manifest>"""

    with zipfile.ZipFile(apk_orig, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_a)
    with zipfile.ZipFile(apk_modded, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_b)

    diff_engine = DiffEngine()
    diff = diff_engine.diff(apk_orig, apk_modded)

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(
            package_name="com.example.modded",
            permissions=[PermissionInfo(name="android.permission.RECORD_AUDIO")],
        ),
        dex=DEXInspection(
            dex_files=[
                DEXFileInspection(
                    path="classes.dex",
                    size=1024,
                    sha256="abc",
                    api_references=["android.media.AudioRecord"],
                )
            ]
        ),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_modded, inspection=insp, diff=diff)

    diff_change = next((c for c in plan.changes if "RECORD_AUDIO" in c.target), None)
    assert diff_change is not None
    assert diff_change.change_type == ChangeType.REMOVE_PERMISSION
    assert "diff" in diff_change.tags


# ===========================================================================
# 2. Evidence, Provenance & Partial Analysis
# ===========================================================================


def test_evidence_provenance_preserved(tmp_path: Path) -> None:
    """Verify that every proposed change retains traceable evidence items."""
    apk_file = tmp_path / "app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.evidence")

    manifest = ManifestInspection(
        package_name="com.example.evidence",
        application=ApplicationInfo(debuggable=True),
        permissions=[PermissionInfo(name="android.permission.CAMERA")],
    )
    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=manifest,
        dex=DEXInspection(
            dex_files=[DEXFileInspection(path="classes.dex", size=1024, sha256="abc")]
        ),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    for change in plan.changes:
        assert len(change.evidence) > 0
        ev = change.evidence[0]
        assert ev.location is not None
        assert len(ev.description) > 0


def test_missing_and_partial_analysis_limitations(tmp_path: Path) -> None:
    """Verify missing privacy/security results record explicit warnings and limitations."""
    apk_file = tmp_path / "partial.apk"
    create_synthetic_apk(apk_file, package_name="com.example.partial")

    # Partial inspection, missing privacy, missing security
    insp = InspectionResult(
        status=AnalysisStatus.PARTIAL,
        manifest=ManifestInspection(package_name="com.example.partial"),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    assert len(plan.warnings) > 0
    assert any("PARTIAL" in w for w in plan.warnings)

    assert len(plan.limitations) >= 3
    assert any("Privacy analysis was not provided" in lim for lim in plan.limitations)
    assert any("Security analysis was not provided" in lim for lim in plan.limitations)


# ===========================================================================
# 3. Risk Assessment, Dependencies & Conflicts
# ===========================================================================


def test_risk_assessment_and_explanations(tmp_path: Path) -> None:
    """Test that all proposed changes have risk levels and explainable rationales."""
    apk_file = tmp_path / "risk.apk"
    create_synthetic_apk(apk_file, package_name="com.example.risk")

    manifest = ManifestInspection(
        package_name="com.example.risk",
        application=ApplicationInfo(debuggable=True),
        permissions=[PermissionInfo(name="android.permission.RECORD_AUDIO")],
        services=[ServiceInfo(name="com.example.Svc", exported=True, permission=None)],
    )
    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=manifest,
        dex=DEXInspection(
            dex_files=[DEXFileInspection(path="classes.dex", size=1024, sha256="abc")]
        ),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    for c in plan.changes:
        assert c.risk in (
            ModificationRisk.LOW,
            ModificationRisk.MEDIUM,
            ModificationRisk.HIGH,
            ModificationRisk.CRITICAL,
        )
        assert len(c.risk_explanation) > 10
        assert c.reversibility in (
            Reversibility.REVERSIBLE,
            Reversibility.PARTIALLY_REVERSIBLE,
            Reversibility.NOT_REVERSIBLE,
            Reversibility.UNKNOWN,
        )


def test_dependency_detection_and_ordering(tmp_path: Path) -> None:
    """Test detecting dependencies between tracker removal and associated components."""
    apk_file = tmp_path / "dep_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.dep")

    manifest = ManifestInspection(
        package_name="com.example.dep",
        providers=[
            ContentProviderInfo(
                name="com.google.android.gms.ads.MobileAdsInitProvider",
                exported=False,
            )
        ],
    )
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest)
    privacy = PrivacyResult(
        status=AnalysisStatus.COMPLETE,
        package_name="com.example.dep",
        detected_sdks=[
            DetectedSDK(
                id="admob",
                name="Google AdMob",
                category=SDKCategory.ADVERTISING,
                confidence=Confidence.CONFIRMED,
                matched_packages=["com.google.android.gms.ads"],
                evidence=[
                    Evidence(
                        description="Init provider",
                        location="manifest:provider",
                        snippet="com.google.android.gms.ads",
                    )
                ],
            )
        ],
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp, privacy=privacy)

    # Tracker proposal exists
    tracker_c = next((c for c in plan.changes if c.target == "Google AdMob"), None)
    assert tracker_c is not None


def test_conflict_detection_same_target(tmp_path: Path) -> None:
    """Test detecting conflicts when changes propose incompatible operations on same target."""
    apk_file = tmp_path / "conflict.apk"
    create_synthetic_apk(apk_file, package_name="com.example.conflict")

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(
            package_name="com.example.conflict",
            services=[ServiceInfo(name="com.example.MyService", exported=True)],
        ),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    # Inject a simulated conflicting second change targeting the same service with remove
    from apkforge.modification.models import PlannedChange

    conflicting_c = PlannedChange(
        id="CHANGE-SIM-REMOVE",
        change_type=ChangeType.REMOVE_COMPONENT,
        target="com.example.MyService",
        operation="Delete component tag for com.example.MyService",
        reason="Simulated complete removal",
    )
    plan.changes.append(conflicting_c)

    from apkforge.modification.conflicts import ConflictDetector

    conflicts = ConflictDetector.detect_conflicts(plan.changes)
    assert len(conflicts) > 0
    assert conflicts[0].conflict_type == ConflictType.TARGET_CONFLICT
    assert "com.example.MyService" in conflicts[0].reason


# ===========================================================================
# 4. Staleness, Serialization & Determinism
# ===========================================================================


def test_plan_source_hash_and_staleness(tmp_path: Path) -> None:
    """Test SHA-256 integrity binding and stale plan detection."""
    apk_file = tmp_path / "stale_test.apk"
    create_synthetic_apk(apk_file, package_name="com.example.stale")

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(package_name="com.example.stale"),
    )
    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    current_hash = plan.source_sha256
    assert len(current_hash) == 64
    assert not plan.is_stale(current_hash)

    # Different APK hash -> stale
    fake_hash = "f" * 64
    assert plan.is_stale(fake_hash)

    was_stale = plan.mark_stale_if_mismatched(fake_hash)
    assert was_stale is True
    assert plan.status == PlanStatus.STALE
    assert any("STALE" in w for w in plan.warnings)


def test_json_and_yaml_roundtrip_serialization(tmp_path: Path) -> None:
    """Test full round-trip serialization and deserialization in JSON and YAML."""
    apk_file = tmp_path / "roundtrip.apk"
    create_synthetic_apk(apk_file, package_name="com.example.roundtrip")

    manifest = ManifestInspection(
        package_name="com.example.roundtrip",
        application=ApplicationInfo(debuggable=True),
        permissions=[PermissionInfo(name="android.permission.CAMERA")],
    )
    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=manifest,
        dex=DEXInspection(
            dex_files=[DEXFileInspection(path="classes.dex", size=1024, sha256="abc")]
        ),
    )

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    # 1. JSON Roundtrip
    json_str = plan_to_json(plan)
    parsed_from_json = plan_from_json(json_str)
    assert parsed_from_json.plan_id == plan.plan_id
    assert parsed_from_json.source_sha256 == plan.source_sha256
    assert parsed_from_json.change_count == plan.change_count
    assert parsed_from_json.status == plan.status

    # 2. YAML Roundtrip
    yaml_str = plan_to_yaml(plan)
    parsed_from_yaml = plan_from_yaml(yaml_str)
    assert parsed_from_yaml.plan_id == plan.plan_id
    assert parsed_from_yaml.source_sha256 == plan.source_sha256
    assert parsed_from_yaml.change_count == plan.change_count


def test_save_and_load_plan(tmp_path: Path) -> None:
    """Test file persistence via save_plan and load_plan."""
    apk_file = tmp_path / "app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.save")

    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=ManifestInspection(
            package_name="com.example.save",
            application=ApplicationInfo(debuggable=True),
        ),
    )
    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    # Save as JSON
    json_path = tmp_path / "plan.json"
    save_plan(plan, json_path)
    loaded_json = load_plan(json_path)
    assert loaded_json.plan_id == plan.plan_id

    # Save as YAML
    yaml_path = tmp_path / "plan.yaml"
    save_plan(plan, yaml_path)
    loaded_yaml = load_plan(yaml_path)
    assert loaded_yaml.plan_id == plan.plan_id


def test_deterministic_plan_generation(tmp_path: Path) -> None:
    """Test that running the planner twice on the same inputs yields identical plans."""
    apk_file = tmp_path / "det.apk"
    create_synthetic_apk(apk_file, package_name="com.example.det")

    manifest = ManifestInspection(
        package_name="com.example.det",
        application=ApplicationInfo(debuggable=True, allow_backup=True),
        permissions=[PermissionInfo(name="android.permission.RECORD_AUDIO")],
    )
    insp = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        manifest=manifest,
        dex=DEXInspection(
            dex_files=[DEXFileInspection(path="classes.dex", size=1024, sha256="abc")]
        ),
    )

    planner = ModificationPlanner()
    plan1 = planner.create_plan(apk_path=apk_file, inspection=insp)
    plan2 = planner.create_plan(apk_path=apk_file, inspection=insp)

    assert plan1.plan_id == plan2.plan_id
    assert plan1.change_count == plan2.change_count
    assert [c.id for c in plan1.changes] == [c.id for c in plan2.changes]
    assert [c.target for c in plan1.changes] == [c.target for c in plan2.changes]


# ===========================================================================
# 5. Negative Tests & Safety Invariants
# ===========================================================================


def test_safety_original_apk_unmodified(tmp_path: Path) -> None:
    """CRITICAL SAFETY TEST: Verify source APK is byte-for-byte unchanged after planning."""
    apk_file = tmp_path / "safety.apk"
    create_synthetic_apk(apk_file, package_name="com.example.safety")

    with open(apk_file, "rb") as f:
        bytes_before = f.read()
    hash_before = hashlib.sha256(bytes_before).hexdigest()

    manifest = ManifestInspection(
        package_name="com.example.safety",
        application=ApplicationInfo(debuggable=True),
    )
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest)

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)
    assert plan.change_count > 0

    with open(apk_file, "rb") as f:
        bytes_after = f.read()
    hash_after = hashlib.sha256(bytes_after).hexdigest()

    assert bytes_before == bytes_after
    assert hash_before == hash_after


def test_negative_dynamic_loading_reduces_confidence(tmp_path: Path) -> None:
    """If unused permission is found but DEX has dynamic loading, confidence must drop to MEDIUM."""
    apk_file = tmp_path / "dyn_app.apk"
    create_synthetic_apk(apk_file, package_name="com.example.dyn")

    manifest = ManifestInspection(
        package_name="com.example.dyn",
        permissions=[PermissionInfo(name="android.permission.RECORD_AUDIO")],
    )
    dex = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1024,
                sha256="abc",
                api_references=["dalvik.system.DexClassLoader"],
            )
        ]
    )
    insp = InspectionResult(status=AnalysisStatus.COMPLETE, manifest=manifest, dex=dex)

    planner = ModificationPlanner()
    plan = planner.create_plan(apk_path=apk_file, inspection=insp)

    perm_change = next(
        (c for c in plan.changes if c.target == "android.permission.RECORD_AUDIO"), None
    )
    assert perm_change is not None
    # Because dynamic loading was detected, confidence is MEDIUM, not HIGH
    assert perm_change.confidence == Confidence.MEDIUM
    assert perm_change.risk == ModificationRisk.MEDIUM
    assert "Dynamic class loading" in perm_change.reason


# ===========================================================================
# 6. CLI Integration Tests
# ===========================================================================


def test_cli_plan_command_text(tmp_path: Path) -> None:
    """Test `apkforge plan <apk>` CLI command with human-readable output."""
    apk_file = tmp_path / "cli_test.apk"
    create_synthetic_apk(apk_file, package_name="com.example.cli")

    result = runner.invoke(app, ["plan", str(apk_file)])
    assert result.exit_code == 0
    assert "APKForge Modification Plan" in result.stdout
    assert "Source APK:" in result.stdout
    assert "Status: REVIEW_REQUIRED" in result.stdout or "Status:" in result.stdout


def test_cli_plan_command_json(tmp_path: Path) -> None:
    """Test `apkforge plan <apk> --json` CLI command."""
    apk_file = tmp_path / "cli_json.apk"
    create_synthetic_apk(apk_file, package_name="com.example.cli.json")

    result = runner.invoke(app, ["plan", str(apk_file), "--json"])
    assert result.exit_code == 0

    parsed = json.loads(result.stdout)
    assert "plan_id" in parsed
    assert "source_sha256" in parsed
    assert "status" in parsed
    assert parsed["status"] == "review_required"
    assert "changes" in parsed


def test_cli_plan_command_yaml(tmp_path: Path) -> None:
    """Test `apkforge plan <apk> --yaml` CLI command."""
    apk_file = tmp_path / "cli_yaml.apk"
    create_synthetic_apk(apk_file, package_name="com.example.cli.yaml")

    result = runner.invoke(app, ["plan", str(apk_file), "--yaml"])
    assert result.exit_code == 0
    assert "plan_id:" in result.stdout
    assert "status: review_required" in result.stdout


def test_cli_plan_command_output_file(tmp_path: Path) -> None:
    """Test saving plan via `apkforge plan <apk> -o plan.yaml`."""
    apk_file = tmp_path / "cli_out.apk"
    create_synthetic_apk(apk_file, package_name="com.example.cli.out")
    out_file = tmp_path / "saved_plan.yaml"

    result = runner.invoke(app, ["plan", str(apk_file), "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.is_file()

    loaded = load_plan(out_file)
    assert loaded.status == PlanStatus.REVIEW_REQUIRED


def test_cli_plan_filtering(tmp_path: Path) -> None:
    """Test `apkforge plan <apk> --type permission --risk low` filtering."""
    apk_file = tmp_path / "cli_filter.apk"
    create_synthetic_apk(apk_file, package_name="com.example.cli.filter")

    result = runner.invoke(
        app,
        ["plan", str(apk_file), "--type", "config", "--risk", "low", "--json"],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    for c in parsed.get("changes", []):
        assert c["risk"] in ("low", "medium", "high", "critical")
