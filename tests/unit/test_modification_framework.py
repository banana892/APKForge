"""Tests for APKForge Phase 7 — Modification Framework.

Tests the Modifier protocol, ModifierRegistry, individual built-in modifiers,
and the ModificationFramework orchestrator.
"""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from apkforge.core.models import Confidence, Evidence
from apkforge.modification.models import (
    ChangeStatus,
    ChangeType,
    ModificationPlan,
    ModificationRisk,
    PlannedChange,
    PlanStatus,
    Reversibility,
)
from apkforge.modification.modifiers.base import (
    Modifier,
    ModificationExecutionContext,
    ModificationResult,
    ModificationStepResult,
    StepStatus,
)
from apkforge.modification.modifiers.component import ComponentModifier
from apkforge.modification.modifiers.dex import DexModifier
from apkforge.modification.modifiers.manifest import ManifestModifier
from apkforge.modification.modifiers.payload import PayloadModifier
from apkforge.modification.modifiers.permission import PermissionModifier
from apkforge.modification.modifiers.registry import ModifierRegistry
from apkforge.modification.modifiers.resource import ResourceModifier
from apkforge.modification.modifiers.tracker import TrackerModifier
from apkforge.modification.framework import ModificationFramework


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_workspace(tmp_path):
    """Create a temp workspace directory."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture()
def sample_apk(tmp_path):
    """Create a minimal valid APK (ZIP) with an AndroidManifest.xml."""
    apk_path = tmp_path / "test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest />")
        zf.writestr("classes.dex", b"dex\n035\x00".decode("latin-1"))
    return apk_path


@pytest.fixture()
def sample_apk_sha256(sample_apk):
    """Compute SHA-256 of the sample APK."""
    h = hashlib.sha256()
    with open(sample_apk, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


@pytest.fixture()
def decoded_workspace(tmp_workspace):
    """Create a workspace with a decoded AndroidManifest.xml."""
    manifest = tmp_workspace / "AndroidManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    package="com.example.test">\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.CAMERA" />\n'
        '    <uses-permission android:name="android.permission.RECORD_AUDIO" />\n'
        "    <application\n"
        '        android:debuggable="true"\n'
        '        android:allowBackup="true"\n'
        '        android:usesCleartextTraffic="true">\n'
        '        <activity android:name="com.example.test.MainActivity"\n'
        '            android:exported="true" />\n'
        '        <service android:name="com.example.test.MyService"\n'
        '            android:exported="true" />\n'
        '        <receiver android:name="com.example.test.MyReceiver"\n'
        '            android:exported="true"\n'
        '            android:enabled="true" />\n'
        '        <provider android:name="com.example.test.MyProvider"\n'
        '            android:exported="true" />\n'
        "    </application>\n"
        "</manifest>\n",
        encoding="utf-8",
    )
    return tmp_workspace


@pytest.fixture()
def sample_plan(sample_apk, sample_apk_sha256):
    """Create a simple approved modification plan."""
    return ModificationPlan(
        plan_id="PLAN-TEST001",
        source_apk=str(sample_apk),
        source_sha256=sample_apk_sha256,
        created_at="2024-01-01T00:00:00Z",
        status=PlanStatus.APPROVED,
        changes=[
            PlannedChange(
                id="CHANGE-001",
                change_type=ChangeType.REMOVE_PERMISSION,
                target="android.permission.CAMERA",
                operation="Remove <uses-permission android:name='android.permission.CAMERA' />",
                reason="Unused permission",
                status=ChangeStatus.ACCEPTED,
                risk=ModificationRisk.LOW,
                reversibility=Reversibility.REVERSIBLE,
            ),
        ],
    )


@pytest.fixture()
def planned_change_remove_perm():
    """Create a PlannedChange for removing a permission."""
    return PlannedChange(
        id="CHANGE-001",
        change_type=ChangeType.REMOVE_PERMISSION,
        target="android.permission.CAMERA",
        operation="Remove <uses-permission android:name='android.permission.CAMERA' />",
        reason="Unused permission",
        status=ChangeStatus.ACCEPTED,
        risk=ModificationRisk.LOW,
        reversibility=Reversibility.REVERSIBLE,
    )


@pytest.fixture()
def planned_change_config():
    """Create a PlannedChange for modifying configuration."""
    return PlannedChange(
        id="CHANGE-002",
        change_type=ChangeType.MODIFY_CONFIGURATION,
        target="android:debuggable",
        operation="Set android:debuggable='false' on <application>",
        reason="Security hardening",
        status=ChangeStatus.ACCEPTED,
        risk=ModificationRisk.LOW,
        reversibility=Reversibility.REVERSIBLE,
    )


@pytest.fixture()
def planned_change_tracker():
    """Create a PlannedChange for removing a tracker."""
    return PlannedChange(
        id="CHANGE-003",
        change_type=ChangeType.REMOVE_TRACKER,
        target="Google AdMob",
        operation="Remove Google AdMob SDK",
        reason="Tracker removal",
        status=ChangeStatus.ACCEPTED,
        risk=ModificationRisk.MEDIUM,
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        evidence=[
            Evidence(
                description="AdMob package detected",
                location="dex:package",
                snippet="com/google/android/gms/ads",
            ),
        ],
    )


# ===========================================================================
# ModifierRegistry Tests
# ===========================================================================


class TestModifierRegistry:
    def test_register_and_lookup(self):
        registry = ModifierRegistry()
        modifier = ManifestModifier()
        registry.register(modifier)
        assert registry.has_modifier_for("remove_permission")
        assert registry.get_modifier("remove_permission") is modifier

    def test_get_modifier_returns_none_for_unknown(self):
        registry = ModifierRegistry()
        assert registry.get_modifier("unknown_type") is None

    def test_get_modifier_by_id(self):
        registry = ModifierRegistry()
        modifier = ManifestModifier()
        registry.register(modifier)
        assert registry.get_modifier_by_id("ManifestModifier") is modifier
        assert registry.get_modifier_by_id("NonexistentModifier") is None

    def test_registered_modifiers(self):
        registry = ModifierRegistry()
        registry.register(ManifestModifier())
        registry.register(TrackerModifier())
        assert len(registry.registered_modifiers) == 2

    def test_supported_change_types(self):
        registry = ModifierRegistry()
        registry.register(ManifestModifier())
        types = registry.supported_change_types
        assert "remove_permission" in types
        assert "modify_configuration" in types

    def test_default_registry_has_all_builtins(self):
        framework = ModificationFramework()
        reg = framework.registry
        assert reg.has_modifier_for("remove_permission")
        assert reg.has_modifier_for("remove_tracker")
        assert reg.has_modifier_for("dex_modification")
        assert reg.has_modifier_for("remove_resource")
        assert reg.has_modifier_for("remove_component")
        assert reg.has_modifier_for("remove_embedded_payload")


# ===========================================================================
# StepResult & ModificationResult Tests
# ===========================================================================


class TestModificationResult:
    def test_empty_result_defaults(self):
        result = ModificationResult(plan_id="P-1")
        assert result.total_steps == 0
        assert result.successful_steps == 0
        assert result.failed_steps == 0
        assert result.skipped_steps == 0
        # Nothing executed is not success (known-limitations §17).
        assert result.all_succeeded is False

    def test_step_counting(self):
        result = ModificationResult(
            plan_id="P-1",
            steps=[
                ModificationStepResult(
                    change_id="C-1",
                    modifier_id="M",
                    status=StepStatus.SUCCESS,
                ),
                ModificationStepResult(
                    change_id="C-2",
                    modifier_id="M",
                    status=StepStatus.FAILED,
                ),
                ModificationStepResult(
                    change_id="C-3",
                    modifier_id="M",
                    status=StepStatus.SKIPPED,
                ),
            ],
        )
        assert result.total_steps == 3
        assert result.successful_steps == 1
        assert result.failed_steps == 1
        assert result.skipped_steps == 1
        assert result.all_succeeded is False

    def test_all_succeeded_with_dry_run(self):
        result = ModificationResult(
            plan_id="P-1",
            steps=[
                ModificationStepResult(
                    change_id="C-1",
                    modifier_id="M",
                    status=StepStatus.DRY_RUN,
                ),
                ModificationStepResult(
                    change_id="C-2",
                    modifier_id="M",
                    status=StepStatus.SUCCESS,
                ),
            ],
        )
        assert result.all_succeeded is True


# ===========================================================================
# ModificationExecutionContext Tests
# ===========================================================================


class TestModificationExecutionContext:
    def test_create_copies_apk(self, sample_apk, tmp_workspace, sample_plan):
        ctx = ModificationExecutionContext.create(
            apk_path=sample_apk,
            plan=sample_plan,
            workspace_dir=tmp_workspace,
        )
        assert ctx.working_copy_path.exists()
        assert ctx.working_copy_path.name == sample_apk.name
        assert ctx.original_apk_path == sample_apk.resolve()
        assert not ctx.dry_run

    def test_create_with_dry_run(self, sample_apk, tmp_workspace, sample_plan):
        ctx = ModificationExecutionContext.create(
            apk_path=sample_apk,
            plan=sample_plan,
            workspace_dir=tmp_workspace,
            dry_run=True,
        )
        assert ctx.dry_run is True

    def test_verify_original_untouched(self, sample_apk, tmp_workspace, sample_plan):
        ctx = ModificationExecutionContext.create(
            apk_path=sample_apk,
            plan=sample_plan,
            workspace_dir=tmp_workspace,
        )
        assert ctx.verify_original_untouched() is True


# ===========================================================================
# ManifestModifier Tests
# ===========================================================================


class TestManifestModifier:
    def test_preflight_with_valid_apk(self, sample_apk, tmp_workspace, sample_plan):
        ctx = ModificationExecutionContext.create(
            apk_path=sample_apk,
            plan=sample_plan,
            workspace_dir=tmp_workspace,
        )
        modifier = ManifestModifier()
        change = sample_plan.changes[0]
        result = modifier.preflight(change, ctx)
        assert result.status == StepStatus.SUCCESS

    def test_preflight_with_missing_apk(self, tmp_workspace, sample_plan):
        missing = tmp_workspace / "nonexistent.apk"
        ctx = ModificationExecutionContext(
            original_apk_path=missing,
            workspace_dir=tmp_workspace,
            working_copy_path=missing,
            plan=sample_plan,
        )
        modifier = ManifestModifier()
        result = modifier.preflight(sample_plan.changes[0], ctx)
        assert result.status == StepStatus.FAILED

    def test_remove_permission(
        self, decoded_workspace, sample_apk, sample_plan, planned_change_remove_perm
    ):
        # Copy the sample APK to workspace as working copy
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ManifestModifier()
        result = modifier.apply(planned_change_remove_perm, ctx)

        assert result.status == StepStatus.SUCCESS
        assert "CAMERA" in result.message

        # Verify the permission was removed from the decoded manifest
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "android.permission.CAMERA" not in manifest
        assert "android.permission.INTERNET" in manifest  # other perms untouched

    def test_modify_configuration_debuggable(
        self, decoded_workspace, sample_apk, sample_plan, planned_change_config
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ManifestModifier()
        result = modifier.apply(planned_change_config, ctx)

        assert result.status == StepStatus.SUCCESS
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert 'android:debuggable="false"' in manifest

    def test_dry_run_does_not_write(
        self, decoded_workspace, sample_apk, sample_plan, planned_change_remove_perm
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
            dry_run=True,
        )
        modifier = ManifestModifier()
        result = modifier.apply(planned_change_remove_perm, ctx)

        assert result.status == StepStatus.DRY_RUN
        # Permission should still be present (not written)
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "android.permission.CAMERA" in manifest

    def test_modify_configuration_cleartext(
        self, decoded_workspace, sample_apk, sample_plan
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-CLR",
            change_type=ChangeType.MODIFY_CONFIGURATION,
            target="android:usesCleartextTraffic",
            operation="Set android:usesCleartextTraffic='false'",
            reason="Network hardening",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ManifestModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert 'android:usesCleartextTraffic="false"' in manifest

    def test_modify_configuration_backup(
        self, decoded_workspace, sample_apk, sample_plan
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-BKP",
            change_type=ChangeType.MODIFY_CONFIGURATION,
            target="android:allowBackup",
            operation="Set android:allowBackup='false'",
            reason="Data protection",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ManifestModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert 'android:allowBackup="false"' in manifest

    def test_rollback_restores_manifest(
        self, decoded_workspace, sample_apk, sample_plan, planned_change_remove_perm
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ManifestModifier()

        # Apply
        apply_result = modifier.apply(planned_change_remove_perm, ctx)
        assert apply_result.status == StepStatus.SUCCESS

        # Rollback
        rb_result = modifier.rollback(planned_change_remove_perm, ctx, apply_result)
        assert rb_result.status == StepStatus.ROLLED_BACK

        # Verify permission is restored
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "android.permission.CAMERA" in manifest


# ===========================================================================
# ComponentModifier Tests
# ===========================================================================


class TestComponentModifier:
    def test_disable_component(
        self, decoded_workspace, sample_apk, sample_plan
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-COMP-1",
            change_type=ChangeType.DISABLE_COMPONENT,
            target="com.example.test.MyReceiver",
            operation="Disable receiver",
            reason="Unneeded component",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ComponentModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert 'android:enabled="false"' in manifest

    def test_remove_component(
        self, decoded_workspace, sample_apk, sample_plan
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-COMP-2",
            change_type=ChangeType.REMOVE_COMPONENT,
            target="com.example.test.MyService",
            operation="Remove service",
            reason="Tracker-related service",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ComponentModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "com.example.test.MyService" not in manifest


# ===========================================================================
# ResourceModifier Tests
# ===========================================================================


class TestResourceModifier:
    def test_remove_resource(self, tmp_workspace, sample_apk, sample_plan):
        # Create a fake resource file
        res_file = tmp_workspace / "res" / "layout" / "tracker_layout.xml"
        res_file.parent.mkdir(parents=True)
        res_file.write_text("<LinearLayout />")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-RES-1",
            change_type=ChangeType.REMOVE_RESOURCE,
            target="res/layout/tracker_layout.xml",
            operation="Remove tracker layout",
            reason="Tracker resource",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ResourceModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        assert not res_file.exists()

    def test_remove_nonexistent_resource(self, tmp_workspace, sample_apk, sample_plan):
        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-RES-2",
            change_type=ChangeType.REMOVE_RESOURCE,
            target="res/layout/nonexistent.xml",
            operation="Remove",
            reason="Cleanup",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = ResourceModifier()
        result = modifier.apply(change, ctx)
        assert result.status == StepStatus.SKIPPED

    def test_dry_run_does_not_remove(self, tmp_workspace, sample_apk, sample_plan):
        res_file = tmp_workspace / "res" / "values" / "strings.xml"
        res_file.parent.mkdir(parents=True)
        res_file.write_text("<resources />")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-RES-3",
            change_type=ChangeType.REMOVE_RESOURCE,
            target="res/values/strings.xml",
            operation="Remove",
            reason="Test",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
            dry_run=True,
        )
        modifier = ResourceModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.DRY_RUN
        assert res_file.exists()  # Should still exist


# ===========================================================================
# TrackerModifier Tests
# ===========================================================================


class TestTrackerModifier:
    def test_tracker_removal_with_smali(
        self, tmp_workspace, sample_apk, sample_plan, planned_change_tracker
    ):
        # Create fake smali directory structure
        smali_dir = tmp_workspace / "smali" / "com" / "google" / "android" / "gms" / "ads"
        smali_dir.mkdir(parents=True)
        (smali_dir / "AdView.smali").write_text(".class public Lcom/google/android/gms/ads/AdView;")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = TrackerModifier()
        result = modifier.apply(planned_change_tracker, ctx)

        assert result.status == StepStatus.SUCCESS
        assert not smali_dir.exists()

    def test_tracker_dry_run(
        self, tmp_workspace, sample_apk, sample_plan, planned_change_tracker
    ):
        smali_dir = tmp_workspace / "smali" / "com" / "google" / "android" / "gms" / "ads"
        smali_dir.mkdir(parents=True)
        (smali_dir / "AdView.smali").write_text(".class public Ad;")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
            dry_run=True,
        )
        modifier = TrackerModifier()
        result = modifier.apply(planned_change_tracker, ctx)

        assert result.status == StepStatus.DRY_RUN
        assert smali_dir.exists()  # Not deleted in dry run


# ===========================================================================
# DexModifier Tests
# ===========================================================================


class TestDexModifier:
    def test_remove_class(self, tmp_workspace, sample_apk, sample_plan):
        # Create fake smali structure
        cls_path = tmp_workspace / "smali" / "com" / "malware" / "Backdoor.smali"
        cls_path.parent.mkdir(parents=True)
        cls_path.write_text(".class public Lcom/malware/Backdoor;")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-DEX-1",
            change_type=ChangeType.DEX_MODIFICATION,
            target="com.malware.Backdoor",
            operation="Remove class",
            reason="Suspicious class",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = DexModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        assert not cls_path.exists()

    def test_remove_package_directory(self, tmp_workspace, sample_apk, sample_plan):
        # Create package directory with multiple classes
        pkg_dir = tmp_workspace / "smali" / "com" / "tracker" / "sdk"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "Init.smali").write_text(".class Init;")
        (pkg_dir / "Event.smali").write_text(".class Event;")

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-DEX-2",
            change_type=ChangeType.DEX_MODIFICATION,
            target="com.tracker.sdk",
            operation="Remove package",
            reason="Tracker SDK",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = DexModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        assert not pkg_dir.exists()

    def test_preflight_no_smali(self, tmp_workspace, sample_apk, sample_plan):
        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-DEX-3",
            change_type=ChangeType.DEX_MODIFICATION,
            target="com.example.Class",
            operation="Remove",
            reason="Test",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = DexModifier()
        result = modifier.preflight(change, ctx)
        assert result.status == StepStatus.FAILED
        assert "smali" in result.message.lower()


# ===========================================================================
# PayloadModifier Tests
# ===========================================================================


class TestPayloadModifier:
    def test_remove_payload(self, tmp_workspace, sample_apk, sample_plan):
        # Create a fake embedded payload
        payload = tmp_workspace / "assets" / "suspicious.elf"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"\x7fELF" + b"\x00" * 100)

        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-PAY-1",
            change_type=ChangeType.REMOVE_EMBEDDED_PAYLOAD,
            target="assets/suspicious.elf",
            operation="Remove ELF payload",
            reason="Suspicious binary",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = PayloadModifier()
        result = modifier.apply(change, ctx)

        assert result.status == StepStatus.SUCCESS
        assert not payload.exists()

    def test_preflight_missing_payload(self, tmp_workspace, sample_apk, sample_plan):
        working = tmp_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        change = PlannedChange(
            id="CHANGE-PAY-2",
            change_type=ChangeType.REMOVE_EMBEDDED_PAYLOAD,
            target="assets/nonexistent.elf",
            operation="Remove",
            reason="Test",
            status=ChangeStatus.ACCEPTED,
        )

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=tmp_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = PayloadModifier()
        result = modifier.preflight(change, ctx)
        assert result.status == StepStatus.FAILED


# ===========================================================================
# PermissionModifier Tests
# ===========================================================================


class TestPermissionModifier:
    def test_remove_permission_delegation(
        self, decoded_workspace, sample_apk, sample_plan, planned_change_remove_perm
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        ctx = ModificationExecutionContext(
            original_apk_path=sample_apk,
            workspace_dir=decoded_workspace,
            working_copy_path=working,
            plan=sample_plan,
        )
        modifier = PermissionModifier()
        result = modifier.apply(planned_change_remove_perm, ctx)

        assert result.status == StepStatus.SUCCESS
        assert result.modifier_id == "PermissionModifier"
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "android.permission.CAMERA" not in manifest


# ===========================================================================
# ModificationFramework Tests
# ===========================================================================


class TestModificationFramework:
    def test_rejects_unapproved_plan(self, sample_apk, sample_apk_sha256, tmp_workspace):
        plan = ModificationPlan(
            plan_id="PLAN-UNAPPVD",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.REVIEW_REQUIRED,
            changes=[],
        )
        framework = ModificationFramework()
        result = framework.execute(plan, sample_apk, workspace_dir=tmp_workspace)

        assert result.status == StepStatus.FAILED
        assert "APPROVED" in result.errors[0]

    def test_detects_stale_plan(self, sample_apk, tmp_workspace):
        plan = ModificationPlan(
            plan_id="PLAN-STALE",
            source_apk=str(sample_apk),
            source_sha256="0" * 64,  # Wrong hash
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[],
        )
        framework = ModificationFramework()
        result = framework.execute(plan, sample_apk, workspace_dir=tmp_workspace)

        assert result.status == StepStatus.FAILED
        assert "STALE" in result.errors[0]

    def test_empty_accepted_changes(
        self, sample_apk, sample_apk_sha256, tmp_workspace
    ):
        plan = ModificationPlan(
            plan_id="PLAN-EMPTY",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.REMOVE_PERMISSION,
                    target="android.permission.CAMERA",
                    status=ChangeStatus.PROPOSED,  # Not accepted
                ),
            ],
        )
        framework = ModificationFramework()
        result = framework.execute(plan, sample_apk, workspace_dir=tmp_workspace)

        # Nothing executed: SKIPPED, not SUCCESS (known-limitations §17).
        assert result.status == StepStatus.SKIPPED
        assert "nothing to apply" in result.warnings[0].lower()

    def test_execute_with_decoded_workspace(
        self, sample_apk, sample_apk_sha256, decoded_workspace
    ):
        # Create APK copy in decoded workspace
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        plan = ModificationPlan(
            plan_id="PLAN-EXEC",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target="android:debuggable",
                    operation="Set android:debuggable='false'",
                    reason="Security hardening",
                    status=ChangeStatus.ACCEPTED,
                ),
            ],
        )
        framework = ModificationFramework()
        result = framework.execute(
            plan, sample_apk, workspace_dir=decoded_workspace
        )

        assert result.status == StepStatus.SUCCESS
        assert result.successful_steps == 1
        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert 'android:debuggable="false"' in manifest

    def test_dry_run_preserves_files(
        self, sample_apk, sample_apk_sha256, decoded_workspace
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        original_manifest = (decoded_workspace / "AndroidManifest.xml").read_text()

        plan = ModificationPlan(
            plan_id="PLAN-DRY",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target="android:debuggable",
                    operation="Set debuggable=false",
                    status=ChangeStatus.ACCEPTED,
                ),
            ],
        )
        framework = ModificationFramework()
        result = framework.execute(
            plan, sample_apk, workspace_dir=decoded_workspace, dry_run=True
        )

        assert result.status == StepStatus.DRY_RUN
        assert result.dry_run is True
        # Manifest should be unchanged
        current_manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert current_manifest == original_manifest

    def test_missing_modifier_fails_preflight(
        self, sample_apk, sample_apk_sha256, tmp_workspace
    ):
        plan = ModificationPlan(
            plan_id="PLAN-NOMOD",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.NATIVE_MODIFICATION,
                    target="lib/arm64-v8a/libnative.so",
                    operation="Patch native lib",
                    status=ChangeStatus.ACCEPTED,
                ),
            ],
        )
        framework = ModificationFramework()
        result = framework.execute(plan, sample_apk, workspace_dir=tmp_workspace)

        assert result.status == StepStatus.FAILED
        assert result.failed_steps >= 1

    def test_missing_apk_file(self, tmp_workspace, sample_apk_sha256):
        missing = tmp_workspace / "nonexistent.apk"
        plan = ModificationPlan(
            plan_id="PLAN-MISS",
            source_apk=str(missing),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[],
        )
        framework = ModificationFramework()
        result = framework.execute(plan, missing, workspace_dir=tmp_workspace)

        assert result.status == StepStatus.FAILED
        assert "not found" in result.errors[0].lower()

    def test_multi_change_execution(
        self, sample_apk, sample_apk_sha256, decoded_workspace
    ):
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        plan = ModificationPlan(
            plan_id="PLAN-MULTI",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.REMOVE_PERMISSION,
                    target="android.permission.CAMERA",
                    operation="Remove CAMERA permission",
                    status=ChangeStatus.ACCEPTED,
                ),
                PlannedChange(
                    id="CHANGE-002",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target="android:debuggable",
                    operation="Set debuggable=false",
                    status=ChangeStatus.ACCEPTED,
                ),
                PlannedChange(
                    id="CHANGE-003",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target="android:allowBackup",
                    operation="Set allowBackup=false",
                    status=ChangeStatus.ACCEPTED,
                ),
            ],
        )
        framework = ModificationFramework()
        result = framework.execute(
            plan, sample_apk, workspace_dir=decoded_workspace
        )

        assert result.status == StepStatus.SUCCESS
        assert result.total_steps == 3
        assert result.successful_steps == 3

        manifest = (decoded_workspace / "AndroidManifest.xml").read_text()
        assert "android.permission.CAMERA" not in manifest
        assert 'android:debuggable="false"' in manifest
        assert 'android:allowBackup="false"' in manifest

    def test_original_apk_never_modified(
        self, sample_apk, sample_apk_sha256, decoded_workspace
    ):
        """The most important invariant: original APK must remain unchanged."""
        working = decoded_workspace / sample_apk.name
        shutil.copy2(sample_apk, working)

        # Record original file content
        original_content = sample_apk.read_bytes()

        plan = ModificationPlan(
            plan_id="PLAN-SAFETY",
            source_apk=str(sample_apk),
            source_sha256=sample_apk_sha256,
            created_at="2024-01-01T00:00:00Z",
            status=PlanStatus.APPROVED,
            changes=[
                PlannedChange(
                    id="CHANGE-001",
                    change_type=ChangeType.REMOVE_PERMISSION,
                    target="android.permission.CAMERA",
                    status=ChangeStatus.ACCEPTED,
                ),
            ],
        )
        framework = ModificationFramework()
        framework.execute(plan, sample_apk, workspace_dir=decoded_workspace)

        # Original APK must be byte-for-byte identical
        assert sample_apk.read_bytes() == original_content

    def test_framework_registry_has_all_builtins(self):
        framework = ModificationFramework()
        reg = framework.registry
        expected_types = [
            "remove_permission",
            "modify_permission",
            "modify_component",
            "modify_manifest",
            "modify_configuration",
            "disable_component",
            "remove_tracker",
            "remove_ad_component",
            "dex_modification",
            "remove_resource",
            "remove_asset",
            "remove_component",
            "remove_embedded_payload",
        ]
        for ct in expected_types:
            assert reg.has_modifier_for(ct), f"Missing modifier for: {ct}"
