"""C.5 boot-receiver modifier: discovery, planning, refusal and exact manifest edits."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apkforge.modification.boot_receiver import (
    BOOT_PERMISSION,
    PlanStatus,
    apply_plan,
    discover,
    manifest_edits,
    plan_disable_boot_receiver,
)

if TYPE_CHECKING:
    from pathlib import Path

PKG = "com.example.app"
BOOT_RX = "com.example.app.conf.BootReceiver"
OTHER_RX = "androidx.profileinstaller.ProfileInstallReceiver"


def manifest(
    *,
    permission: bool = True,
    boot_enabled: str | None = 'android:enabled="true" ',
    boot_name: str = BOOT_RX,
    second_boot: bool = False,
    sdk23: bool = False,
) -> str:
    perm = f'    <uses-permission android:name="{BOOT_PERMISSION}"/>\n' if permission else ""
    if sdk23:
        perm += f'    <uses-permission-sdk-23 android:name="{BOOT_PERMISSION}"/>\n'
    second = (
        '        <receiver android:exported="false" android:name=".Second">\n'
        "            <intent-filter>\n"
        '                <action android:name="android.intent.action.LOCKED_BOOT_COMPLETED"/>\n'
        "            </intent-filter>\n"
        "        </receiver>\n"
        if second_boot
        else ""
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        f'package="{PKG}">\n'
        f"{perm}"
        '    <uses-permission android:name="android.permission.INTERNET"/>\n'
        '    <application android:label="@string/app_name">\n'
        '        <activity android:exported="true" android:name=".Main"/>\n'
        f'        <receiver {boot_enabled or ""}android:exported="true" android:name="{boot_name}">\n'  # noqa: E501
        "            <intent-filter>\n"
        '                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n'
        '                <action android:name="android.intent.action.MY_PACKAGE_REPLACED"/>\n'
        "            </intent-filter>\n"
        "        </receiver>\n"
        f"{second}"
        f'        <receiver android:enabled="true" android:exported="true" android:name="{OTHER_RX}" '  # noqa: E501
        'android:permission="android.permission.DUMP">\n'
        "            <intent-filter>\n"
        '                <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>\n'  # noqa: E501
        "            </intent-filter>\n"
        "        </receiver>\n"
        "    </application>\n"
        "</manifest>\n"
    )


def _plan(xml: str, receiver: str | None = None):
    return plan_disable_boot_receiver(
        discover(xml), target_apk="app.apk", target_sha256="0" * 64, receiver=receiver
    )


class TestDiscovery:
    def test_finds_permission_and_boot_receiver_only(self) -> None:
        d = discover(manifest())
        assert d.package == PKG
        assert d.permission_declarations == ["uses-permission"]
        assert set(d.receivers) == {BOOT_RX, OTHER_RX}
        (rx,) = d.boot_receivers
        assert rx.name == BOOT_RX and rx.enabled_raw == "true"
        assert rx.boot_actions == ["android.intent.action.BOOT_COMPLETED"]
        assert rx.other_actions == ["android.intent.action.MY_PACKAGE_REPLACED"]

    def test_relative_receiver_name_is_resolved(self) -> None:
        (rx,) = discover(manifest(boot_name=".conf.BootReceiver")).boot_receivers
        assert rx.name == BOOT_RX and rx.raw_name == ".conf.BootReceiver"


class TestPlanning:
    def test_ready_plan_declares_edits_and_expectations(self) -> None:
        plan = _plan(manifest())
        assert plan.status == PlanStatus.READY and plan.receiver == BOOT_RX
        assert all(p.satisfied for p in plan.preconditions)
        assert [(e.kind, e.attribute, e.before, e.after) for e in plan.source_edits] == [
            ("remove_element", None, None, None),
            ("set_attribute", "android:enabled", "true", "false"),
        ]
        assert [(e.category, e.kind, e.identifier, e.detail) for e in plan.expected_changes] == [
            ("uses_permission", "removed", BOOT_PERMISSION, {}),
            (
                "component",
                "modified",
                BOOT_RX,
                {"component_type": "receiver", "enabled": [True, False]},
            ),
        ]
        assert any("MY_PACKAGE_REPLACED" in c for c in plan.consequences)
        assert plan.limitations

    def test_absent_enabled_attribute_expects_none_to_false(self) -> None:
        plan = _plan(manifest(boot_enabled=None))
        assert plan.ready
        assert plan.expected_changes[1].detail["enabled"] == [None, False]

    def test_missing_permission_refused(self) -> None:
        plan = _plan(manifest(permission=False))
        assert plan.status == PlanStatus.TARGET_MISSING
        assert not plan.source_edits and not plan.expected_changes

    def test_missing_boot_receiver_refused(self) -> None:
        xml = manifest().replace("android.intent.action.BOOT_COMPLETED", "a.b.SOMETHING_ELSE")
        plan = _plan(xml)
        assert plan.status == PlanStatus.TARGET_MISSING and plan.receiver is None
        assert not plan.source_edits

    def test_multiple_boot_receivers_are_ambiguous(self) -> None:
        plan = _plan(manifest(second_boot=True))
        assert plan.status == PlanStatus.AMBIGUOUS_TARGET and not plan.source_edits
        assert "com.example.app.Second" in plan.problems[0]

    def test_explicit_receiver_resolves_ambiguity(self) -> None:
        plan = _plan(manifest(second_boot=True), receiver="com.example.app.Second")
        assert plan.ready and plan.receiver == "com.example.app.Second"

    def test_explicit_non_boot_receiver_refused(self) -> None:
        plan = _plan(manifest(), receiver=OTHER_RX)
        assert plan.status == PlanStatus.TARGET_MISSING

    @pytest.mark.parametrize(
        ("enabled", "reason"),
        [
            ('android:enabled="false" ', "already disabled"),
            ('android:enabled="@bool/x" ', "cannot be evaluated"),
        ],
    )
    def test_unsupported_receiver_state(self, enabled: str, reason: str) -> None:
        plan = _plan(manifest(boot_enabled=enabled))
        assert plan.status == PlanStatus.UNSUPPORTED and reason in plan.problems[0]

    def test_sdk23_declaration_unsupported(self) -> None:
        assert _plan(manifest(sdk23=True)).status == PlanStatus.UNSUPPORTED

    def test_first_refusal_wins(self) -> None:
        plan = _plan(manifest(permission=False, boot_enabled='android:enabled="false" '))
        assert plan.status == PlanStatus.TARGET_MISSING and len(plan.problems) == 2


class TestApply:
    def test_exact_manifest_transformation(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        original = manifest()
        path.write_text(original)
        res = apply_plan(_plan(original), path)
        assert res.applied and res.matches_plan, res.errors
        after = path.read_text()
        removed = [line for line in original.splitlines() if line not in after.splitlines()]
        added = [line for line in after.splitlines() if line not in original.splitlines()]
        assert removed == [
            f'    <uses-permission android:name="{BOOT_PERMISSION}"/>',
            f'        <receiver android:enabled="true" android:exported="true" android:name="{BOOT_RX}">',  # noqa: E501
        ]
        assert added == [
            f'        <receiver android:enabled="false" android:exported="true" android:name="{BOOT_RX}">'  # noqa: E501
        ]
        # The unrelated receiver and the other permission are untouched.
        assert f'android:enabled="true" android:exported="true" android:name="{OTHER_RX}"' in after
        assert "android.permission.INTERNET" in after

    def test_adds_enabled_attribute_when_absent(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        original = manifest(boot_enabled=None)
        path.write_text(original)
        res = apply_plan(_plan(original), path)
        assert res.applied, res.errors
        assert (
            f'<receiver android:enabled="false" android:exported="true" android:name="{BOOT_RX}">'
            in path.read_text()
        )

    def test_only_selected_receiver_changes(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        original = manifest(second_boot=True)
        path.write_text(original)
        res = apply_plan(_plan(original, receiver=BOOT_RX), path)
        assert res.applied, res.errors
        edits = manifest_edits(original, path.read_text())
        assert {e.element for e in edits} == {
            f"manifest/uses-permission[name={BOOT_PERMISSION}]",
            f"manifest/application[0]/receiver[name={BOOT_RX}]",
        }

    def test_refused_plan_leaves_manifest_untouched(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        original = manifest(permission=False)
        path.write_text(original)
        res = apply_plan(_plan(original), path)
        assert not res.applied and path.read_text() == original

    def test_stale_plan_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        plan = _plan(manifest())
        path.write_text(manifest().replace("INTERNET", "CAMERA"))
        res = apply_plan(plan, path)
        assert not res.applied and "stale" in res.errors[0]

    def test_edit_not_matching_plan_is_reverted(self, tmp_path: Path) -> None:
        path = tmp_path / "AndroidManifest.xml"
        original = manifest()
        path.write_text(original)
        plan = _plan(original)
        plan.source_edits[1].after = "maybe"  # plan no longer describes what the edit does
        res = apply_plan(plan, path)
        assert not res.applied and not res.matches_plan
        assert path.read_text() == original

    def test_manifest_edits_detects_any_structural_change(self) -> None:
        a = manifest()
        b = a.replace("MY_PACKAGE_REPLACED", "PACKAGE_ADDED")
        edits = manifest_edits(a, b)
        assert [e.kind for e in edits] == ["remove_element", "add_element"]
