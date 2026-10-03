"""Phase E3: full manifest tree comparison and coverage by the specialised differs."""

from __future__ import annotations

from typing import Any

from apkforge.diff.expectations import observe
from apkforge.diff.manifest_tree import (
    ManifestTreeDiff,
    diff_manifest_trees,
    explained_by,
    parse_manifest_xml,
)
from apkforge.diff.models import (
    ChangeType,
    ComponentChange,
    ComponentDiff,
    DiffChange,
    IntentFilterDiff,
    ManifestDiff,
    PermissionDiff,
)
from tests.unit.test_c5_expectations import _diff

NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def _m(app: str = "", top: str = "") -> str:
    return (
        f'<manifest {NS} package="com.example" android:versionCode="1">'
        f'<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>{top}'
        f'<application android:allowBackup="true">{app}</application></manifest>'
    )


RECV = (
    '<receiver android:name="com.example.Boot" android:exported="true">'
    '<intent-filter android:priority="5">'
    '<action android:name="android.intent.action.BOOT_COMPLETED"/>'
    "</intent-filter></receiver>"
)


def _changes(a: str, b: str) -> list[Any]:
    return diff_manifest_trees(parse_manifest_xml(a), parse_manifest_xml(b))


class TestTree:
    def test_identical_trees_have_no_changes(self) -> None:
        assert _changes(_m(RECV), _m(RECV)) == []

    def test_keys_are_stable_and_named(self) -> None:
        t = parse_manifest_xml(_m(RECV))
        assert "application#0/receiver[name=com.example.Boot]/intent-filter#0" in t.elements
        key = (
            "application#0/receiver[name=com.example.Boot]/intent-filter#0/"
            "action[name=android.intent.action.BOOT_COMPLETED]"
        )
        assert key in t.elements

    def test_attribute_modification(self) -> None:
        ch = _changes(_m(RECV), _m(RECV.replace('exported="true"', 'exported="false"')))
        assert len(ch) == 1
        c = ch[0]
        assert c.kind == "modified" and c.attribute == "android:exported"
        assert (c.before, c.after) == ("true", "false")

    def test_added_subtree_reported_once_at_top(self) -> None:
        meta = '<meta-data android:name="k" android:value="v"/>'
        ch = _changes(_m(), _m(meta))
        assert [(c.kind, c.element) for c in ch] == [("added", "application#0/meta-data[name=k]")]
        assert ch[0].detail()["elements"] == 1 and len(ch[0].detail()["subtree_sha256"]) == 64

    def test_duplicate_identity_gets_occurrence_suffix(self) -> None:
        dup = '<meta-data android:name="k" android:value="1"/>' * 2
        t = parse_manifest_xml(_m(dup))
        assert {"application#0/meta-data[name=k]", "application#0/meta-data[name=k]~1"} <= set(
            t.elements
        )


def _tree(a: str, b: str) -> ManifestTreeDiff:
    return ManifestTreeDiff(status="complete", changes=_changes(a, b))


class TestExplanation:
    def test_uses_permission_removal_explained_by_permission_diff(self) -> None:
        perm = '<uses-permission android:name="android.permission.CAMERA"/>'
        tree = _tree(_m(top=perm), _m())
        d = _diff(
            manifest_tree=tree, permissions=PermissionDiff(removed=["android.permission.CAMERA"])
        )
        assert (
            explained_by(tree.changes[0], d) == "uses_permission removed android.permission.CAMERA"
        )
        assert not [o for o in observe(d) if o.category == "manifest_element"]

    def test_unreported_permission_change_is_residual(self) -> None:
        perm = '<uses-permission android:name="android.permission.CAMERA"/>'
        tree = _tree(_m(top=perm), _m())
        d = _diff(manifest_tree=tree)  # the permission differ reported nothing
        residual = [o for o in observe(d) if o.category == "manifest_element"]
        assert [(o.kind, o.identifier) for o in residual] == [
            ("removed", "uses-permission[name=android.permission.CAMERA]")
        ]

    def test_component_attribute_explained_only_for_that_attribute(self) -> None:
        after = RECV.replace('exported="true"', 'exported="true" android:enabled="false"')
        after = after.replace("<receiver ", '<receiver android:process=":x" ')
        tree = _tree(_m(RECV), _m(after))
        comp = ComponentChange(
            name="com.example.Boot",
            component_type="receiver",
            change_type=ChangeType.MODIFIED,
            exported_before=True,
            exported_after=True,
            enabled_before=None,
            enabled_after=False,
            details={"enabled_before": None, "enabled_after": False},
        )
        d = _diff(manifest_tree=tree, components=ComponentDiff(receivers=[comp]))
        by_attr = {c.attribute: explained_by(c, d) for c in tree.changes}
        assert by_attr["android:enabled"] is not None
        assert by_attr["android:process"] is None  # not reported by ComponentDiffer here

    def test_intent_filter_action_explained_but_priority_residual(self) -> None:
        after = RECV.replace(
            "</intent-filter>",
            '<action android:name="android.intent.action.MY_PACKAGE_REPLACED"/></intent-filter>',
        ).replace('android:priority="5"', 'android:priority="999"')
        tree = _tree(_m(RECV), _m(after))
        comp = ComponentChange(
            name="com.example.Boot",
            component_type="receiver",
            change_type=ChangeType.MODIFIED,
            intent_filter_diff=IntentFilterDiff(
                actions_added=["android.intent.action.MY_PACKAGE_REPLACED"]
            ),
        )
        d = _diff(manifest_tree=tree, components=ComponentDiff(receivers=[comp]))
        residual = {o.identifier for o in observe(d) if o.category == "manifest_element"}
        assert residual == {
            "application#0/receiver[name=com.example.Boot]/intent-filter#0@android:priority"
        }

    def test_activity_alias_is_never_explained(self) -> None:
        alias = '<activity-alias android:name="com.example.Alias" android:targetActivity=".Main"/>'
        tree = _tree(_m(), _m(alias))
        assert explained_by(tree.changes[0], _diff(manifest_tree=tree)) is None

    def test_application_attribute_explained_by_manifest_diff(self) -> None:
        tree = _tree(_m(), _m().replace('allowBackup="true"', 'allowBackup="false"'))
        d = _diff(
            manifest_tree=tree,
            manifest=ManifestDiff(
                attribute_changes=[
                    DiffChange(
                        change_type=ChangeType.MODIFIED,
                        category="manifest.application",
                        identifier="allowBackup",
                        before=True,
                        after=False,
                    )
                ]
            ),
        )
        assert explained_by(tree.changes[0], d) == "manifest_attribute allowBackup"

    def test_queries_and_meta_data_are_residual(self) -> None:
        q = '<queries><package android:name="org.example.browser"/></queries>'
        tree = _tree(_m(), _m(top=q))
        obs = [o for o in observe(_diff(manifest_tree=tree)) if o.category == "manifest_element"]
        assert [o.identifier for o in obs] == ["queries#0"]
