"""Regression tests: intent-filter extraction from the lxml tree Androguard returns.

Androguard's ``APK.get_android_manifest_xml()`` returns ``lxml.etree._Element``. The
inspector used to accept only ``xml.etree.ElementTree.Element`` and swallowed every error,
so real APKs had no intent filters at all (known-limitations §16). Synthetic test APKs use a
text manifest and take the ``xml.etree`` fallback path, which is why the existing tests did
not catch it. These tests drive the Androguard path with a real lxml tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from lxml import etree

from apkforge.core.models import AnalysisStatus
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.manifest import ManifestInspector
from tests.fixtures import create_synthetic_apk

if TYPE_CHECKING:
    from pathlib import Path

NS = "{http://schemas.android.com/apk/res/android}"

MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.lxml">
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <application android:label="lxml">
        <activity android:name=".ui.LinkActivity" android:exported="true">
            <!-- comment nodes are children in lxml and must be skipped -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com"
                    android:pathPrefix="/open" />
            </intent-filter>
        </activity>
        <activity android:name=".ui.PlainActivity" android:exported="false" />
        <service android:name="com.example.lxml.SyncService" android:exported="true">
            <intent-filter>
                <action android:name="android.content.SyncAdapter" />
            </intent-filter>
        </service>
        <receiver android:name="BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="package" />
                <data android:mimeType="text/plain" />
            </intent-filter>
            <intent-filter>
                <action android:name="com.example.lxml.SECOND" />
            </intent-filter>
        </receiver>
        <receiver android:name="com.example.lxml.media.MediaButtonReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MEDIA_BUTTON" />
            </intent-filter>
            <intent-filter>
                <action android:name="com.example.lxml.NOTIFY" />
            </intent-filter>
        </receiver>
        <receiver android:name="androidx.media3.session.MediaButtonReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MEDIA_BUTTON" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""


class _LxmlBackedAPK:
    """Stand-in for ``androguard.core.apk.APK`` backed by a real lxml manifest tree.

    Component names are resolved the way Androguard resolves them (fully qualified).
    """

    def __init__(self, _path: str) -> None:
        self._xml = etree.fromstring(MANIFEST)
        self._package = self._xml.get("package")

    def _resolve(self, name: str) -> str:
        if name.startswith("."):
            return self._package + name
        return name if "." in name else f"{self._package}.{name}"

    def _components(self, tag: str) -> list[str]:
        app = self._xml.find("application")
        return [self._resolve(e.get(f"{NS}name")) for e in app.findall(tag)]

    def is_valid_APK(self) -> bool:
        return True

    def get_package(self) -> str:
        return self._package

    def get_android_manifest_xml(self) -> etree._Element:
        return self._xml

    def get_permissions(self) -> list[str]:
        return [e.get(f"{NS}name") for e in self._xml.findall("uses-permission")]

    def get_declared_permissions(self) -> list[str]:
        return []

    def get_activities(self) -> list[str]:
        return self._components("activity")

    def get_services(self) -> list[str]:
        return self._components("service")

    def get_receivers(self) -> list[str]:
        return self._components("receiver")

    def get_providers(self) -> list[str]:
        return []

    def get_attribute_value(self, tag: str, attribute: str, name: str | None = None) -> str | None:
        for e in self._xml.iter(tag):
            if name is None or self._resolve(e.get(f"{NS}name")) == name:
                return e.get(f"{NS}{attribute}")
        return None


@pytest.fixture()
def lxml_apk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr("androguard.core.apk.APK", _LxmlBackedAPK)
    apk = tmp_path / "lxml.apk"
    apk.write_bytes(b"not read: APK is replaced")
    return apk


def test_fixture_tree_is_real_lxml() -> None:
    tree = _LxmlBackedAPK("x").get_android_manifest_xml()
    assert type(tree) is etree._Element
    assert type(tree.find("application")) is etree._Element


def test_activity_filters_extracted_from_lxml(lxml_apk: Path) -> None:
    result, warnings = ManifestInspector().inspect(lxml_apk)

    assert warnings == []
    acts = {a.name: a for a in result.activities}
    link = acts["com.example.lxml.ui.LinkActivity"]
    assert len(link.intent_filters) == 1
    f = link.intent_filters[0]
    assert f.actions == ["android.intent.action.VIEW"]
    assert f.categories == ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"]
    assert len(f.data) == 1
    assert (f.data[0].scheme, f.data[0].host, f.data[0].path_prefix) == (
        "https",
        "example.com",
        "/open",
    )
    # A component without filters is still an empty list, with no warning.
    assert acts["com.example.lxml.ui.PlainActivity"].intent_filters == []


def test_service_filters_extracted_from_lxml(lxml_apk: Path) -> None:
    result, warnings = ManifestInspector().inspect(lxml_apk)

    assert warnings == []
    (svc,) = result.services
    assert svc.name == "com.example.lxml.SyncService"
    assert [f.actions for f in svc.intent_filters] == [["android.content.SyncAdapter"]]


def test_receiver_filters_with_actions_categories_and_data(lxml_apk: Path) -> None:
    result, warnings = ManifestInspector().inspect(lxml_apk)

    assert warnings == []
    recs = {r.name: r for r in result.receivers}
    boot = recs["com.example.lxml.BootReceiver"]
    assert len(boot.intent_filters) == 2
    first = boot.intent_filters[0]
    assert first.actions == [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.MY_PACKAGE_REPLACED",
    ]
    assert first.categories == ["android.intent.category.DEFAULT"]
    assert [(d.scheme, d.mime_type) for d in first.data] == [
        ("package", None),
        (None, "text/plain"),
    ]
    assert boot.intent_filters[1].actions == ["com.example.lxml.SECOND"]


def test_receivers_sharing_a_simple_class_name_keep_their_own_filters(lxml_apk: Path) -> None:
    result, _ = ManifestInspector().inspect(lxml_apk)

    recs = {r.name: r for r in result.receivers}
    app_rec = recs["com.example.lxml.media.MediaButtonReceiver"]
    lib_rec = recs["androidx.media3.session.MediaButtonReceiver"]
    assert [f.actions for f in app_rec.intent_filters] == [
        ["android.intent.action.MEDIA_BUTTON"],
        ["com.example.lxml.NOTIFY"],
    ]
    assert [f.actions for f in lib_rec.intent_filters] == [["android.intent.action.MEDIA_BUTTON"]]


def test_extraction_failure_is_recorded_not_swallowed(
    lxml_apk: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: ManifestInspector, component_xml: object) -> list[object]:
        raise ValueError("malformed intent-filter")

    monkeypatch.setattr(ManifestInspector, "_extract_intent_filters", boom)
    result, warnings = ManifestInspector().inspect(lxml_apk)

    # Components are still reported; every failed extraction carries its reason.
    assert len(result.activities) == 2
    assert len(warnings) == len(result.activities) + len(result.services) + len(result.receivers)
    assert (
        "intent-filter extraction failed for receiver com.example.lxml.BootReceiver: "
        "ValueError: malformed intent-filter"
    ) in warnings


def test_extraction_failure_makes_manifest_inspection_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = create_synthetic_apk(tmp_path / "partial.apk", package_name="com.test.partial")

    control = InspectionEngine().inspect(apk, enabled_inspectors={"manifest"})
    assert control.inspector_statuses["manifest"] == "complete"

    def boom(self: ManifestInspector, component_xml: object) -> list[object]:
        raise RuntimeError("element API unavailable")

    monkeypatch.setattr(ManifestInspector, "_extract_intent_filters", boom)
    result = InspectionEngine().inspect(apk, enabled_inspectors={"manifest"})

    assert result.inspector_statuses["manifest"] == "partial"
    assert result.status == AnalysisStatus.PARTIAL
    assert any(
        w.startswith("intent-filter extraction failed for activity")
        and "RuntimeError: element API unavailable" in w
        for w in result.warnings
    )
