"""Unit tests for ManifestInspector."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkforge.inspection.manifest import ManifestInspector
from apkforge.intake import AndroidPackage, APKMetadata, InputFormat, PackageType


def test_manifest_inspector_with_full_components(tmp_path: Path) -> None:
    apk_path = tmp_path / "manifest_test.apk"

    manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fullapp"
    android:versionCode="42"
    android:versionName="3.1.4">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

    <permission android:name="com.example.custom.PERMISSION"
        android:protectionLevel="signature" />

    <application
        android:label="Full App"
        android:debuggable="true"
        android:allowBackup="false"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data
                    android:scheme="https"
                    android:host="app.example.com"
                    android:pathPrefix="/deep" />
            </intent-filter>
        </activity>

        <service android:name=".SyncService"
            android:exported="false"
            android:permission="android.permission.BIND_JOB_SERVICE" />

        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <provider android:name=".DataProvider"
            android:authorities="com.example.fullapp.provider"
            android:exported="false"
            android:readPermission="com.example.READ"
            android:writePermission="com.example.WRITE"
            android:grantUriPermissions="true" />

    </application>
</manifest>"""

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)

    inspector = ManifestInspector()
    result, _warnings = inspector.inspect(apk_path)

    assert result.package_name == "com.example.fullapp"
    assert result.version_code == 42
    assert result.version_name == "3.1.4"
    assert result.min_sdk == 21
    assert result.target_sdk == 33

    # Permissions
    perm_names = [p.name for p in result.permissions]
    assert "android.permission.INTERNET" in perm_names
    assert "android.permission.ACCESS_FINE_LOCATION" in perm_names

    # Custom declared permission
    custom_perms = [
        p for p in result.declared_permissions if p.name == "com.example.custom.PERMISSION"
    ]
    assert len(custom_perms) == 1
    assert custom_perms[0].protection_level == "signature"

    # Application attributes
    assert result.application.label == "Full App"
    assert result.application.debuggable is True
    assert result.application.allow_backup is False
    assert result.application.uses_cleartext_traffic is True
    assert result.application.network_security_config == "@xml/network_security_config"

    # Activities
    assert len(result.activities) == 1
    main_act = result.activities[0]
    assert main_act.name.endswith("MainActivity")
    assert main_act.exported is True
    assert len(main_act.intent_filters) == 2

    # Intent filter check
    view_filter = next(
        f for f in main_act.intent_filters if "android.intent.action.VIEW" in f.actions
    )
    assert "android.intent.category.BROWSABLE" in view_filter.categories
    assert len(view_filter.data) == 1
    assert view_filter.data[0].scheme == "https"
    assert view_filter.data[0].host == "app.example.com"
    assert view_filter.data[0].path_prefix == "/deep"

    # Services
    assert len(result.services) == 1
    sync_srv = result.services[0]
    assert sync_srv.name.endswith("SyncService")
    assert sync_srv.exported is False
    assert sync_srv.permission == "android.permission.BIND_JOB_SERVICE"

    # Receivers
    assert len(result.receivers) == 1
    boot_rcv = result.receivers[0]
    assert boot_rcv.name.endswith("BootReceiver")
    assert boot_rcv.exported is True
    assert boot_rcv.intent_filters[0].actions == ["android.intent.action.BOOT_COMPLETED"]

    # Providers
    assert len(result.providers) == 1
    data_prv = result.providers[0]
    assert data_prv.name.endswith("DataProvider")
    assert data_prv.authorities == "com.example.fullapp.provider"
    assert data_prv.exported is False
    assert data_prv.read_permission == "com.example.READ"
    assert data_prv.write_permission == "com.example.WRITE"
    assert data_prv.grant_uri_permissions is True


def test_manifest_inspector_reuses_phase1_package(tmp_path: Path) -> None:
    apk_path = tmp_path / "reuse_test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml",
            b'<manifest package="com.test.reuse"><application/></manifest>',
        )

    pkg = AndroidPackage(
        input_path=apk_path,
        package_type=PackageType.APK,
        input_format=InputFormat.SINGLE_APK,
        metadata=APKMetadata(
            package_name="com.test.reuse",
            version_name="9.9.9",
            version_code=999,
            min_sdk=24,
            target_sdk=34,
        ),
    )

    inspector = ManifestInspector()
    result, _warnings = inspector.inspect(apk_path, package=pkg)

    assert result.package_name == "com.test.reuse"
    assert result.version_name == "9.9.9"
    assert result.version_code == 999
    assert result.min_sdk == 24
    assert result.target_sdk == 34
