"""Comprehensive unit tests for the Phase 3 APK Diff Engine."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus
from apkforge.diff import ChangeType, DEXDiffer, DiffEngine, NetworkDiffer
from apkforge.inspection.models import (
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    EvidenceSource,
    FieldInfo,
    InspectionResult,
    MethodInfo,
    NetworkInspection,
    URLReference,
)
from tests.fixtures import create_synthetic_apk, generate_test_pkcs7_cert

runner = CliRunner()


def test_diff_engine_identity_and_different_package_name(tmp_path: Path) -> None:
    apk_a = tmp_path / "app_a.apk"
    apk_b = tmp_path / "app_b.apk"

    create_synthetic_apk(
        apk_a,
        package_name="com.example.original",
        version_name="1.0.0",
        version_code=100,
        min_sdk=21,
        target_sdk=30,
    )
    create_synthetic_apk(
        apk_b,
        package_name="com.example.modified",
        version_name="2.0.0",
        version_code=200,
        min_sdk=24,
        target_sdk=34,
    )

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    # 1. Identity status
    assert result.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL)
    assert result.identity.is_same_package is False

    # 2. Package changes
    assert result.identity.package_name_change is not None
    assert result.identity.package_name_change.before == "com.example.original"
    assert result.identity.package_name_change.after == "com.example.modified"

    # 3. Version changes
    assert result.identity.version_name_change is not None
    assert result.identity.version_name_change.before == "1.0.0"
    assert result.identity.version_name_change.after == "2.0.0"

    assert result.identity.version_code_change is not None
    assert result.identity.version_code_change.before == 100
    assert result.identity.version_code_change.after == 200

    # 4. Warning recorded for different package names
    assert any("Package identities differ" in w for w in result.warnings)


def test_diff_engine_permissions(tmp_path: Path) -> None:
    apk_a = tmp_path / "perm_a.apk"
    apk_b = tmp_path / "perm_b.apk"

    manifest_a = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.perms"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application android:label="PermTest" />
</manifest>"""

    manifest_b = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.perms"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <permission android:name="com.example.custom.SECRET" android:protectionLevel="signature" />
    <application android:label="PermTest" />
</manifest>"""

    with zipfile.ZipFile(apk_a, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_a)
    with zipfile.ZipFile(apk_b, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_b)

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    assert result.permissions.added == ["android.permission.RECORD_AUDIO"]
    assert result.permissions.removed == []
    assert result.permissions.unchanged == ["android.permission.READ_CONTACTS"]
    assert result.permissions.declared_added == ["com.example.custom.SECRET"]

    assert result.summary.permissions_added == 1
    assert result.summary.permissions_removed == 0


def test_diff_engine_components_and_intent_filters(tmp_path: Path) -> None:
    apk_a = tmp_path / "comp_a.apk"
    apk_b = tmp_path / "comp_b.apk"

    manifest_a = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.comps"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="CompApp" android:debuggable="false" android:allowBackup="true">
        <activity android:name="com.example.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name="com.example.OldService" android:exported="false" />
    </application>
</manifest>"""

    manifest_b = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.comps"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="CompApp" android:debuggable="true" android:allowBackup="false">
        <activity android:name="com.example.MainActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="https" android:host="app.example.com" />
            </intent-filter>
        </activity>
        <service android:name="com.example.NewService" android:exported="true" />
    </application>
</manifest>"""

    with zipfile.ZipFile(apk_a, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_a)
    with zipfile.ZipFile(apk_b, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_b)

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    # 1. Manifest attributes diff
    attrs = {c.identifier: (c.before, c.after) for c in result.manifest.attribute_changes}
    assert "debuggable" in attrs
    assert attrs["debuggable"] == (False, True)
    assert "allowBackup" in attrs
    assert attrs["allowBackup"] == (True, False)

    # 2. Activity diff
    act = next(a for a in result.components.activities if a.name == "com.example.MainActivity")
    assert act.change_type == ChangeType.MODIFIED
    assert act.exported_before is True
    assert act.exported_after is False
    assert act.intent_filter_diff is not None
    assert "android.intent.action.VIEW" in act.intent_filter_diff.actions_added

    # 3. Service diff
    svc_names = {s.name: s.change_type for s in result.components.services}
    assert svc_names.get("com.example.OldService") == ChangeType.REMOVED
    assert svc_names.get("com.example.NewService") == ChangeType.ADDED


def test_diff_engine_dex_differ_structured() -> None:
    # Test DEXDiffer directly with structured ClassInfo and MethodInfo
    differ = DEXDiffer()

    # Model A: Class1 (methods: onCreate, oldMethod), Class2
    cls1_a = ClassInfo(name="com.example.Class1", superclass="java.lang.Object")
    cls2_a = ClassInfo(name="com.example.Class2", superclass="java.lang.Object")
    methods_a = [
        MethodInfo(name="onCreate", class_name="com.example.Class1", return_type="void"),
        MethodInfo(name="oldMethod", class_name="com.example.Class1", return_type="int"),
    ]
    fields_a = [
        FieldInfo(name="token", class_name="com.example.Class1", type="Ljava/lang/String;"),
    ]
    dex_file_a = DEXFileInspection(
        path="classes.dex",
        size=1000,
        sha256="hash_a",
        inventory=DEXClassInventory(classes=[cls1_a, cls2_a], methods=methods_a, fields=fields_a),
        api_references=["android.os.Bundle"],
    )

    insp_a = InspectionResult(
        dex=DEXInspection(
            dex_files=[dex_file_a],
        )
    )

    # Model B: Class1 (methods: onCreate, newMethod), Class3 (added)
    cls1_b = ClassInfo(name="com.example.Class1", superclass="android.app.Activity")
    cls3_b = ClassInfo(name="com.example.Class3", superclass="java.lang.Object")
    methods_b = [
        MethodInfo(name="onCreate", class_name="com.example.Class1", return_type="void"),
        MethodInfo(name="newMethod", class_name="com.example.Class1", return_type="void"),
    ]
    fields_b = [
        FieldInfo(name="token", class_name="com.example.Class1", type="Ljava/lang/String;"),
        FieldInfo(name="secretKey", class_name="com.example.Class1", type="[B"),
    ]
    dex_file_b = DEXFileInspection(
        path="classes.dex",
        size=1200,
        sha256="hash_b",
        inventory=DEXClassInventory(classes=[cls1_b, cls3_b], methods=methods_b, fields=fields_b),
        api_references=["android.os.Bundle", "android.location.LocationManager"],
    )

    insp_b = InspectionResult(
        dex=DEXInspection(
            dex_files=[dex_file_b],
        )
    )

    diff = differ.diff(insp_a, insp_b)

    # 1. DEX file modified
    assert diff.dex_files_modified == ["classes.dex"]

    # 2. Classes added / removed
    assert diff.classes_added == ["com.example.Class3"]
    assert diff.classes_removed == ["com.example.Class2"]

    # 3. Class1 modified
    assert len(diff.classes_modified) == 1
    cm = diff.classes_modified[0]
    assert cm.class_name == "com.example.Class1"
    assert cm.superclass_before == "java.lang.Object"
    assert cm.superclass_after == "android.app.Activity"
    assert any("newMethod" in m for m in cm.methods_added)
    assert any("oldMethod" in m for m in cm.methods_removed)
    assert any("secretKey" in f for f in cm.fields_added)

    # 4. API references added
    assert "android.location.LocationManager" in diff.api_references_added


def test_diff_engine_network_differ() -> None:
    differ = NetworkDiffer()

    src = EvidenceSource(file="classes.dex", class_name="com.example.NetClient")
    url_a = URLReference(url="https://api.v1.old.com/auth", source=src)
    url_common = URLReference(url="https://api.common.com/health", source=src)
    url_b = URLReference(url="https://api.v2.new.com/telemetry", source=src)

    insp_a = InspectionResult(
        network=NetworkInspection(
            urls=[url_a, url_common],
            domains=[],
            ip_addresses=[],
        )
    )
    insp_b = InspectionResult(
        network=NetworkInspection(
            urls=[url_common, url_b],
            domains=[],
            ip_addresses=[],
        )
    )

    diff = differ.diff(insp_a, insp_b)

    urls_add = [u.url for u in diff.urls_added]
    urls_rem = [u.url for u in diff.urls_removed]
    assert urls_add == ["https://api.v2.new.com/telemetry"]
    assert urls_rem == ["https://api.v1.old.com/auth"]
    assert diff.urls_unchanged_count == 1
    assert diff.urls_added[0].source_class == "com.example.NetClient"


def test_diff_engine_native_libraries(tmp_path: Path) -> None:
    apk_a = tmp_path / "native_a.apk"
    apk_b = tmp_path / "native_b.apk"

    create_synthetic_apk(
        apk_a,
        native_abis=["arm64-v8a"],
    )
    # APK B adds armeabi-v7a and changes arm64-v8a file content
    extra_b = {
        "lib/arm64-v8a/libsample.so": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100,  # Modified size
    }
    create_synthetic_apk(
        apk_b,
        native_abis=["armeabi-v7a"],
        extra_files=extra_b,
    )

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    assert "armeabi-v7a" in result.native.abis_added
    assert any(lib.path == "lib/armeabi-v7a/libsample.so" for lib in result.native.libraries_added)
    assert any(lib.change_type == ChangeType.MODIFIED for lib in result.native.libraries_modified)


def test_diff_engine_certificates(tmp_path: Path) -> None:
    apk_a = tmp_path / "cert_a.apk"
    apk_b = tmp_path / "cert_b.apk"

    cert_bytes_a = generate_test_pkcs7_cert(common_name="Original Developer")
    cert_bytes_b = generate_test_pkcs7_cert(common_name="Modded Developer")

    extra_a = {"META-INF/CERT.RSA": cert_bytes_a}
    extra_b = {"META-INF/CERT.RSA": cert_bytes_b}

    create_synthetic_apk(apk_a, include_cert=False, extra_files=extra_a)
    create_synthetic_apk(apk_b, include_cert=False, extra_files=extra_b)

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    assert result.certificates.status == "CHANGED"
    assert result.summary.certificate_status == "CHANGED"
    assert any("Certificate: CHANGED" in line for line in result.summary.text_lines)


def test_diff_engine_files_and_summary_consistency(tmp_path: Path) -> None:
    apk_a = tmp_path / "mixed_a.apk"
    apk_b = tmp_path / "mixed_b.apk"

    files_a = {
        "assets/file_to_remove.txt": b"OLD_DATA",
        "assets/file_to_modify.txt": b"VERSION_1",
        "res/raw/file_stay.bin": b"CONSTANT_DATA",
    }
    files_b = {
        "assets/file_to_add.txt": b"NEW_DATA",
        "assets/file_to_modify.txt": b"VERSION_2_MODIFIED",
        "res/raw/file_stay.bin": b"CONSTANT_DATA",
    }

    create_synthetic_apk(apk_a, extra_files=files_a)
    create_synthetic_apk(apk_b, extra_files=files_b)

    engine = DiffEngine()
    result = engine.diff(apk_a, apk_b)

    # File-level checks
    assert result.files.total_added >= 1
    assert result.files.total_removed >= 1
    assert result.files.total_modified >= 1

    # Verify Summary counts match detailed lists
    assert result.summary.files_added == result.files.total_added
    assert result.summary.files_removed == result.files.total_removed
    assert result.summary.files_modified == result.files.total_modified
    assert result.summary.permissions_added == len(result.permissions.added)
    assert result.summary.permissions_removed == len(result.permissions.removed)
    assert result.summary.classes_added == len(result.dex.classes_added)
    assert result.summary.classes_removed == len(result.dex.classes_removed)


def test_diff_engine_determinism(tmp_path: Path) -> None:
    apk_a = tmp_path / "det_a.apk"
    apk_b = tmp_path / "det_b.apk"

    create_synthetic_apk(apk_a, dex_count=2, native_abis=["arm64-v8a"])
    create_synthetic_apk(apk_b, dex_count=2, native_abis=["arm64-v8a", "x86_64"])

    engine = DiffEngine()
    result1 = engine.diff(apk_a, apk_b)
    result2 = engine.diff(apk_a, apk_b)

    # Exact byte-for-byte JSON equivalence
    json1 = result1.model_dump_json(indent=2)
    json2 = result2.model_dump_json(indent=2)
    assert json1 == json2


def test_cli_diff_command_text_and_json(tmp_path: Path) -> None:
    apk_a = tmp_path / "cli_a.apk"
    apk_b = tmp_path / "cli_b.apk"

    create_synthetic_apk(apk_a, version_name="1.0.0")
    create_synthetic_apk(apk_b, version_name="1.1.0")

    # 1. Text format
    res_text = runner.invoke(app, ["diff", str(apk_a), str(apk_b), "--verbose"])
    assert res_text.exit_code == 0
    assert "APKForge Package Diff" in res_text.stdout
    assert "MODIFICATION SUMMARY" in res_text.stdout

    # 2. JSON format
    res_json = runner.invoke(app, ["diff", str(apk_a), str(apk_b), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert "identity" in data
    assert "summary" in data
    assert "permissions" in data
    assert "components" in data
    assert "files" in data
    assert data["apk_a"]["package_name"] == "com.apkforge.testapp"


def test_diff_engine_error_isolation(tmp_path: Path) -> None:
    valid_apk = tmp_path / "valid.apk"
    create_synthetic_apk(valid_apk)

    corrupt_apk = tmp_path / "corrupt.apk"
    corrupt_apk.write_bytes(b"NOT_A_VALID_ZIP")

    engine = DiffEngine()
    result = engine.diff(valid_apk, corrupt_apk)

    assert result.status == AnalysisStatus.FAILED
    assert any("Intake failed" in lim or "not a valid" in lim.lower() for lim in result.limitations)
