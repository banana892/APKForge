"""Unit tests for Phase 2 inspection data models."""

from __future__ import annotations

import json

from apkforge.core.models import AnalysisStatus
from apkforge.inspection.models import (
    ActivityInfo,
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    DomainReference,
    EmbeddedAPKInfo,
    EmbeddedDEXInfo,
    EmbeddedFileInspection,
    EvidenceSource,
    ExecutableFileInfo,
    FieldInfo,
    InspectionResult,
    IntentDataInfo,
    IntentFilterInfo,
    IPAddressReference,
    ManifestInspection,
    MethodInfo,
    NativeInspection,
    NativeLibraryInspection,
    NativeStringReference,
    NetworkInspection,
    ObfuscationIndicators,
    ObfuscationInspection,
    PackageInventory,
    PermissionInfo,
    URLReference,
)
from apkforge.intake import PackageType


def test_permission_model() -> None:
    perm = PermissionInfo(name="android.permission.CAMERA", protection_level="dangerous")
    assert perm.name == "android.permission.CAMERA"
    assert perm.protection_level == "dangerous"


def test_intent_filter_and_components() -> None:
    data = IntentDataInfo(scheme="https", host="example.com", path_prefix="/auth")
    intent_filter = IntentFilterInfo(
        actions=["android.intent.action.VIEW"],
        categories=["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
        data=[data],
    )
    activity = ActivityInfo(
        name="com.example.MainActivity",
        exported=True,
        intent_filters=[intent_filter],
    )
    assert activity.exported is True
    assert len(activity.intent_filters) == 1
    assert activity.intent_filters[0].actions == ["android.intent.action.VIEW"]
    assert activity.intent_filters[0].data[0].host == "example.com"


def test_dex_models() -> None:
    field = FieldInfo(
        class_name="com.example.MainActivity",
        name="tag",
        type="Ljava/lang/String;",
        access_flags="public static final",
    )
    method = MethodInfo(
        class_name="com.example.MainActivity",
        name="onCreate",
        return_type="V",
        parameters=["Landroid/os/Bundle;"],
        access_flags="protected",
    )
    cls_info = ClassInfo(
        name="com.example.MainActivity",
        superclass="android.app.Activity",
        interfaces=["android.view.View$OnClickListener"],
        methods=[method],
        fields=[field],
    )
    dex_file = DEXFileInspection(
        path="classes.dex",
        size=1024,
        sha256="abc" * 20 + "abcd",
        class_count=1,
        method_count=1,
        field_count=1,
        inventory=DEXClassInventory(classes=[cls_info]),
    )
    dex_insp = DEXInspection(
        dex_files=[dex_file],
        total_classes=1,
        total_methods=1,
        total_fields=1,
    )
    assert dex_insp.total_classes == 1
    assert dex_insp.dex_files[0].inventory.classes[0].name == "com.example.MainActivity"


def test_native_models() -> None:
    native_lib = NativeLibraryInspection(
        path="lib/arm64-v8a/libnative.so",
        size=4096,
        sha256="123" * 21 + "1",
        abi="arm64-v8a",
        elf_class="ELF64",
        endianness="little-endian",
        machine_type="AArch64",
        sections=[".text", ".data", ".rodata"],
        dynamic_dependencies=["libc.so", "libm.so"],
        exported_symbols=["Java_com_example_Native_call"],
        strings=[
            NativeStringReference(
                library="libnative.so",
                offset=100,
                value="Hello from C++",
            )
        ],
    )
    native_insp = NativeInspection(
        libraries=[native_lib],
        total_libraries=1,
        abis_found=["arm64-v8a"],
    )
    assert native_insp.total_libraries == 1
    assert native_insp.abis_found == ["arm64-v8a"]
    assert len(native_insp.libraries[0].strings) == 1


def test_network_models() -> None:
    src = EvidenceSource(file="classes.dex", class_name="com.example.API")
    url_ref = URLReference(url="https://api.example.com/v1", source=src)
    dom_ref = DomainReference(domain="api.example.com", source=src)
    ip_ref = IPAddressReference(address="192.0.2.1", version=4, sources=[src])

    net_insp = NetworkInspection(
        urls=[url_ref],
        domains=[dom_ref],
        ip_addresses=[ip_ref],
    )
    assert len(net_insp.urls) == 1
    assert net_insp.urls[0].url == "https://api.example.com/v1"
    assert net_insp.domains[0].domain == "api.example.com"
    assert net_insp.ip_addresses[0].address == "192.0.2.1"


def test_embedded_models() -> None:
    emb_apk = EmbeddedAPKInfo(path="assets/payload.apk", size=1000, sha256="aaa")
    emb_dex = EmbeddedDEXInfo(path="assets/secondary.dex", size=500, sha256="bbb")
    emb_bin = ExecutableFileInfo(path="assets/root_script.sh", size=100, detected_type="script")

    emb_insp = EmbeddedFileInspection(
        embedded_apks=[emb_apk],
        embedded_dex=[emb_dex],
        executable_files=[emb_bin],
    )
    assert len(emb_insp.embedded_apks) == 1
    assert len(emb_insp.embedded_dex) == 1
    assert len(emb_insp.executable_files) == 1


def test_obfuscation_models() -> None:
    ind = ObfuscationIndicators(
        short_class_name_pct=75.5,
        short_method_name_pct=60.0,
        short_field_name_pct=80.0,
        total_classes_sampled=100,
        observations=["High ratio of single-character class names."],
    )
    obf = ObfuscationInspection(indicators=ind, is_likely_obfuscated=True)
    assert obf.is_likely_obfuscated is True
    assert obf.indicators.short_class_name_pct == 75.5


def test_inspection_result_json_roundtrip() -> None:
    res = InspectionResult(
        status=AnalysisStatus.COMPLETE,
        package_type=PackageType.APK,
        inventory=PackageInventory(
            manifest_count=1,
            dex_count=1,
            native_library_count=1,
            resource_count=10,
            asset_count=2,
            certificate_count=1,
            total_file_count=15,
        ),
        manifest=ManifestInspection(package_name="com.test.roundtrip", version_name="1.0"),
        inspector_statuses={"manifest": "complete", "dex": "complete"},
    )

    json_str = res.model_dump_json()
    data = json.loads(json_str)

    assert data["status"] == "complete"
    assert data["package_type"] == "apk"
    assert data["manifest"]["package_name"] == "com.test.roundtrip"
    assert data["inventory"]["resource_count"] == 10
    assert data["inspector_statuses"]["manifest"] == "complete"
