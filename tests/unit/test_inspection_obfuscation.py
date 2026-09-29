"""Unit tests for ObfuscationInspector."""

from __future__ import annotations

from apkforge.inspection.models import (
    ClassInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    FieldInfo,
    MethodInfo,
)
from apkforge.inspection.obfuscation import ObfuscationInspector


def test_obfuscation_inspector_with_normal_names() -> None:
    c1_name = "com.example.service.AuthenticationManager"
    c2_name = "com.example.network.HttpRestClient"
    classes = [
        ClassInfo(name=c1_name),
        ClassInfo(name=c2_name),
    ]
    methods = [
        MethodInfo(class_name=c1_name, name="authenticateUser"),
        MethodInfo(class_name=c1_name, name="validateSessionToken"),
        MethodInfo(class_name=c2_name, name="sendHttpRequest"),
        MethodInfo(class_name=c2_name, name="parseJsonResponse"),
    ]
    fields = [
        FieldInfo(class_name=c1_name, name="currentUserSession", type="Ljava/lang/String;"),
        FieldInfo(class_name=c2_name, name="connectionTimeout", type="I"),
    ]

    dex_insp = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1024,
                sha256="abc",
                inventory=DEXClassInventory(classes=classes, methods=methods, fields=fields),
            )
        ]
    )

    inspector = ObfuscationInspector()
    result, _warnings = inspector.inspect(dex_insp)

    assert result.is_likely_obfuscated is False
    assert result.indicators.short_class_name_pct == 0.0
    assert result.indicators.short_method_name_pct == 0.0


def test_obfuscation_inspector_with_short_obfuscated_names() -> None:
    # 8 classes with 1-character names -> 100% short names
    classes = [
        ClassInfo(name=f"com.example.a.{c}") for c in ["a", "b", "c", "d", "e", "f", "g", "h"]
    ]
    methods = [
        MethodInfo(class_name="com.example.a.a", name="a"),
        MethodInfo(class_name="com.example.a.a", name="b"),
    ]
    fields = [
        FieldInfo(class_name="com.example.a.a", name="x", type="I"),
        FieldInfo(class_name="com.example.a.a", name="y", type="I"),
    ]

    dex_insp = DEXInspection(
        dex_files=[
            DEXFileInspection(
                path="classes.dex",
                size=1024,
                sha256="abc",
                inventory=DEXClassInventory(classes=classes, methods=methods, fields=fields),
            )
        ]
    )

    inspector = ObfuscationInspector()
    result, _warnings = inspector.inspect(dex_insp)

    # Should detect obfuscation indicators
    assert result.is_likely_obfuscated is True
    assert result.indicators.short_class_name_pct >= 80.0
    assert result.indicators.short_method_name_pct >= 80.0
    assert result.indicators.short_field_name_pct >= 80.0

    # Critical security invariant:
    # Obfuscation indicator is descriptive evidence, NOT a malware verdict.
    # The inspector must NOT set any malware classification.
    assert hasattr(result, "is_likely_obfuscated")
    assert not hasattr(result, "is_malware")
