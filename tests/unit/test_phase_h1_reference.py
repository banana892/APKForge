"""Phase H.1 unit tests: smali indexing, manifest/resource references, completeness
propagation, deterministic ids/serialisation and false-absence prevention."""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from apkforge.reference import (
    AbsenceConclusion,
    AnalysisState,
    ApkIdentity,
    Component,
    Evidence,
    FieldAccess,
    InvokeKind,
    MatchBasis,
    NativeResolution,
    ReferenceAnalysisResult,
    ReferenceAnalysisService,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
    combine_states,
    format_reference_report,
    parse_smali,
)
from apkforge.reference.manifest import analyze_manifest
from apkforge.reference.models import evidence_id_for
from apkforge.reference.resources import analyze_tree

S = AnalysisState
K = ReferenceKind
PATH = "smali/com/x/A.smali"


def smali(body: str, header: str = ".class public Lcom/x/A;\n.super Ljava/lang/Object;\n") -> str:
    return header + body


def method(body: str, sig: str = "run()V", mods: str = "public") -> str:
    lines = "\n".join("    " + ln.strip() for ln in body.strip().splitlines())
    return f"\n.method {mods} {sig}\n    .registers 6\n{lines}\n.end method\n"


def of(res, kind):  # type: ignore[no-untyped-def]
    return [e for e in res.evidence if e.kind is kind]


# ---------------------------------------------------------------------------
# Completeness states
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        ([], S.NOT_ANALYZED),
        ([S.NOT_ANALYZED, S.NOT_ANALYZED], S.NOT_ANALYZED),
        ([S.COMPLETE], S.COMPLETE),
        ([S.COMPLETE, S.COMPLETE, S.COMPLETE], S.COMPLETE),
        ([S.COMPLETE, S.PARTIAL, S.COMPLETE], S.PARTIAL),  # DEX 1/2/3 example
        ([S.COMPLETE, S.NOT_ANALYZED], S.PARTIAL),
        ([S.COMPLETE, S.UNKNOWN], S.PARTIAL),
        ([S.UNKNOWN, S.NOT_ANALYZED], S.UNKNOWN),
        ([S.UNKNOWN], S.UNKNOWN),
        ([S.PARTIAL], S.PARTIAL),
    ],
)
def test_combine_states(states: list[AnalysisState], expected: AnalysisState) -> None:
    assert combine_states(states) is expected


# ---------------------------------------------------------------------------
# smali: reference kinds
# ---------------------------------------------------------------------------


def test_invoke_forms_and_method_details() -> None:
    res = parse_smali(
        smali(
            method(
                """
                invoke-static {}, Lcom/x/B;->s()V
                invoke-direct {p0}, Lcom/x/B;->d(ILjava/lang/String;)[J
                invoke-virtual {p0, v1}, Lcom/x/B;->v(I)V
                invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
                invoke-interface {v0}, Ljava/util/List;->size()I
                invoke-virtual/range {v0 .. v3}, Lcom/x/B;->r(IJ)V
                invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;
                return-void
                """
            )
        ),
        PATH,
        "classes.dex",
    )
    assert res.state is S.COMPLETE
    m = of(res, K.METHOD_REFERENCE)
    assert [e.invoke_kind for e in m] == [
        InvokeKind.STATIC,
        InvokeKind.DIRECT,
        InvokeKind.VIRTUAL,
        InvokeKind.SUPER,
        InvokeKind.INTERFACE,
        InvokeKind.VIRTUAL,
        InvokeKind.VIRTUAL,
    ]
    d = m[1]
    assert d.target == "com.x.B.d(ILjava/lang/String;)[J"
    assert d.parameter_types == ("int", "java.lang.String") and d.return_type == "long[]"
    assert (d.source_class, d.source_method, d.source_line) == ("com.x.A", "run()V", 7)
    assert d.instruction == "invoke-direct" and d.source_dex == "classes.dex"
    assert m[5].instruction == "invoke-virtual/range"
    assert m[6].target_class == "java.lang.Object"  # array receiver -> element class


def test_constructor_and_new_instance() -> None:
    res = parse_smali(
        smali(
            method(
                """
                new-instance v0, Lcom/x/B;
                invoke-direct {v0, v1}, Lcom/x/B;-><init>(I)V
                """
            )
        ),
        PATH,
    )
    (ctor,) = of(res, K.CONSTRUCTOR_REFERENCE)
    assert ctor.member_name == "<init>" and ctor.descriptor == "(I)V"
    assert of(res, K.METHOD_REFERENCE) == []
    cls = {(e.target, e.instruction) for e in of(res, K.CLASS_REFERENCE)}
    assert {("com.x.B", "new-instance"), ("com.x.B", "invoke-direct")} <= cls


@pytest.mark.parametrize(
    ("op", "access"),
    [
        ("iget", FieldAccess.IGET),
        ("iget-object", FieldAccess.IGET),
        ("iget-wide", FieldAccess.IGET),
        ("iput-boolean", FieldAccess.IPUT),
        ("sget-object", FieldAccess.SGET),
        ("sput-wide", FieldAccess.SPUT),
        ("iget-object-volatile", FieldAccess.IGET),
    ],
)
def test_field_access_kinds(op: str, access: FieldAccess) -> None:
    regs = "v0, p0" if op.startswith("i") else "v0"
    res = parse_smali(smali(method(f"{op} {regs}, Lcom/x/B;->f:Ljava/util/Map;")), PATH)
    (f,) = of(res, K.FIELD_REFERENCE)
    assert (f.access_kind, f.member_name, f.descriptor) == (access, "f", "Ljava/util/Map;")
    assert f.target == "com.x.B.f:Ljava/util/Map;" and f.return_type == "java.util.Map"
    types = {(e.target, e.context) for e in of(res, K.TYPE_REFERENCE)}
    assert {("com.x.B", "member-owner"), ("java.util.Map", "member-descriptor")} <= types


def test_type_references_from_every_position() -> None:
    res = parse_smali(
        smali(
            """
.implements Lcom/x/I;
.annotation runtime Lcom/x/Ann;
    value = Lcom/x/AnnValue;
.end annotation
.field private f:[[Lcom/x/F;
"""
            + method(
                """
                check-cast p1, Lcom/x/Cast;
                instance-of v0, p1, Lcom/x/Inst;
                new-array v0, v1, [Lcom/x/Arr;
                filled-new-array {v0, v1}, [Lcom/x/Filled;
                const-class v0, Lcom/x/Konst;
                .local v2, "x":Lcom/x/Local;
                :try_start_0
                nop
                :try_end_0
                .catch Lcom/x/Exc; {:try_start_0 .. :try_end_0} :catch_0
                :catch_0
                return-void
                """,
                sig="m(Lcom/x/P;)Lcom/x/R;",
            )
        ),
        PATH,
    )
    assert res.state is S.COMPLETE, res.issues
    types = {e.target: e for e in of(res, K.TYPE_REFERENCE)}
    expect = {
        "com.x.I": "interface",
        "com.x.Ann": "annotation",
        "com.x.AnnValue": "annotation-value",
        "com.x.F": "field-type",
        "com.x.P": "method-parameter",
        "com.x.R": "method-return",
        "com.x.Cast": "operand",
        "com.x.Inst": "operand",
        "com.x.Arr": "array-element",
        "com.x.Filled": "array-element",
        "com.x.Konst": "operand",
        "com.x.Local": "local-variable-debug-info",
        "com.x.Exc": "exception-handler",
        "java.lang.Object": "superclass",
    }
    assert {k: types[k].context for k in expect} == expect
    assert types["com.x.F"].array_dimensions == 2
    # class edges come from instructions / super / implements / catch only
    class_targets = {e.target for e in of(res, K.CLASS_REFERENCE)}
    assert "com.x.P" not in class_targets and "com.x.Ann" not in class_targets
    assert {"com.x.Cast", "com.x.Inst", "com.x.Konst", "com.x.Exc", "com.x.I"} <= class_targets
    assert [e.target for e in of(res, K.CONST_CLASS_REFERENCE)] == ["com.x.Konst"]


def test_type_mentions_are_deduplicated_per_method() -> None:
    res = parse_smali(
        smali(
            method("check-cast p1, Lcom/x/B;\ncheck-cast p1, Lcom/x/B;\ncheck-cast p1, Lcom/x/B;")
        ),
        PATH,
    )
    (c,) = [e for e in of(res, K.CLASS_REFERENCE) if e.target == "com.x.B"]
    assert c.occurrences == 3 and c.source_line == 6


def test_strings_escapes_and_comments() -> None:
    res = parse_smali(
        smali(
            method(
                r"""
                const-string v0, "a \"q\" #not-comment\né"  # trailing comment
                const-string/jumbo v1, "😀"
                const-string v2, "lone \ud83d"
                """
            )
            + '.field public static K:Ljava/lang/String; = "init"\n'
        ),
        PATH,
    )
    assert res.state is S.COMPLETE, res.issues
    vals = [e.string_value for e in of(res, K.STRING_REFERENCE)]
    assert vals == ['a "q" #not-comment\né', "😀", "lone \\ud83d", "init"]
    json.dumps(vals).encode("utf-8")  # serialisable (no lone surrogates)


# ---------------------------------------------------------------------------
# smali: malformed / unsupported input
# ---------------------------------------------------------------------------


def test_missing_class_header_is_unknown() -> None:
    res = parse_smali("invoke-static {}, Lcom/x/B;->s()V\n", PATH)
    assert not res.analyzed and res.state is S.UNKNOWN
    assert res.issues[0].code == "MALFORMED_SMALI"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("invoke-static {}, garbage", "MALFORMED_SMALI"),
        ("invoke-virtual {v0}, Lcom/x/B;->m(Q)V", "MALFORMED_SMALI"),
        ('const-string v0, "unterminated', "MALFORMED_SMALI"),
        ("iget-quick v0, v1, field@0x8", "UNSUPPORTED_INSTRUCTION"),
        (
            'invoke-custom {v0}, call_site_0("run", ()V)@Lcom/x/Bsm;->b()V',
            "UNSUPPORTED_INSTRUCTION",
        ),
        ("const-method-handle v0, invoke-static@Lcom/x/B;->m()V", "UNSUPPORTED_INSTRUCTION"),
        ("weird-op v0, Lcom/x/B;", "UNSUPPORTED_INSTRUCTION"),
        (".mystery Lcom/x/B;", "UNSUPPORTED_DIRECTIVE"),
    ],
)
def test_malformed_or_unsupported_lines_make_file_partial(body: str, code: str) -> None:
    res = parse_smali(smali(method(body)), PATH)
    assert res.analyzed and res.state is S.PARTIAL
    assert [i.code for i in res.issues] == [code]
    assert res.issues[0].location == f"{PATH}:6"
    assert all(e.analysis_state is S.PARTIAL for e in res.evidence)


def test_unsupported_lines_still_contribute_type_mentions() -> None:
    res = parse_smali(smali(method("weird-op v0, Lcom/x/Hidden;")), PATH)
    assert any(
        e.target == "com.x.Hidden" and e.context == "unsupported-operand"
        for e in of(res, K.TYPE_REFERENCE)
    )


def test_unterminated_method_and_block() -> None:
    res = parse_smali(smali(".method public m()V\n    return-void\n"), PATH)
    assert res.state is S.PARTIAL and "unterminated method" in res.issues[0].message
    res = parse_smali(smali(method(".array-data 4\n0x1")[: -len(".end method\n")]), PATH)
    assert res.state is S.PARTIAL


def test_payload_blocks_and_plain_instructions_are_not_issues() -> None:
    res = parse_smali(
        smali(
            method(
                """
                const/4 v0, 0x1
                const-wide v2, 0x1L
                add-int/lit8 v0, v0, 0x1
                if-eqz v0, :cond_0
                packed-switch v0, :pswitch_data_0
                fill-array-data v1, :array_0
                :cond_0
                return-void
                :pswitch_data_0
                .packed-switch 0x0
                    :cond_0
                .end packed-switch
                :array_0
                .array-data 4
                    0x1
                .end array-data
                """
            )
        ),
        PATH,
    )
    assert res.state is S.COMPLETE, res.issues


def test_debug_info_directives_are_supported() -> None:
    res = parse_smali(
        smali(
            method(
                """
                .param p1, "name"    # Ljava/lang/String;
                    .annotation build Lcom/x/NonNull;
                    .end annotation
                .end param
                .prologue
                .line 12
                const/4 v0, 0x0
                .local v0, "items":Ljava/util/List;, "Ljava/util/List<Lcom/x/Item;>;"
                .end local v0    # "items":Ljava/util/List;
                .restart local v0    # "items":Ljava/util/List;
                invoke-static {}, Lcom/x/B;->s()V
                """,
                sig="m(Ljava/lang/String;)V",
            )
        ),
        PATH,
    )
    assert res.state is S.COMPLETE, res.issues
    (m,) = of(res, K.METHOD_REFERENCE)
    assert m.java_line == 12
    targets = {e.target for e in of(res, K.TYPE_REFERENCE)}
    assert {"com.x.NonNull", "java.util.List"} <= targets
    assert "com.x.Item" not in targets  # generic signature strings are not type operands


def test_inline_subannotation_is_supported() -> None:
    res = parse_smali(
        smali(
            """
.annotation system Ldalvik/annotation/AnnotationDefault;
    value = .subannotation Lcom/x/State;
        value = Lcom/x/Bundler;
    .end subannotation
.end annotation
"""
        ),
        PATH,
    )
    assert res.state is S.COMPLETE, res.issues
    assert {"com.x.State", "com.x.Bundler"} <= {e.target for e in of(res, K.TYPE_REFERENCE)}


# ---------------------------------------------------------------------------
# smali: reflection & native
# ---------------------------------------------------------------------------


def test_reflection_member_target_identified() -> None:
    res = parse_smali(
        smali(
            method(
                """
                const-class v0, Lcom/x/B;
                const-string v1, "secret"
                const/4 v2, 0x0
                invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
                move-result-object v3
                invoke-virtual {v3, v2, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
                """
            )
        ),
        PATH,
    )
    get, inv = of(res, K.REFLECTION_INDICATOR)
    assert get.resolution is ResolutionStatus.TARGET_IDENTIFIED
    assert (get.target, get.target_class, get.member_name) == (
        "com.x.B.secret",
        "com.x.B",
        "secret",
    )
    s = of(res, K.STRING_REFERENCE)[0]
    assert s.string_use is StringUse.POSSIBLE_METHOD_NAME
    cc = of(res, K.CONST_CLASS_REFERENCE)[0]
    assert set(get.associated_evidence) == {s.evidence_id, cc.evidence_id}
    assert inv.resolution is ResolutionStatus.NO_TARGET_IDENTIFIED
    assert inv.reflection_api == "java.lang.reflect.Method.invoke"


@pytest.mark.parametrize(
    "between",
    [
        ":cond_0",  # branch target: value may come from elsewhere
        "move-result-object v0",  # overwritten
        'const-string v0, "other.Cls"\nmove-object v0, v5',  # replaced by an unknown value
    ],
)
def test_reflection_target_unknown_when_flow_is_broken(between: str) -> None:
    res = parse_smali(
        smali(
            method(
                f"""
                const-string v0, "com.x.B"
                {between}
                invoke-static {{v0}}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
                """
            )
        ),
        PATH,
    )
    (r,) = of(res, K.REFLECTION_INDICATOR)
    assert r.resolution is ResolutionStatus.TARGET_UNKNOWN and r.target == "<unresolved>"


def test_reflection_flow_survives_try_labels_and_moves() -> None:
    res = parse_smali(
        smali(
            method(
                """
                const-string v0, "com.x.B"
                :try_start_0
                move-object v4, v0
                invoke-virtual {v5, v4}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
                :try_end_0
                """
            )
        ),
        PATH,
    )
    (r,) = of(res, K.REFLECTION_INDICATOR)
    assert r.resolution is ResolutionStatus.TARGET_IDENTIFIED and r.target_class == "com.x.B"
    assert r.reflection_api == "java.lang.ClassLoader.loadClass"


@pytest.mark.parametrize(
    ("call", "api"),
    [
        (
            "invoke-direct {v0, v1, v2, v3, v4}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
            "dalvik.system.DexClassLoader.<init>",
        ),
        (
            "invoke-virtual {v0, v1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;",
            "java.lang.reflect.Field.get",
        ),
        (
            "invoke-static {v0, v1, v2}, Ljava/lang/reflect/Proxy;->newProxyInstance(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;",
            "java.lang.reflect.Proxy.newProxyInstance",
        ),
        (
            "invoke-virtual {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
            "java.lang.reflect.Constructor.newInstance",
        ),
    ],
)
def test_reflection_apis_without_a_name_argument(call: str, api: str) -> None:
    (r,) = of(parse_smali(smali(method(call)), PATH), K.REFLECTION_INDICATOR)
    assert r.reflection_api == api and r.resolution is ResolutionStatus.NO_TARGET_IDENTIFIED


def test_native_loads() -> None:
    res = parse_smali(
        smali(
            method(
                """
                invoke-static {p1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
                const-string v1, "/data/x/libz.so"
                invoke-virtual {v0, v1}, Ljava/lang/Runtime;->load(Ljava/lang/String;)V
                """
            )
            + "\n.method private native my_native(I)V\n.end method\n"
        ),
        PATH,
    )
    unknown, path_load, nat = (
        *of(res, K.NATIVE_LIBRARY_LOAD),
        of(res, K.NATIVE_METHOD)[0],
    )
    assert unknown.native_resolution is NativeResolution.UNKNOWN and unknown.library_name is None
    assert path_load.library_name == "/data/x/libz.so"
    assert path_load.native_resolution is NativeResolution.IDENTIFIED
    assert nat.target == "com.x.A.my_native(I)V" and nat.member_name == "my_native"
    assert "Java_com_x_A_my_1native" in nat.confidence_basis


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:name=".App" android:backupAgent="Backup">
    <activity android:name=".A"><meta-data android:name="k" android:value="com.x.B"/></activity>
    <activity-alias android:name=".Alias" android:targetActivity="com.x.A"/>
    <service android:name="com.x.S"/>
    <receiver android:name=".R"/>
    <provider android:name=".P" android:authorities="com.x.one;com.x.two"/>
  </application>
</manifest>
"""


def test_manifest_references() -> None:
    m = analyze_manifest(MANIFEST, {"com.x.B"})
    assert m.state is S.COMPLETE and m.package == "com.x"
    got = {(e.instruction, e.context, e.target, e.match_basis) for e in m.evidence}
    CA, PA, EV = MatchBasis.CLASS_ATTRIBUTE, MatchBasis.PROVIDER_AUTHORITY, MatchBasis.EXACT_VALUE
    assert got == {
        ("application", "android:name", "com.x.App", CA),
        ("application", "android:backupAgent", "com.x.Backup", CA),
        ("activity", "android:name", "com.x.A", CA),
        ("activity-alias", "android:targetActivity", "com.x.A", CA),
        ("service", "android:name", "com.x.S", CA),
        ("receiver", "android:name", "com.x.R", CA),
        ("provider", "android:name", "com.x.P", CA),
        ("provider", "android:authorities", "com.x.one", PA),
        ("provider", "android:authorities", "com.x.two", PA),
        ("meta-data", "android:value", "com.x.B", EV),
    }
    meta = next(e for e in m.evidence if e.instruction == "meta-data")
    assert not meta.definitive  # textual match only
    assert m.authorities == {"com.x.one": "com.x.P", "com.x.two": "com.x.P"}


def test_manifest_incomplete_states() -> None:
    assert analyze_manifest(None, set()).state is S.UNKNOWN
    assert analyze_manifest("<manifest", set()).state is S.UNKNOWN
    m = analyze_manifest(MANIFEST.replace('"com.x.S"', '"@string/svc"'), set())
    assert m.state is S.PARTIAL and m.issues[0].code == "UNRESOLVED_RESOURCE_VALUE"


# ---------------------------------------------------------------------------
# Resources / assets
# ---------------------------------------------------------------------------


def _tree(root: Path, files: dict[str, bytes | str]) -> Path:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
    return root


def _scan(root: Path, dirs: tuple[str, ...] = ("res",)):  # type: ignore[no-untyped-def]
    return analyze_tree(
        root,
        dirs,
        "resources",
        package="com.x",
        classes={"com.x.Frag", "com.x.View", "com.x.Svc"},
        authorities={"com.x.files": "com.x.P"},
    )


def test_resource_matches(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        {
            "res/layout/a.xml": (
                '<L xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '  <fragment android:name=".Frag"/>\n'
                "  <com.x.View/>\n"
                '  <TextView android:text="see com.x.Svc now"/>\n'
                "</L>\n"
            ),
            "res/values/strings.xml": (
                '<resources><string name="c">com.x.Frag</string>'
                '<string name="u">content://com.x.files/p</string></resources>'
            ),
            "res/drawable/i.png": b"\x89PNG\r\n\x1a\n\x00\xff",
        },
    )
    r = _scan(tmp_path)
    assert r.state is S.COMPLETE, r.issues
    got = {(e.source_file, e.source_line, e.target, e.match_basis) for e in r.evidence}
    assert got == {
        ("res/layout/a.xml", 2, "com.x.Frag", MatchBasis.CLASS_ATTRIBUTE),
        ("res/layout/a.xml", 3, "com.x.View", MatchBasis.XML_ELEMENT_NAME),
        ("res/layout/a.xml", 4, "com.x.Svc", MatchBasis.EMBEDDED_TOKEN),
        ("res/values/strings.xml", 1, "com.x.Frag", MatchBasis.EXACT_VALUE),
        ("res/values/strings.xml", 1, "com.x.files", MatchBasis.EMBEDDED_TOKEN),
    }
    frag = next(e for e in r.evidence if e.match_basis is MatchBasis.CLASS_ATTRIBUTE)
    assert frag.xml_location == "/L[1]/fragment[1]/@android:name" and frag.definitive
    assert r.files_analyzed == r.files_total == 3


def test_service_loader_and_unknown_dir(tmp_path: Path) -> None:
    _tree(tmp_path, {"unknown/META-INF/services/com.x.Api": "# providers\ncom.x.Svc\n"})
    r = _scan(tmp_path, ("assets", "unknown"))
    (ev,) = r.evidence
    assert (ev.match_basis, ev.source_line, ev.target) == (
        MatchBasis.SERVICE_LOADER_ENTRY,
        2,
        "com.x.Svc",
    )


@pytest.mark.parametrize(
    ("name", "data", "code"),
    [
        ("assets/blob.bin", b"\x00\x01\xff\xfe" * 4, "BINARY_NOT_INSPECTED"),
        ("assets/bad.xml", "<a><b>com.x.View</a>", "XML_PARSE_ERROR"),
        (
            "res/xml/dtd.xml",
            '<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>',
            "XML_PARSE_ERROR",
        ),
    ],
)
def test_uninspectable_inputs_are_partial(
    tmp_path: Path, name: str, data: bytes | str, code: str
) -> None:
    _tree(tmp_path, {name: data})
    r = _scan(tmp_path, ("res", "assets"))
    assert r.state is S.PARTIAL and [i.code for i in r.issues] == [code]
    if name == "assets/bad.xml":  # textual evidence of the unparsed file is kept
        assert [(e.target, e.match_basis) for e in r.evidence] == [
            ("com.x.View", MatchBasis.EMBEDDED_TOKEN)
        ]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    (tmp_path / "outside.txt").write_text("com.x.View")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "link.txt").symlink_to(tmp_path / "outside.txt")
    r = _scan(tmp_path, ("assets",))
    assert r.state is S.PARTIAL and r.evidence == []


# ---------------------------------------------------------------------------
# Service over a decoded project (no toolchain)
# ---------------------------------------------------------------------------


def _project(root: Path) -> Path:
    _tree(
        root,
        {
            "AndroidManifest.xml": (
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.x" android:versionName="1.2" android:versionCode="7">'
                '<application><activity android:name=".A"/></application></manifest>'
            ),
            "apktool.yml": "version: 3.0.3\n",
            "smali/com/x/A.smali": smali(
                method(
                    """
                    const-string v0, "com.x.B"
                    const-string v1, "hello world"
                    const-string v2, "someIdentifier"
                    const-string v3, "org.other.Missing"
                    invoke-static {}, Lcom/x/B;->bar()V
                    """
                )
            ),
            "smali_classes2/com/x/B.smali": smali(
                method("return-void", sig="bar()V", mods="public static"),
                header=".class public Lcom/x/B;\n.super Ljava/lang/Object;\n",
            ),
            "smali_classes2/com/x/Lonely.smali": smali(
                "", header=".class public Lcom/x/Lonely;\n.super Ljava/lang/Object;\n"
            ),
        },
    )
    return root


def test_analyze_decoded_project(tmp_path: Path) -> None:
    r = ReferenceAnalysisService.analyze_decoded(
        _project(tmp_path), apk_entries=["classes.dex", "classes2.dex", "AndroidManifest.xml"]
    )
    assert r.analysis_state is S.COMPLETE
    assert [c.component for c in r.components] == [c.value for c in Component]
    assert [s.component for s in r.components[0].subcomponents] == [
        "dex:classes.dex",
        "dex:classes2.dex",
    ]
    assert [c.name for c in r.defined_classes] == ["com.x.A", "com.x.B", "com.x.Lonely"]
    assert (r.apk.package_name, r.apk.version_name, r.apk.version_code) == ("com.x", "1.2", "7")
    uses = {e.string_value: e.string_use for e in r.references if e.kind is K.STRING_REFERENCE}
    assert uses == {
        "com.x.B": StringUse.POSSIBLE_CLASS_NAME,
        "hello world": StringUse.STRING_LITERAL,
        "someIdentifier": StringUse.UNKNOWN_STRING_USE,
        "org.other.Missing": StringUse.UNKNOWN_STRING_USE,
    }
    ix = r.index()
    assert ix.callers_of("Lcom/x/B;") == ["com.x.A"]  # descriptor form accepted
    assert ix.find_string_references("hello", contains=True).evidence[0].string_value == (
        "hello world"
    )
    lonely = ix.assess_absence("com/x/Lonely")
    assert lonely.conclusion is AbsenceConclusion.NO_REFERENCES_WITHIN_SCOPE
    assert lonely.absence_established and lonely.target == "com.x.Lonely"
    b = ix.assess_absence("com.x.B")
    assert b.conclusion is AbsenceConclusion.REFERENCES_OBSERVED
    assert b.indirect_evidence[0].string_value == "com.x.B"


def test_self_references_are_excluded_by_default(tmp_path: Path) -> None:
    r = ReferenceAnalysisService.analyze_decoded(_project(tmp_path), apk_entries=[])
    ix = r.index()
    assert ix.find_type_references("com.x.Lonely").evidence == []
    own = ix.find_class_references("java.lang.Object", include_self=True)
    assert {e.source_class for e in own.evidence} == {"com.x.A", "com.x.B", "com.x.Lonely"}


def test_missing_decoded_dex_and_resources_propagate(tmp_path: Path) -> None:
    r = ReferenceAnalysisService.analyze_decoded(
        _project(tmp_path),
        apk_entries=["classes.dex", "classes2.dex", "classes3.dex", "resources.arsc"],
    )
    sub = {s.component: s.state for s in r.components[0].subcomponents}
    assert sub["dex:classes3.dex"] is S.UNKNOWN
    assert r.component_state(Component.DEX) is S.PARTIAL
    assert r.component_state(Component.REFLECTION) is S.PARTIAL  # unseen code may reflect
    assert r.component_state(Component.NATIVE_CODE) is S.PARTIAL
    assert r.component_state(Component.RESOURCES) is S.PARTIAL
    assert r.analysis_state is S.PARTIAL
    aa = r.index().assess_absence("com.x.Lonely")
    assert aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
    assert "dex analysis is PARTIAL" in aa.reasons
    q = r.index().find_class_references("com.x.Lonely")
    assert q.evidence == [] and not q.absence_established


def test_malformed_smali_propagates_to_aggregate(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / "smali_classes2/com/x/Broken.smali").write_text(
        smali(method("invoke-custom {v0}, call_site_0()@Lcom/x/Y;->b()V"))
    )
    (tmp_path / "smali/com/x/Bin.smali").write_bytes(b"\xff\xfe\x00")
    r = ReferenceAnalysisService.analyze_decoded(tmp_path, apk_entries=[])
    sub = {s.component: (s.state, s.issue_count) for s in r.components[0].subcomponents}
    assert sub == {"dex:classes.dex": (S.PARTIAL, 1), "dex:classes2.dex": (S.PARTIAL, 1)}
    assert r.analysis_state is S.PARTIAL
    assert not r.index().assess_absence("com.x.Lonely").absence_established


def test_resources_not_requested_are_not_analyzed(tmp_path: Path) -> None:
    r = ReferenceAnalysisService.analyze_decoded(
        _project(tmp_path), apk_entries=[], include_resources=False
    )
    assert r.component_state(Component.RESOURCES) is S.NOT_ANALYZED
    assert r.analysis_state is S.PARTIAL
    aa = r.index().assess_absence("com.x.Lonely")
    assert aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
    q = r.index().find_resource_references("com.x.Lonely")
    assert q.analysis_state is S.NOT_ANALYZED and not q.absence_established


def test_no_apk_entries_and_no_smali_is_unknown(tmp_path: Path) -> None:
    _tree(tmp_path, {"AndroidManifest.xml": '<manifest package="p"/>'})
    r = ReferenceAnalysisService.analyze_decoded(tmp_path)
    assert r.component_state(Component.DEX) is S.UNKNOWN
    assert not r.index().assess_absence("p.X").absence_established


# ---------------------------------------------------------------------------
# Determinism / serialisation
# ---------------------------------------------------------------------------


def test_deterministic_ids_ordering_and_json(tmp_path: Path) -> None:
    a = ReferenceAnalysisService.analyze_decoded(_project(tmp_path / "one"), apk_entries=[])
    b = ReferenceAnalysisService.analyze_decoded(_project(tmp_path / "two"), apk_entries=[])
    assert a.to_json() == b.to_json()  # different absolute locations, same result
    text = a.to_json()
    assert str(tmp_path) not in text
    ids = [e.evidence_id for e in a.all_evidence()]
    assert len(ids) == len(set(ids))
    assert a.references == sorted(a.references, key=Evidence.sort_key)
    back = ReferenceAnalysisResult.model_validate_json(text)
    assert back.to_json() == text
    assert json.loads(a.to_json(include_code_references=False)).get("references") is None
    assert json.loads(text)["evidence_counts"]["METHOD_REFERENCE"] == 1


def test_evidence_id_is_stable() -> None:
    ev = Evidence(
        kind=K.CLASS_REFERENCE, source_file="smali/a/B.smali", target="a.C", source_line=3
    )
    assert ev.finalize_id().evidence_id == evidence_id_for(ev)
    # golden value: ids must not depend on interpreter, hash seed or machine
    assert ev.evidence_id == evidence_id_for(
        {
            "kind": "CLASS_REFERENCE",
            "source_file": "smali/a/B.smali",
            "target": "a.C",
            "source_line": 3,
        }
    )
    assert (
        ev.evidence_id
        == "ev-"
        + __import__("hashlib")
        .sha256(b'["CLASS_REFERENCE","smali/a/B.smali",3,null,null,"a.C",null,null,null,null]')
        .hexdigest()[:16]
    )


# ---------------------------------------------------------------------------
# Service read-only behaviour without a toolchain
# ---------------------------------------------------------------------------


class _FailingDecode:
    work_dir = None

    def prepare_workspace(self, *, work_dir=None, build_id=None):  # type: ignore[no-untyped-def]
        from apkforge.builders.workspace import BuildWorkspace

        return BuildWorkspace.create(work_dir), None

    def decode(self, apk, ws):  # type: ignore[no-untyped-def]
        class _S:
            passed = False
            failure_cause = "simulated Apktool failure"

        return _S()


def test_decode_failure_is_unknown_not_absent(tmp_path: Path) -> None:
    import zipfile

    apk = tmp_path / "x.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n")
    before = apk.read_bytes()
    svc = ReferenceAnalysisService(_FailingDecode(), work_dir=tmp_path / "ws")  # type: ignore[arg-type]
    r = svc.analyze(apk)
    assert r.analysis_state is S.UNKNOWN and r.errors
    assert all(c.state is S.UNKNOWN for c in r.components)
    assert r.original_unchanged is True and apk.read_bytes() == before
    assert list((tmp_path / "ws").iterdir()) == []  # workspace removed
    aa = r.index().assess_absence("a.B")
    assert aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
    assert r.apk.sha256 and r.apk.file_name == "x.apk"


def test_not_a_zip(tmp_path: Path) -> None:
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip")
    r = ReferenceAnalysisService(work_dir=tmp_path).analyze(bad)
    assert r.analysis_state is S.UNKNOWN and "not a readable APK" in r.errors[0]
    assert r.original_unchanged is True


def test_report_states_absence_limits(tmp_path: Path) -> None:
    r = ReferenceAnalysisService.analyze_decoded(
        _project(tmp_path), apk_entries=[], include_resources=False
    )
    text = format_reference_report(r, [r.index().assess_absence("com.x.Lonely")], verbose=True)
    assert "ABSENCE_NOT_ESTABLISHED" in text and "NOT_ANALYZED" in text
    assert "does not transform APKs" in text
    assert ApkIdentity().file_name is None
