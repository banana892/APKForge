"""Phase H.1 synthetic APK fixtures.

Each fixture is an Apktool project (hand-written smali + text manifest + optional
res/assets/lib) that is *built into a real APK* with the existing
:class:`~apkforge.builders.BuildService` (Apktool 3.0.3) and then analysed by decoding
that APK again. Nothing is mocked at the smali level.

Package ``com.example.h1``; classes ``A``, ``B``, ``C``.
"""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.builders import BuildService

__all__ = ["FIXTURES", "PKG", "Fixture", "build_fixture", "write_project"]

PKG = "com.example.h1"
B = f"{PKG}.B"
C = f"{PKG}.C"

_APKTOOL_YML = """\
version: 3.0.3
apkFileName: {name}.apk
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: {min_sdk}
  targetSdkVersion: 34
packageInfo:
  forcedPackageId: 127
versionInfo:
  versionCode: 1
  versionName: '1.0'
doNotCompress:
- resources.arsc
"""


def _manifest(components: str = "") -> str:
    return textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="utf-8" standalone="no"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PKG}">
            <application android:label="H1">
                <activity android:name=".A" android:exported="false"/>
        {components}
            </application>
        </manifest>
        """
    )


def _cls(name: str, body: str = "", super_: str = "Ljava/lang/Object;") -> str:
    return (
        f".class public Lcom/example/h1/{name};\n"
        f".super {super_}\n"
        f'.source "{name}.java"\n\n'
        ".field public static counter:I\n\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        f"    invoke-direct {{p0}}, {super_}-><init>()V\n"
        "    return-void\n"
        ".end method\n\n"
        ".method public static bar()V\n"
        "    .registers 0\n"
        "    return-void\n"
        ".end method\n" + textwrap.dedent(body)
    )


def _method(name: str, proto: str, regs: int, body: str) -> str:
    lines = "\n".join("    " + ln for ln in textwrap.dedent(body).strip().splitlines())
    return f"\n.method public {name}{proto}\n    .registers {regs}\n{lines}\n.end method\n"


@dataclass
class Fixture:
    name: str
    description: str
    classes: dict[str, str]  # simple name -> smali text (classes.dex)
    classes2: dict[str, str] = field(default_factory=dict)  # -> classes2.dex
    manifest_components: str = ""
    files: dict[str, bytes] = field(default_factory=dict)  # project-relative -> content
    #: apktool.yml minSdkVersion (smali assembles invoke-custom/-polymorphic only at >= 26)
    min_sdk: int = 21


def _ab(a_body: str = "", b_body: str = "", **kw: object) -> dict[str, str]:
    return {"A": _cls("A", a_body), "B": _cls("B", b_body), **kw}  # type: ignore[dict-item]


FIXTURES: list[Fixture] = [
    Fixture("f01_isolated", "A and B; B has no references", _ab()),
    Fixture(
        "f02_class_ref",
        "A -> B (instance-of)",
        _ab(
            _method(
                "isB",
                "(Ljava/lang/Object;)Z",
                3,
                """
                instance-of v0, p1, Lcom/example/h1/B;
                return v0
                """,
            )
        ),
    ),
    Fixture(
        "f03_multiple_callers",
        "A -> B and C -> B (check-cast)",
        {
            **_ab(
                _method(
                    "cast",
                    "(Ljava/lang/Object;)V",
                    2,
                    """
                    check-cast p1, Lcom/example/h1/B;
                    return-void
                    """,
                )
            ),
            "C": _cls(
                "C",
                _method(
                    "cast",
                    "(Ljava/lang/Object;)V",
                    2,
                    """
                    check-cast p1, Lcom/example/h1/B;
                    return-void
                    """,
                ),
            ),
        },
    ),
    Fixture(
        "f04_method_ref",
        "A.foo() -> B.bar()",
        _ab(
            _method(
                "foo",
                "()V",
                1,
                """
                invoke-static {}, Lcom/example/h1/B;->bar()V
                return-void
                """,
            )
        ),
    ),
    Fixture(
        "f05_field_ref",
        "A -> B.counter (sget/sput)",
        _ab(
            _method(
                "foo",
                "()V",
                2,
                """
                sget v0, Lcom/example/h1/B;->counter:I
                add-int/lit8 v0, v0, 0x1
                sput v0, Lcom/example/h1/B;->counter:I
                return-void
                """,
            )
        ),
    ),
    Fixture(
        "f06_constructor",
        "new-instance B; invoke-direct B.<init>",
        _ab(
            _method(
                "make",
                "()Ljava/lang/Object;",
                2,
                """
                new-instance v0, Lcom/example/h1/B;
                invoke-direct {v0}, Lcom/example/h1/B;-><init>()V
                return-object v0
                """,
            )
        ),
    ),
    Fixture(
        "f07_const_class",
        "const-class B",
        _ab(
            _method(
                "type",
                "()Ljava/lang/Class;",
                2,
                """
                const-class v0, Lcom/example/h1/B;
                return-object v0
                """,
            )
        ),
    ),
    Fixture(
        "f08_string",
        "a string naming B (not a structural reference)",
        _ab(
            _method(
                "name",
                "()Ljava/lang/String;",
                2,
                """
                const-string v0, "com.example.h1.B"
                return-object v0
                """,
            )
        ),
    ),
    Fixture(
        "f09_reflection",
        'Class.forName("com.example.h1.B") plus an unresolved Class.forName(p1); C isolated',
        {
            **_ab(
                _method(
                    "load",
                    "()Ljava/lang/Object;",
                    2,
                    """
                    const-string v0, "com.example.h1.B"
                    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
                    move-result-object v0
                    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;
                    move-result-object v0
                    return-object v0
                    """,
                )
                + _method(
                    "loadDynamic",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    3,
                    """
                    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
                    move-result-object v0
                    return-object v0
                    """,
                )
            ),
            "C": _cls("C"),
        },
    ),
    Fixture(
        "f10_native_method",
        "B declares a native method",
        _ab(b_body="\n.method public static native nativeCall(I)I\n.end method\n"),
    ),
    Fixture(
        "f11_load_library",
        'System.loadLibrary("h1native") with a bundled lib/arm64-v8a/libh1native.so',
        _ab(
            "\n.method static constructor <clinit>()V\n"
            "    .registers 1\n"
            '    const-string v0, "h1native"\n'
            "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        ),
        files={"lib/arm64-v8a/libh1native.so": b"\x7fELF\x02\x01\x01\x00synthetic"},
    ),
    Fixture(
        "f12_manifest",
        "manifest service .B, receiver C, activity-alias -> A",
        {**_ab(), "C": _cls("C")},
        manifest_components=(
            '        <service android:name=".B" android:exported="false"/>\n'
            '        <receiver android:name="com.example.h1.C" android:exported="false"/>\n'
            '        <activity-alias android:name=".Alias" android:targetActivity=".A"/>'
        ),
    ),
    Fixture(
        "f13_resource",
        "layout inflates <com.example.h1.B>; assets text mentions C",
        {**_ab(), "C": _cls("C")},
        files={
            "res/layout/main.xml": textwrap.dedent(
                """\
                <?xml version="1.0" encoding="utf-8"?>
                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
                    android:layout_width="match_parent" android:layout_height="match_parent">
                    <com.example.h1.B android:layout_width="wrap_content"
                        android:layout_height="wrap_content"/>
                </LinearLayout>
                """
            ).encode(),
            "assets/config.txt": b"handler=com.example.h1.C\n",
        },
    ),
    Fixture(
        "f14_incomplete",
        "multidex (C in classes2.dex) + malformed assets/broken.xml; B unreferenced",
        _ab(),
        classes2={"C": _cls("C")},
        files={"assets/broken.xml": b"<config><item>unterminated</config>\n"},
    ),
]


def write_project(fx: Fixture, root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "apktool.yml").write_text(_APKTOOL_YML.format(name=fx.name, min_sdk=fx.min_sdk))
    (root / "AndroidManifest.xml").write_text(_manifest(fx.manifest_components))
    for smali_dir, classes in (("smali", fx.classes), ("smali_classes2", fx.classes2)):
        for name, text in classes.items():
            path = root / smali_dir / "com" / "example" / "h1" / f"{name}.smali"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    for rel, data in fx.files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def build_fixture(service: BuildService, fx: Fixture, work: Path) -> Path:
    """Write the project for *fx* and build it into ``work/<name>.apk`` (real Apktool)."""
    project = write_project(fx, work / "projects" / fx.name)
    out = work / "apks" / f"{fx.name}.apk"
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = service.build(project, out, overwrite=True)
    if not stage.passed:
        raise RuntimeError(f"{fx.name}: build failed: {stage.failure_cause}\n{stage.stderr}")
    return out
