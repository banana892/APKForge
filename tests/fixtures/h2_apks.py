"""Phase H.2 synthetic APK fixtures (method shapes, hierarchy, method reflection).

Built like the H.1 fixtures (``tests/fixtures/h1_apks.py``): hand-written smali in an
Apktool project, built into a real APK with BuildService and decoded again. Package
``com.example.h1``. The H.1 fixtures are reused for class-level cases.
"""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

from tests.fixtures.h1_apks import PKG, Fixture, _cls, _method

__all__ = ["H2_FIXTURES", "PKG"]

_P = "Lcom/example/h1/"


def _plain(name: str, header: str, body: str) -> str:
    """A class without the default members of ``_cls`` (no constructor, no bar())."""
    return f".class {header} {_P}{name};\n.super Ljava/lang/Object;\n" + body


_D = _cls(
    "D",
    _method("helper", "()V", 1, "return-void")
    + _method("used", "()V", 1, "return-void")
    + _method(
        "recursive",
        "()V",
        1,
        f"""
        invoke-virtual {{p0}}, {_P}D;->recursive()V
        return-void
        """,
    )
    + _method("over", "()V", 1, "return-void")
    + _method("over", "(I)V", 2, "return-void")
    + _method("onClick", "(Landroid/view/View;)V", 2, "return-void")
    + _method("helper2", "()V", 1, "return-void")
    + _method("shared", "()V", 1, "return-void")
    + "\n.method public static sutil()V\n    .registers 0\n    return-void\n.end method\n"
    + "\n.method private priv()V\n    .registers 1\n    return-void\n.end method\n"
    + _method("equals", "(Ljava/lang/Object;)Z", 3, "const/4 v0, 0x0\nreturn v0")
    + _method("readResolve", "()Ljava/lang/Object;", 1, "return-object p0"),
)

_A_CALLS = _method(
    "go",
    "()V",
    2,
    f"""
    new-instance v0, {_P}F;
    invoke-direct {{v0}}, {_P}F;-><init>()V
    invoke-virtual {{v0}}, {_P}D;->used()V
    invoke-virtual {{v0}}, {_P}D;->shared()V
    invoke-static {{}}, {_P}F;->sutil()V
    return-void
    """,
)

_F = (
    f".class public {_P}F;\n.super {_P}D;\n"
    + f"\n.method public constructor <init>()V\n    .registers 1\n    invoke-direct {{p0}}, {_P}D;-><init>()V\n    return-void\n.end method\n"
    + _method("helper2", "()V", 1, "return-void")
    + _method(
        "callShared",
        "()V",
        1,
        f"""
        invoke-virtual {{p0}}, {_P}D;->shared()V
        return-void
        """,
    )
)

_I = _plain("I", "public interface abstract", "\n.method public abstract run()V\n.end method\n")
_E = (
    f".class public {_P}E;\n.super Ljava/lang/Object;\n.implements {_P}I;\n"
    + _method("run", "()V", 1, "return-void")
    + _method("own", "()V", 1, "return-void")
)
_H = _cls("H", _method("handle", "()V", 1, "return-void"), super_="Landroid/app/Activity;")
_K = _cls(
    "K",
    "\n.annotation runtime Lkotlin/Metadata;\n    mv = {\n        0x1,\n        0x9,\n        0x0\n    }\n.end annotation\n"
    + _method("k", "()V", 1, "return-void"),
)
_J = _cls(
    "J",
    "\n.method public js()V\n    .registers 1\n    .annotation runtime Landroid/webkit/JavascriptInterface;\n    .end annotation\n    return-void\n.end method\n",
)
_N = _plain(
    "N",
    "public final enum",
    "\n.method public static values()[Lcom/example/h1/N;\n    .registers 1\n    const/4 v0, 0x0\n    return-object v0\n.end method\n",
)

H2_FIXTURES: list[Fixture] = [
    Fixture(
        "g01_methods",
        "method shapes: isolated, called, recursive, overloads, overrides, interface, "
        "onClick shape, Kotlin metadata, runtime annotation, enum values(), unresolved supertype",
        {
            "A": _cls("A", _A_CALLS),
            "B": _cls("B"),
            "D": _D,
            "E": _E,
            "F": _F,
            "H": _H,
            "I": _I,
            "J": _J,
            "K": _K,
            "N": _N,
        },
    ),
    Fixture(
        "g02_method_reflection",
        'D.secret() looked up by getDeclaredMethod("secret") on const-class D (resolved)',
        {
            "A": _cls(
                "A",
                _method(
                    "lookup",
                    "()Ljava/lang/Object;",
                    4,
                    f"""
                    const-class v0, {_P}D;
                    const-string v1, "secret"
                    const/4 v2, 0x0
                    new-array v2, v2, [Ljava/lang/Class;
                    invoke-virtual {{v0, v1, v2}}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
                    move-result-object v0
                    return-object v0
                    """,
                ),
            ),
            "D": _cls("D", _method("secret", "()V", 1, "return-void")),
        },
    ),
    Fixture(
        "g03_duplicate_class",
        "class C defined in both classes.dex and classes2.dex",
        {"A": _cls("A"), "C": _cls("C")},
        classes2={"C": _cls("C")},
    ),
]
