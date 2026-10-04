"""Phase H.5 synthetic APK corpus for H-TRANS-002 (remove isolated method).

Built and published exactly like the H.3 corpus (tests/fixtures/h3_apks.py): a
hand-written Apktool project in package ``com.example.h1``, built with BuildService,
round-tripped once and signed v2/v3 by a separate publisher key, so every rebuild is
semantically EQUIVALENT (only the signature is replaced) and the output is re-signed by a
different key as with any real APK.

The positive fixtures are shaped so that H.2 *independently* decides ``ELIGIBLE`` for the
target method (nothing here is hard-coded into H.5); the negative fixtures reproduce each
refusal / uncertainty class H.5 must respect. The positive target is an ordinary ``static``
method with no callers, no override relationship, no reflection, native, manifest or
resource dependency, that contributes a unique string and a unique framework API reference
so the removal exercises the full string / API consequence prediction.
"""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from tests.fixtures.h1_apks import PKG, Fixture, _cls
from tests.fixtures.h3_apks import _RES, publish_fixture, publisher_key

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from apkforge.builders import BuildService, SigningConfig

__all__ = [
    "FAULTS",
    "H5_FIXTURES",
    "MULTIPARAM_TARGET",
    "OVERLOAD_KEEP",
    "OVERLOAD_TARGET",
    "PKG",
    "TARGET",
    "TARGET_CLASS",
    "TARGET_SIGNATURE",
    "TARGET_SMALI",
    "build_corpus",
    "inject_at_build",
    "publish_fixture",
    "publisher_key",
]

#: the decoded smali file and the method signature of the h5_isolated positive target
TARGET_SMALI = "smali/com/example/h1/B.smali"
TARGET_SIGNATURE = "isolatedStamp()Ljava/lang/String;"

#: the positive target: an isolated static method of a plain class
TARGET_CLASS = f"{PKG}.B"
TARGET = f"{TARGET_CLASS}->isolatedStamp()Ljava/lang/String;"
#: the eligible overload and the two overloads that must remain
OVERLOAD_TARGET = f"{PKG}.B->foo(I)V"
OVERLOAD_KEEP = (f"{PKG}.B->foo()V", f"{PKG}.B->foo(Ljava/lang/String;)V")
#: an isolated static method with several (primitive, object, wide) parameters
MULTIPARAM_TARGET = f"{PKG}.B->combine(ILjava/lang/String;J)Ljava/lang/String;"

#: an isolated static method: one unique string + one unique framework API, no callers
_ISOLATED_STAMP = (
    "\n.method public static isolatedStamp()Ljava/lang/String;\n"
    "    .registers 1\n"
    "    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;\n"
    '    const-string v0, "h5-only-in-this-method"\n'
    "    return-object v0\n"
    ".end method\n"
)
#: three static overloads of foo; only foo(I)V carries a unique string
_OVERLOADS = (
    "\n.method public static foo()V\n    .registers 0\n    return-void\n.end method\n"
    "\n.method public static foo(I)V\n    .registers 2\n"
    '    const-string v0, "h5-only-in-foo-int"\n    return-void\n.end method\n'
    "\n.method public static foo(Ljava/lang/String;)V\n    .registers 1\n    return-void\n.end method\n"
)
#: B.combine(int, String, long): Phase E keys it as combine(int,java.lang.String,long)...
_MULTIPARAM = (
    "\n.method public static combine(ILjava/lang/String;J)Ljava/lang/String;\n"
    "    .registers 5\n"
    '    const-string v0, "h5-only-in-combine"\n'
    "    return-object v0\n"
    ".end method\n"
)
_CALLER = "\n.method public static callee()V\n    .registers 0\n    return-void\n.end method\n"
_INSTANCE_RUN = "\n.method public run()V\n    .registers 1\n    return-void\n.end method\n"

# interface Iface with one abstract method; B implements it
_IFACE = (
    ".class public abstract interface Lcom/example/h1/Iface;\n"
    ".super Ljava/lang/Object;\n"
    '.source "Iface.java"\n\n'
    ".method public abstract handle()V\n.end method\n"
)
_B_IMPLEMENTS = (
    ".class public Lcom/example/h1/B;\n"
    ".super Ljava/lang/Object;\n"
    ".implements Lcom/example/h1/Iface;\n"
    '.source "B.java"\n\n'
    ".method public constructor <init>()V\n"
    "    .registers 1\n"
    "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n"
    "    return-void\n"
    ".end method\n\n"
    ".method public handle()V\n    .registers 1\n    return-void\n.end method\n"
)


def _fx(name: str, description: str, classes: dict[str, str], **kw: object) -> Fixture:
    files = {**_RES, **kw.pop("files", {})}  # type: ignore[dict-item]
    return Fixture(name, description, classes, files=files, **kw)  # type: ignore[arg-type]


H5_FIXTURES: list[Fixture] = [
    _fx(
        "h5_isolated",
        "A (activity) and B; B.isolatedStamp() is an isolated static method using a unique "
        "string + framework API",
        {"A": _cls("A"), "B": _cls("B", _ISOLATED_STAMP)},
    ),
    _fx(
        "h5_isolated_alt",
        "same shape as h5_isolated with a different A (a second, distinct APK for SHA tests)",
        {
            "A": _cls(
                "A",
                "\n.method public static tag()V\n    .registers 0\n    return-void\n.end method\n",
            ),
            "B": _cls("B", _ISOLATED_STAMP),
        },
    ),
    _fx(
        "h5_overloads",
        "B declares foo()V, foo(I)V and foo(Ljava/lang/String;)V (all isolated static); only "
        "foo(I)V is targeted",
        {"A": _cls("A"), "B": _cls("B", _OVERLOADS)},
    ),
    _fx(
        "h5_multiparam",
        "B.combine(ILjava/lang/String;J) is an isolated static method with several parameters",
        {"A": _cls("A"), "B": _cls("B", _MULTIPARAM)},
    ),
    _fx(
        "h5_caller",
        "A.go() calls B.callee() (static call site)",
        {
            "A": _cls(
                "A",
                "\n.method public static go()V\n    .registers 0\n"
                f"    invoke-static {{}}, L{PKG.replace('.', '/')}/B;->callee()V\n"
                "    return-void\n.end method\n",
            ),
            "B": _cls("B", _CALLER),
        },
    ),
    _fx(
        "h5_reflection",
        "A.load(String) calls Class.forName(p1) (unresolved reflection); B.isolatedStamp() "
        "otherwise isolated",
        {
            "A": _cls(
                "A",
                "\n.method public static load(Ljava/lang/String;)Ljava/lang/Class;\n"
                "    .registers 3\n"
                "    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n"
                "    move-result-object v0\n    return-object v0\n.end method\n",
            ),
            "B": _cls("B", _ISOLATED_STAMP),
        },
    ),
    _fx(
        "h5_native",
        "B.isolatedStamp() isolated, but a bundled .so and System.loadLibrary make native code present (unanalysed)",
        {
            "A": _cls(
                "A",
                "\n.method static constructor <clinit>()V\n"
                "    .registers 1\n"
                '    const-string v0, "h5native"\n'
                "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
                "    return-void\n.end method\n",
            ),
            "B": _cls("B", _ISOLATED_STAMP),
        },
        files={"lib/arm64-v8a/libh5native.so": b"\x7fELF\x02\x01\x01\x00synthetic"},
    ),
    _fx(
        "h5_override",
        "A declares run()V (instance); B extends A and overrides run()V",
        {
            "A": _cls("A", _INSTANCE_RUN),
            "B": _cls("B", _INSTANCE_RUN, super_="Lcom/example/h1/A;"),
        },
    ),
    _fx(
        "h5_interface",
        "interface Iface declares abstract handle()V; B implements it",
        {"A": _cls("A"), "Iface": _IFACE, "B": _B_IMPLEMENTS},
    ),
]


def build_corpus(service: BuildService, work: Path, publisher: SigningConfig) -> dict[str, Path]:
    """Publish every H.5 fixture; returns ``{name: apk}``."""
    return {fx.name: publish_fixture(service, fx, work, publisher) for fx in H5_FIXTURES}


# ---------------------------------------------------------------------------
# Fault injection into the transformed build only (the control rebuild of the
# original still carries the method, so the edit never touches it).
# ---------------------------------------------------------------------------

_A_SMALI = "smali/com/example/h1/A.smali"


def _modify_other_class(project: Path) -> None:
    """Change an unrelated class's method body (A), so A appears modified."""
    path = project / _A_SMALI
    path.write_text(path.read_text().replace("return-void", "nop\n    return-void", 1))


def _leave_reference(project: Path) -> None:
    """Add a call to the removed method from A.bar(), leaving a dangling reference."""
    path = project / _A_SMALI
    text = path.read_text()
    inject = "    invoke-static {}, Lcom/example/h1/B;->isolatedStamp()Ljava/lang/String;\n    return-void"
    path.write_text(text.replace("    return-void", inject, 1))


def _modify_resource(project: Path) -> None:
    path = project / "res/values/strings.xml"
    path.write_text(path.read_text().replace(">H3<", ">H3-tampered<"))


def _modify_manifest(project: Path) -> None:
    path = project / "AndroidManifest.xml"
    perm = '<uses-permission android:name="android.permission.INTERNET"/>\n    <application'
    path.write_text(path.read_text().replace("<application", perm, 1))


def _add_native(project: Path) -> None:
    lib = project / "lib/arm64-v8a/libinjected.so"
    lib.parent.mkdir(parents=True, exist_ok=True)
    lib.write_bytes(b"\x7fELF\x02\x01\x01\x00injected-by-a-faulty-build")


def _add_asset(project: Path) -> None:
    asset = project / "assets/injected.txt"
    asset.parent.mkdir(parents=True, exist_ok=True)
    asset.write_bytes(b"not part of the plan")


#: fault -> (edit of the transformed project, domain H.4 must reject it in)
FAULTS: dict[str, tuple[Callable[[Path], None], str]] = {
    "other_method_modified": (_modify_other_class, "dex"),
    "reference_left": (_leave_reference, "dex"),
    "resource_modified": (_modify_resource, "resources"),
    "manifest_modified": (_modify_manifest, "manifest"),
    "native_added": (_add_native, "native"),
    "asset_added": (_add_asset, "assets"),
}


@contextlib.contextmanager
def inject_at_build(service: BuildService, edit: Callable[[Path], None]) -> Iterator[None]:
    """While active, ``service.build`` applies *edit* to a decoded project in which the
    target method has already been removed (i.e. only the transformed build, never the
    control rebuild, whose project still declares the method)."""
    real = service.build

    def build(project: Path, out: Path, **kw: Any) -> Any:
        if TARGET_SIGNATURE not in (project / TARGET_SMALI).read_text(encoding="utf-8"):
            edit(project)
        return real(project, out, **kw)

    service.build = build  # type: ignore[method-assign]
    try:
        yield
    finally:
        service.build = real  # type: ignore[method-assign]
