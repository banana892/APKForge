"""Phase H.6 synthetic APK corpus for H-TRANS-003 (controlled call-site replacement).

Built and published exactly like the H.3/H.5 corpora (tests/fixtures/h3_apks.py): a
hand-written Apktool project in package ``com.example.h1``, built with BuildService,
round-tripped once and signed v2/v3 by a separate publisher key.

``h6_callsite`` is the positive APK. Its caller ``A`` invokes ``Source`` in every shape the
contract distinguishes, and ``Replacement`` declares compatible and incompatible
replacements, so one APK carries the positive targets (static, wide/primitive arguments
with a returned primitive, private-instance ``invoke-direct``, the second of two identical
calls) *and* the H.2 refusals that need no special environment (missing / ambiguous /
repeated call site, signature / argument / return mismatches, inaccessible replacement,
constructor and virtual calls). ``Replacement`` is never invoked by the original APK, so
its appearance in ``A`` marks the transformed build.

The other fixtures each add one environment the eligibility rules must respect
(unresolved reflection, unanalysed native code, invoke-custom / invoke-polymorphic).
Nothing here is hard-coded into H.6: H.2 decides every outcome from H.1 evidence.
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
    "ARGS_REPLACEMENT",
    "ARGS_TARGET",
    "CALLER_SMALI",
    "FAULTS",
    "H6_FIXTURES",
    "INSTANCE_REPLACEMENT",
    "INSTANCE_TARGET",
    "PKG",
    "REPEATED_TARGET",
    "REPLACEMENT",
    "STATIC_TARGET",
    "build_corpus",
    "inject_at_build",
    "publish_fixture",
    "publisher_key",
]

_P = PKG.replace(".", "/")
SRC = f"L{_P}/Source;"
REP = f"L{_P}/Replacement;"
CALLER_SMALI = "smali/com/example/h1/A.smali"

GET = "getValue()Ljava/lang/String;"
COMPUTE = "compute(IJLjava/lang/String;)I"

#: positive targets (H-TRANS-003 ``CALLER@INVOKED[#N]``) and their replacements
STATIC_TARGET = f"{PKG}.A->run()Ljava/lang/String;@{PKG}.Source->{GET}"
REPLACEMENT = f"{PKG}.Replacement->{GET}"
ARGS_TARGET = f"{PKG}.A->calc(IJLjava/lang/String;)I@{PKG}.Source->{COMPUTE}"
ARGS_REPLACEMENT = f"{PKG}.Replacement->{COMPUTE}"
INSTANCE_TARGET = f"{PKG}.A->instanceCall()Ljava/lang/String;@{PKG}.A->secret()Ljava/lang/String;"
INSTANCE_REPLACEMENT = f"{PKG}.A->secretAlt()Ljava/lang/String;"
REPEATED_TARGET = f"{PKG}.A->twice()Ljava/lang/String;@{PKG}.Source->{GET}#2"


def _m(header: str, regs: int, *body: str) -> str:
    lines = "".join(f"    {b}\n" for b in body)
    return f"\n.method {header}\n    .registers {regs}\n{lines}.end method\n"


_SOURCE_BODY = (
    _m(f"public static {GET}", 1, 'const-string v0, "h6-source"', "return-object v0")
    + _m(f"public static {COMPUTE}", 4, "return p0")
    + _m("public instanceValue()Ljava/lang/String;", 2, 'const-string v0, "h6-instance"',
         "return-object v0")
)  # fmt: skip
_SOURCE = _cls("Source", _SOURCE_BODY)

_REPLACEMENT_BODY = (
    _m(f"public static {GET}", 1, 'const-string v0, "h6-replacement"', "return-object v0")
    + _m(f"public static {COMPUTE}", 4, "add-int/lit8 p0, p0, 0x1", "return p0")
    # incompatible replacements (each refused by H.2 for exactly one reason)
    + _m("public getValueInstance()Ljava/lang/String;", 2, 'const-string v0, "h6-i"',
         "return-object v0")
    + _m("public static getValueArg(I)Ljava/lang/String;", 2, 'const-string v0, "h6-a"',
         "return-object v0")
    + _m("public static getValueInt()I", 1, "const/4 v0, 0x1", "return v0")
    + _m("private static hidden()Ljava/lang/String;", 1, 'const-string v0, "h6-h"',
         "return-object v0")
)  # fmt: skip
_REPLACEMENT = _cls("Replacement", _REPLACEMENT_BODY)

_CALLER_BODY = (
    # static, object result
    _m("public static run()Ljava/lang/String;", 1,
       f"invoke-static {{}}, {SRC}->{GET}", "move-result-object v0", "return-object v0")
    # primitive + wide + object arguments, primitive result
    + _m("public static calc(IJLjava/lang/String;)I", 5,
         f"invoke-static {{p0, p1, p2, p3}}, {SRC}->{COMPUTE}", "move-result v0", "return v0")
    # private instance method (invoke-direct), same class
    + _m("public instanceCall()Ljava/lang/String;", 2,
         f"invoke-direct {{p0}}, L{_P}/A;->secret()Ljava/lang/String;", "move-result-object v0",
         "return-object v0")
    + _m("private secret()Ljava/lang/String;", 2, 'const-string v0, "h6-secret"',
         "return-object v0")
    + _m("private secretAlt()Ljava/lang/String;", 2, 'const-string v0, "h6-secret-alt"',
         "return-object v0")
    # the same call twice: only #2 is the positive target
    + _m("public static twice()Ljava/lang/String;", 2,
         f"invoke-static {{}}, {SRC}->{GET}", "move-result-object v0",
         f"invoke-static {{}}, {SRC}->{GET}", "move-result-object v1", "return-object v1")
    # overloaded callers (an unqualified caller name is ambiguous); results discarded
    + _m("public static over()V", 0, f"invoke-static {{}}, {SRC}->{GET}", "return-void")
    + _m("public static over(I)V", 1, f"invoke-static {{}}, {SRC}->{GET}", "return-void")
    # constructor and virtual invocations (unsupported shapes)
    + _m("public static make()Ljava/lang/Object;", 1, f"new-instance v0, {SRC}",
         f"invoke-direct {{v0}}, {SRC}-><init>()V", "return-object v0")
    + _m(f"public static virt({SRC})Ljava/lang/String;", 2,
         f"invoke-virtual {{p0}}, {SRC}->instanceValue()Ljava/lang/String;",
         "move-result-object v0", "return-object v0")
)  # fmt: skip

#: the positive APK's classes
_CLASSES = {"A": _cls("A", _CALLER_BODY), "Source": _SOURCE, "Replacement": _REPLACEMENT}

#: invoke-polymorphic (interpreted by H.1) in A; invoke-custom (not interpreted: D's file
#: is PARTIAL, so the DEX is PARTIAL) in D, next to an ordinary static call
_BSM = "bsm(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
_POLY = _m(
    "public static poly(Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;", 2,
    "invoke-polymorphic {p0}, Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;, ()Ljava/lang/Object;",
    "move-result-object v0", "return-object v0",
)  # fmt: skip
_D_CUSTOM = _cls(
    "D",
    _m("public static custom()Ljava/lang/Runnable;", 1,
       f'invoke-custom {{}}, call_site_0("run", ()Ljava/lang/Runnable;)@{SRC}->{_BSM}',
       "move-result-object v0", "return-object v0")
    + _m("public static mixed()Ljava/lang/String;", 1,
         f"invoke-static {{}}, {SRC}->{GET}", "move-result-object v0", "return-object v0"),
)  # fmt: skip
_SOURCE_WITH_BSM = _cls(
    "Source", _SOURCE_BODY + _m(f"public static {_BSM}", 4, "const/4 v0, 0x0", "return-object v0")
)

_NATIVE_REPLACEMENT = _cls(
    "Replacement",
    _REPLACEMENT_BODY
    + "\n.method public static native nativeValue()Ljava/lang/String;\n.end method\n",
)


def _fx(name: str, description: str, classes: dict[str, str], **kw: object) -> Fixture:
    files = {**_RES, **kw.pop("files", {})}  # type: ignore[dict-item]
    return Fixture(name, description, classes, files=files, **kw)  # type: ignore[arg-type]


H6_FIXTURES: list[Fixture] = [
    _fx(
        "h6_callsite",
        "A invokes Source (static, wide args, repeated, overloaded callers, constructor, "
        "virtual) and its own private secret(); Replacement declares compatible and "
        "incompatible replacements",
        dict(_CLASSES),
    ),
    _fx(
        "h6_callsite_alt",
        "same shape as h6_callsite with one more A method (a second, distinct APK)",
        {
            **_CLASSES,
            "A": _cls("A", _CALLER_BODY + _m("public static tag()V", 0, "return-void")),
        },
    ),
    _fx(
        "h6_reflection",
        "h6_callsite + C.load(String) calls Class.forName(p0) (unresolved reflection)",
        {
            **_CLASSES,
            "C": _cls(
                "C",
                _m(
                    "public static load(Ljava/lang/String;)Ljava/lang/Class;",
                    2,
                    "invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
                    "move-result-object v0",
                    "return-object v0",
                ),
            ),
        },
    ),
    _fx(
        "h6_native",
        "h6_callsite + a bundled .so loaded by C.<clinit> (native code present, unanalysed); "
        "Replacement also declares a native nativeValue()",
        {
            **_CLASSES,
            "Replacement": _NATIVE_REPLACEMENT,
            "C": _cls(
                "C",
                _m(
                    "static constructor <clinit>()V",
                    1,
                    'const-string v0, "h6native"',
                    "invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
                    "return-void",
                ),
            ),
        },
        files={"lib/arm64-v8a/libh6native.so": b"\x7fELF\x02\x01\x01\x00synthetic"},
    ),
    _fx(
        "h6_dynamic",
        "A.poly() uses invoke-polymorphic; D.custom() uses invoke-custom (D's file and the DEX "
        "are PARTIAL); A.run() and D.mixed() also call Source.getValue()",
        {
            "A": _cls("A", _CALLER_BODY + _POLY),
            "Source": _SOURCE_WITH_BSM,
            "Replacement": _REPLACEMENT,
            "D": _D_CUSTOM,
        },
        min_sdk=26,
    ),
]


def build_corpus(service: BuildService, work: Path, publisher: SigningConfig) -> dict[str, Path]:
    """Publish every H.6 fixture; returns ``{name: apk}``."""
    return {fx.name: publish_fixture(service, fx, work, publisher) for fx in H6_FIXTURES}


# ---------------------------------------------------------------------------
# Fault injection into the transformed build only. The control rebuild of the original
# never invokes Replacement->getValue(), so an edit keyed on it never touches the control.
# ---------------------------------------------------------------------------

_MARK = f"{REP}->{GET}"


def _modify_other_method(project: Path) -> None:
    """Change an unrelated method body of the caller class (A.calc)."""
    path = project / CALLER_SMALI
    path.write_text(path.read_text().replace("move-result v0\n", "move-result v0\n    nop\n", 1))


def _modify_other_class(project: Path) -> None:
    """Change an unrelated class (Source.getValue returns another string)."""
    path = project / "smali/com/example/h1/Source.smali"
    path.write_text(path.read_text().replace('"h6-source"', '"h6-tampered"'))


def _second_call_site(project: Path) -> None:
    """Also replace the call in A.twice() (a second, unplanned call-site change)."""
    path = project / CALLER_SMALI
    text = path.read_text()
    start = text.index("twice()")
    path.write_text(text[:start] + text[start:].replace(f"{SRC}->{GET}", _MARK, 1))


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
    "other_method_modified": (_modify_other_method, "dex"),
    "other_class_modified": (_modify_other_class, "dex"),
    "second_call_site": (_second_call_site, "dex"),
    "resource_modified": (_modify_resource, "resources"),
    "manifest_modified": (_modify_manifest, "manifest"),
    "native_added": (_add_native, "native"),
    "asset_added": (_add_asset, "assets"),
}


@contextlib.contextmanager
def inject_at_build(service: BuildService, edit: Callable[[Path], None]) -> Iterator[None]:
    """While active, ``service.build`` applies *edit* to a decoded project whose caller
    already invokes the replacement (the transformed build only, never the control)."""
    real = service.build

    def build(project: Path, out: Path, **kw: Any) -> Any:
        caller = project / CALLER_SMALI
        if caller.is_file() and _MARK in caller.read_text(encoding="utf-8"):
            edit(project)
        return real(project, out, **kw)

    service.build = build  # type: ignore[method-assign]
    try:
        yield
    finally:
        service.build = real  # type: ignore[method-assign]
