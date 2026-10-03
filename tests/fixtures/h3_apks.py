"""Phase H.3 synthetic APK corpus (real, rebuildable, publisher-signed APKs).

Built like the H.1/H.2 fixtures (hand-written smali in an Apktool project, package
``com.example.h1``), then *published* the way a real app is: decoded and rebuilt once with
BuildService (so the resource table is a rebuild fixed point), aligned and signed with a
separate "publisher" key, v2/v3 only. The H.3 output is therefore re-signed by a
different key, as with any real APK, and the no-op rebuild of every fixture is
semantically EQUIVALENT (only the signature is replaced).

Positive fixtures are designed so that H.2 can establish ``ELIGIBLE`` for the target;
the others reproduce each refusal/uncertainty class H.3 must not bypass.
"""

# ruff: noqa: E501 - verbatim smali instructions (long type descriptors) cannot be wrapped

from __future__ import annotations

import subprocess
import textwrap
from typing import TYPE_CHECKING

from apkforge.builders import SigningConfig
from tests.fixtures.h1_apks import PKG, Fixture, _cls, _method, build_fixture

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.builders import BuildService

__all__ = ["H3_FIXTURES", "PKG", "TARGET", "publish_fixture", "publisher_key"]

TARGET = f"{PKG}.B"
_RES = {
    "res/values/strings.xml": textwrap.dedent(
        """\
        <?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="app_name">H3</string>
        </resources>
        """
    ).encode()
}
_PASSWORD = "h3-fixture-publisher"
_ALIAS = "h3publisher"

#: B uses a string and a framework API no other class uses: removing B must remove both
_B_ISOLATED = _cls(
    "B",
    _method(
        "stamp",
        "()Ljava/lang/String;",
        3,
        """
        invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;
        const-string v0, "h3-only-in-b"
        return-object v0
        """,
    ),
)
_A_PLAIN = _cls(
    "A",
    _method(
        "now",
        "()J",
        2,
        """
        invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
        move-result-wide v0
        return-wide v0
        """,
    ),
)
_C_PLAIN = _cls("C", _method("ping", "()V", 1, "return-void"))


def _fx(name: str, description: str, classes: dict[str, str], **kw: object) -> Fixture:
    files = {**_RES, **kw.pop("files", {})}  # type: ignore[dict-item]
    return Fixture(name, description, classes, files=files, **kw)  # type: ignore[arg-type]


H3_FIXTURES: list[Fixture] = [
    _fx(
        "h3_isolated",
        "A (activity), B and C; B is isolated and uses a unique string + framework API",
        {"A": _A_PLAIN, "B": _B_ISOLATED, "C": _C_PLAIN},
    ),
    _fx(
        "h3_isolated_alt",
        "same shape as h3_isolated with a different C (a second, distinct APK)",
        {"A": _A_PLAIN, "B": _B_ISOLATED, "C": _cls("C", _method("pong", "()V", 1, "return-void"))},
    ),
    _fx(
        "h3_caller",
        "A.go() -> B.bar() (static call)",
        {
            "A": _cls(
                "A",
                _method(
                    "go",
                    "()V",
                    1,
                    f"""
                    invoke-static {{}}, L{PKG.replace(".", "/")}/B;->bar()V
                    return-void
                    """,
                ),
            ),
            "B": _B_ISOLATED,
            "C": _C_PLAIN,
        },
    ),
    _fx(
        "h3_reflection",
        "A.load(String) calls Class.forName(p1) (unresolved reflection); B otherwise isolated",
        {
            "A": _cls(
                "A",
                _method(
                    "load",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    3,
                    """
                    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
                    move-result-object v0
                    return-object v0
                    """,
                ),
            ),
            "B": _B_ISOLATED,
            "C": _C_PLAIN,
        },
    ),
    _fx(
        "h3_native",
        'B declares a native method; A calls System.loadLibrary("h3native") with a bundled .so',
        {
            "A": _cls(
                "A",
                "\n.method static constructor <clinit>()V\n"
                "    .registers 1\n"
                '    const-string v0, "h3native"\n'
                "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
                "    return-void\n"
                ".end method\n",
            ),
            "B": _cls("B", "\n.method public static native nativeCall(I)I\n.end method\n"),
            "C": _C_PLAIN,
        },
        files={"lib/arm64-v8a/libh3native.so": b"\x7fELF\x02\x01\x01\x00synthetic"},
    ),
    _fx(
        "h3_manifest",
        "B is declared as a <service> in the manifest; otherwise isolated",
        {"A": _A_PLAIN, "B": _B_ISOLATED, "C": _C_PLAIN},
        manifest_components='        <service android:name=".B" android:exported="false"/>',
    ),
]


def publisher_key(keytool: Path, directory: Path) -> SigningConfig:
    """A throwaway "publisher" key (not the APKForge development key)."""
    directory.mkdir(parents=True, exist_ok=True)
    keystore = directory / "publisher.p12"
    password = directory / "password"
    if not keystore.is_file():
        password.write_text(_PASSWORD)
        subprocess.run(
            [
                str(keytool),
                "-genkeypair",
                "-keystore",
                str(keystore),
                "-storetype",
                "PKCS12",
                "-alias",
                _ALIAS,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-storepass",
                _PASSWORD,
                "-keypass",
                _PASSWORD,
                "-dname",
                "CN=H3 fixture publisher",
            ],
            check=True,
            capture_output=True,
        )
    return SigningConfig(keystore=keystore, alias=_ALIAS, password_file=password)


def publish_fixture(
    service: BuildService, fx: Fixture, work: Path, publisher: SigningConfig
) -> Path:
    """Build *fx*, round-trip it once through BuildService and sign it v2/v3-only with
    *publisher*. Returns ``work/published/<name>.apk``."""
    raw = build_fixture(service, fx, work)
    ws, prep = service.prepare_workspace(work_dir=work / "publish-ws")
    if ws is None:
        raise RuntimeError(f"{fx.name}: {prep.failure_cause}")
    for stage in (
        service.decode(raw, ws),
        service.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws),
        service.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws),
    ):
        if not stage.passed:
            raise RuntimeError(f"{fx.name}: {stage.stage} failed: {stage.failure_cause}")
    out = work / "published" / f"{fx.name}.apk"
    out.parent.mkdir(parents=True, exist_ok=True)
    apksigner = service.toolchain.apksigner
    assert apksigner is not None
    subprocess.run(
        [
            str(apksigner),
            "sign",
            "--v1-signing-enabled",
            "false",
            "--ks",
            str(publisher.keystore),
            "--ks-key-alias",
            publisher.alias,
            "--ks-pass",
            f"pass:{_PASSWORD}",
            "--out",
            str(out),
            str(ws.aligned_apk),
        ],
        check=True,
        capture_output=True,
    )
    return out
