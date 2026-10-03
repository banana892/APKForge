"""Phase H.4 synthetic helpers on top of the H.3 corpus (tests/fixtures/h3_apks.py).

- :func:`unpublished_fixture`: an H.3 fixture built and signed by the publisher key
  *without* the publishing round trip, so its resource table is not yet the toolchain's
  fixed point: every rebuild re-encodes ``resources.arsc`` (measured by the control
  rebuild, never assumed). H.2 still decides ELIGIBLE for the target.
- :func:`inject_at_build`: a fault injected into the *transformed* build only (the
  decoded project no longer holds the target's smali file), after H.3's mutation and
  source checks, so the faulty APK is built, aligned and signed like a real output.
  The control rebuild is untouched.
"""

from __future__ import annotations

import contextlib
import subprocess
from typing import TYPE_CHECKING, Any

from tests.fixtures.h1_apks import build_fixture

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from apkforge.builders import BuildService, SigningConfig
    from tests.fixtures.h1_apks import Fixture

__all__ = ["FAULTS", "TARGET_SMALI", "inject_at_build", "unpublished_fixture"]

TARGET_SMALI = "smali/com/example/h1/B.smali"
_PASSWORD = "h3-fixture-publisher"  # tests/fixtures/h3_apks.py


def unpublished_fixture(
    service: BuildService, fx: Fixture, work: Path, publisher: SigningConfig
) -> Path:
    """Build *fx*, align it and sign it v2/v3-only with *publisher* (no round trip)."""
    raw = build_fixture(service, fx, work)
    ws, prep = service.prepare_workspace(work_dir=work / "unpublished-ws")
    if ws is None:
        raise RuntimeError(f"{fx.name}: {prep.failure_cause}")
    stage = service.align(raw, ws.aligned_apk, workspace=ws)
    if not stage.passed:
        raise RuntimeError(f"{fx.name}: align failed: {stage.failure_cause}")
    out = work / "unpublished" / f"{fx.name}.apk"
    out.parent.mkdir(parents=True, exist_ok=True)
    assert service.toolchain.apksigner is not None
    subprocess.run(
        [str(service.toolchain.apksigner), "sign", "--v1-signing-enabled", "false",
         "--ks", str(publisher.keystore), "--ks-key-alias", publisher.alias,
         "--ks-pass", f"pass:{_PASSWORD}", "--out", str(out), str(ws.aligned_apk)],
        check=True, capture_output=True,
    )  # fmt: skip
    return out


def _remove_other_class(project: Path) -> None:
    """The H.3 faulty mutation (target + unrelated class C removed), but late enough to
    be built: H.3's census and source checks have already passed."""
    (project / "smali/com/example/h1/C.smali").unlink()


def _edit_class(project: Path) -> None:
    path = project / "smali/com/example/h1/C.smali"
    path.write_text(path.read_text().replace("return-void", "nop\n    return-void", 1))


def _edit_resource(project: Path) -> None:
    path = project / "res/values/strings.xml"
    path.write_text(path.read_text().replace(">H3<", ">H3-tampered<"))


def _edit_manifest(project: Path) -> None:
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
    "other_class_removed": (_remove_other_class, "dex"),
    "other_class_modified": (_edit_class, "dex"),
    "resource_modified": (_edit_resource, "resources"),
    "manifest_modified": (_edit_manifest, "manifest"),
    "native_added": (_add_native, "native"),
    "asset_added": (_add_asset, "assets"),
}


@contextlib.contextmanager
def inject_at_build(service: BuildService, edit: Callable[[Path], None]) -> Iterator[None]:
    """While active, ``service.build`` applies *edit* to a decoded project that no longer
    holds the target (i.e. only the transformed build, never the control rebuild)."""
    real = service.build

    def build(project: Path, out: Path, **kw: Any) -> Any:
        if not (project / TARGET_SMALI).exists():
            edit(project)
        return real(project, out, **kw)

    service.build = build  # type: ignore[method-assign]
    try:
        yield
    finally:
        service.build = real  # type: ignore[method-assign]
