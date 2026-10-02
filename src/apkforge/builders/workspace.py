"""Isolated per-build workspaces.

Layout::

    <base>/<build-id>/
        input/<name>.apk        private copy of the input; tools never see the original
        decoded/                Apktool decode output (untrusted content)
        build/unaligned.apk     Apktool build output
        aligned/aligned.apk     zipalign output
        signed/signed.apk       apksigner output (the final APK)
        logs/build.log          pipeline summary; logs/stage-<stage>.log has full tool output
        metadata/result.json    serialized BuildResult

Build ids embed a UTC timestamp and a random suffix and the directory is created
with ``exist_ok=False``, so concurrent builds can never share a workspace.

Retention: a failed build keeps everything (by default). A successful build
without ``keep`` removes the bulky intermediates (input/, decoded/, build/,
aligned/) and keeps logs/ and metadata/; signed/ is kept unless the APK was
exported elsewhere.
"""

from __future__ import annotations

import datetime
import shutil
import uuid
from pathlib import Path

from apkforge.core.exceptions import WorkspaceError

__all__ = ["BuildWorkspace", "new_build_id"]

_INTERMEDIATE_DIRS = ("input", "decoded", "build", "aligned")


def new_build_id() -> str:
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


class BuildWorkspace:
    """Filesystem workspace for a single BuildService execution."""

    def __init__(self, root: Path, build_id: str) -> None:
        self.root = root.resolve()
        self.build_id = build_id
        self.input_dir = self.root / "input"
        self.decoded_dir = self.root / "decoded"
        self.build_dir = self.root / "build"
        self.aligned_dir = self.root / "aligned"
        self.signed_dir = self.root / "signed"
        self.logs_dir = self.root / "logs"
        self.metadata_dir = self.root / "metadata"
        self.unaligned_apk = self.build_dir / "unaligned.apk"
        self.aligned_apk = self.aligned_dir / "aligned.apk"
        self.signed_apk = self.signed_dir / "signed.apk"
        self.master_log = self.logs_dir / "build.log"
        self.result_json = self.metadata_dir / "result.json"
        self.input_apk: Path | None = None

    @classmethod
    def create(cls, base_dir: Path, build_id: str | None = None) -> BuildWorkspace:
        build_id = build_id or new_build_id()
        base_dir = base_dir.resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        root = base_dir / build_id
        root.mkdir(exist_ok=False)
        ws = cls(root, build_id)
        for d in (
            ws.input_dir,
            ws.build_dir,
            ws.aligned_dir,
            ws.signed_dir,
            ws.logs_dir,
            ws.metadata_dir,
        ):
            d.mkdir()
        return ws

    def import_input(self, apk: Path) -> Path:
        """Copy the input APK into ``input/``; the original is never handed to a tool."""
        dest = self.subpath("input", "original.apk")
        shutil.copyfile(apk, dest)
        dest.chmod(0o444)
        self.input_apk = dest
        return dest

    def subpath(self, *parts: str) -> Path:
        """Path inside the workspace; rejects anything that would escape it."""
        candidate = (self.root / Path(*parts)).resolve()
        if not candidate.is_relative_to(self.root):
            raise WorkspaceError(
                f"Path traversal detected: {candidate} escapes workspace {self.root}",
                context="build-workspace",
            )
        return candidate

    def stage_log(self, stage: str) -> Path:
        return self.logs_dir / f"stage-{stage}.log"

    def append_log(self, text: str) -> None:
        with self.master_log.open("a", encoding="utf-8") as f:
            f.write(text + "\n")

    def apply_retention(self, *, success: bool, keep: bool, exported: bool) -> None:
        """Delete files according to the retention policy (see module docstring)."""
        if keep or not success:
            return
        for name in _INTERMEDIATE_DIRS:
            target = self.root / name
            if target.exists():
                # input/original.apk is read-only; rmtree needs write on the dir only.
                shutil.rmtree(target, ignore_errors=True)
        if exported:
            shutil.rmtree(self.signed_dir, ignore_errors=True)
