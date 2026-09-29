"""Unit tests — Workspace abstraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from apkforge.core.exceptions import WorkspaceError
from apkforge.core.models import APKInput
from apkforge.core.workspace import Workspace


def _make_apk(tmp_path: Path, name: str = "test.apk") -> APKInput:
    apk = tmp_path / name
    apk.write_bytes(b"PK")  # minimal content
    return APKInput(path=apk)


class TestWorkspaceCreate:
    @pytest.mark.unit()
    def test_creates_directory(self, tmp_path: Path) -> None:
        ws = Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws")
        try:
            assert ws.root.exists()
            assert ws.root.is_dir()
        finally:
            ws.cleanup()

    @pytest.mark.unit()
    def test_session_id_unique(self, tmp_path: Path) -> None:
        apk = _make_apk(tmp_path)
        ws1 = Workspace.create(apk, base_dir=tmp_path / "ws")
        ws2 = Workspace.create(apk, base_dir=tmp_path / "ws")
        try:
            assert ws1.session_id != ws2.session_id
            assert ws1.root != ws2.root
        finally:
            ws1.cleanup()
            ws2.cleanup()

    @pytest.mark.unit()
    def test_source_apk_preserved(self, tmp_path: Path) -> None:
        apk = _make_apk(tmp_path)
        ws = Workspace.create(apk, base_dir=tmp_path / "ws")
        try:
            assert ws.source_apk.path == apk.path
        finally:
            ws.cleanup()


class TestWorkspaceSubpath:
    @pytest.mark.unit()
    def test_valid_subpath(self, tmp_path: Path) -> None:
        ws = Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws")
        try:
            p = ws.subpath("smali", "com", "example", "App.smali")
            assert ws.root in p.parents or p.parent == ws.root
        finally:
            ws.cleanup()

    @pytest.mark.unit()
    def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        ws = Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws")
        try:
            with pytest.raises(WorkspaceError, match="traversal"):
                ws.subpath("..", "..", "etc", "passwd")
        finally:
            ws.cleanup()


class TestWorkspaceCleanup:
    @pytest.mark.unit()
    def test_cleanup_removes_directory(self, tmp_path: Path) -> None:
        ws = Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws")
        root = ws.root
        assert root.exists()
        ws.cleanup()
        assert not root.exists()

    @pytest.mark.unit()
    def test_cleanup_idempotent(self, tmp_path: Path) -> None:
        ws = Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws")
        ws.cleanup()
        ws.cleanup()  # second call must not raise
        assert ws.is_closed

    @pytest.mark.unit()
    def test_context_manager(self, tmp_path: Path) -> None:
        root: Path | None = None
        with Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws") as ws:
            root = ws.root
            assert root.exists()
        assert root is not None
        assert not root.exists()

    @pytest.mark.unit()
    def test_context_manager_cleanup_on_exception(self, tmp_path: Path) -> None:
        root: Path | None = None
        with (
            pytest.raises(RuntimeError),
            Workspace.create(_make_apk(tmp_path), base_dir=tmp_path / "ws") as ws,
        ):
            root = ws.root
            raise RuntimeError("simulated failure")
        assert root is not None
        assert not root.exists()


class TestWorkspaceSecurity:
    @pytest.mark.unit()
    def test_workspace_inside_base_dir(self, tmp_path: Path) -> None:
        base = tmp_path / "apkforge_base"
        ws = Workspace.create(_make_apk(tmp_path), base_dir=base)
        try:
            # The workspace root must be inside the configured base directory
            assert str(ws.root).startswith(str(base))
        finally:
            ws.cleanup()

    @pytest.mark.unit()
    def test_original_apk_not_modified(self, tmp_path: Path) -> None:
        apk = tmp_path / "original.apk"
        original_content = b"PK original content"
        apk.write_bytes(original_content)
        apk_input = APKInput(path=apk)

        with Workspace.create(apk_input, base_dir=tmp_path / "ws"):
            # In Phase 0 nothing modifies the APK, but we verify the contract
            assert apk.read_bytes() == original_content
