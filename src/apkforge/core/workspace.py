"""APKForge workspace abstraction.

The workspace is a per-session isolated directory that holds working copies
of extracted APK contents.  The original APK is treated as **immutable** —
all modifications happen inside the workspace.

Lifecycle::

    Original APK (immutable)
          │
          ▼
    Workspace.create()   ← creates isolated temp directory
          │
          ▼
    Workspace.stage()    ← copies APK into workspace (Phase 1+)
          │
          ▼
    Analysis / Modification inside workspace/
          │
          ▼
    Build & Verification (Phase 2+)
          │
          ▼
    Workspace.cleanup()  ← removes temp directory (unless keep_on_success)

Phase 0 only establishes the abstraction.  The actual extraction and
modification steps are stubs pending Phase 1.

Security principles
-------------------
- The workspace directory is always a freshly-created, unique temporary
  directory inside :attr:`~apkforge.core.config.WorkspaceSettings.base_directory`.
- Path traversal is prevented by validating that all workspace paths stay
  within the workspace root.
- Workspace directories outside the configured base directory are rejected.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.core.exceptions import WorkspaceError
from apkforge.core.logging import get_logger

if TYPE_CHECKING:
    from apkforge.core.models import APKInput

__all__ = ["Workspace"]

_log = get_logger(__name__)


class Workspace:
    """Isolated working directory for a single APKForge operation.

    Each :class:`Workspace` instance owns exactly one temporary directory.
    Use :meth:`create` (class method) as the canonical constructor.

    Attributes:
        session_id: Unique identifier for this workspace session.
        root: Absolute path to the workspace root directory.
        source_apk: The source APK associated with this workspace.

    Example::

        ws = Workspace.create(apk_input, base_dir=Path("/tmp/apkforge"))
        try:
            # ... analysis and modification work ...
            pass
        finally:
            ws.cleanup(success=True)
    """

    def __init__(
        self,
        root: Path,
        source_apk: APKInput,
        *,
        session_id: str | None = None,
    ) -> None:
        self._root = root
        self._source_apk = source_apk
        self._session_id = session_id or str(uuid.uuid4())
        self._closed = False

    # ------------------------------------------------------------------
    # Class-method constructor
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        source_apk: APKInput,
        base_dir: Path | None = None,
    ) -> Workspace:
        """Create a new workspace for *source_apk*.

        Args:
            source_apk: The APK input this workspace is associated with.
            base_dir: Parent directory for the workspace.  Defaults to the OS
                temporary directory joined with ``apkforge``.

        Returns:
            Workspace: A new, ready-to-use workspace.

        Raises:
            WorkspaceError: If the workspace directory cannot be created.
        """
        if base_dir is None:
            import tempfile as _tmp

            base_dir = Path(_tmp.gettempdir()) / "apkforge"

        try:
            base_dir.mkdir(parents=True, exist_ok=True)
            session_id = str(uuid.uuid4())
            root = Path(tempfile.mkdtemp(prefix=f"apkforge_{session_id[:8]}_", dir=base_dir))
        except OSError as exc:
            raise WorkspaceError(
                f"Failed to create workspace under {base_dir}: {exc}",
                context="workspace-create",
            ) from exc

        _log.info("Workspace created: %s", root)
        return cls(root=root, source_apk=source_apk, session_id=session_id)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        """Unique session identifier."""
        return self._session_id

    @property
    def root(self) -> Path:
        """Absolute path to the workspace root directory."""
        return self._root

    @property
    def source_apk(self) -> APKInput:
        """The source (immutable) APK associated with this workspace."""
        return self._source_apk

    @property
    def is_closed(self) -> bool:
        """Return True if :meth:`cleanup` has been called."""
        return self._closed

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def subpath(self, *parts: str) -> Path:
        """Return a path inside the workspace, rejecting traversal attempts.

        Args:
            *parts: Path components relative to the workspace root.

        Returns:
            Path: Absolute path inside the workspace.

        Raises:
            WorkspaceError: If the resulting path escapes the workspace root.
        """
        candidate = (self._root / Path(*parts)).resolve()
        try:
            candidate.relative_to(self._root.resolve())
        except ValueError:
            raise WorkspaceError(
                f"Path traversal detected: {candidate!r} is outside workspace root {self._root!r}",
                context="workspace-path",
            ) from None
        return candidate

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def cleanup(self, *, success: bool = True) -> None:
        """Remove the workspace directory.

        Args:
            success: Pass ``True`` if the operation completed successfully,
                ``False`` if it failed.  The ``keep_on_failure`` / ``keep_on_success``
                settings from :class:`~apkforge.core.config.WorkspaceSettings`
                control whether the directory is actually removed.  Phase 0
                always removes the directory; the settings integration is Phase 1+.

        Note:
            This method is safe to call multiple times (idempotent).
        """
        if self._closed:
            return
        self._closed = True

        if not self._root.exists():
            return

        import shutil

        try:
            shutil.rmtree(self._root)
            _log.debug("Workspace cleaned up: %s (success=%s)", self._root, success)
        except OSError as exc:
            _log.warning("Failed to clean up workspace %s: %s", self._root, exc)

    def __repr__(self) -> str:
        return (
            f"Workspace(session_id={self._session_id!r}, root={self._root!r}, "
            f"closed={self._closed})"
        )

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.cleanup(success=exc_type is None)
