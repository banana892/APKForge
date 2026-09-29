"""APKForge — Android APK Security & Modification Workbench.

APKForge is a local-first workbench for static analysis, security review,
privacy auditing, comparison, and controlled modification of Android APK files.

Current status: Phase 0 — Foundation only.
"""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__: str = version("apkforge")
except PackageNotFoundError:  # pragma: no cover — only during editable installs
    __version__ = "0.1.0-dev"
