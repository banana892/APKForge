"""APKForge exception hierarchy.

All APKForge-specific exceptions inherit from :class:`APKForgeError`.
Callers should catch the most specific exception they know how to handle and
let the rest propagate — do not silently swallow unrecognised errors.

Hierarchy::

    APKForgeError
    ├── InputError
    │   └── FileNotFoundError (built-in, not redefined here)
    ├── ConfigurationError
    ├── AnalysisError
    │   ├── ExtractionError
    │   └── ParsingError
    ├── PluginError
    │   ├── PluginNotFoundError
    │   └── PluginInitError
    ├── ModificationError
    ├── BuildError
    ├── VerificationError
    └── WorkspaceError

Security note
-------------
Analysis failures must never be treated as "clean".  Code that catches
:class:`AnalysisError` (or any subclass) should set the analysis status to
:attr:`~apkforge.core.models.AnalysisStatus.FAILED`, not to COMPLETE.
"""

from __future__ import annotations

__all__ = [
    "APKForgeError",
    "AnalysisError",
    "BuildError",
    "ConfigurationError",
    "ExtractionError",
    "InputError",
    "ModificationError",
    "ParsingError",
    "PluginError",
    "PluginInitError",
    "PluginNotFoundError",
    "ToolchainError",
    "VerificationError",
    "WorkspaceError",
]


class APKForgeError(Exception):
    """Base class for all APKForge errors.

    Always prefer raising a more specific subclass.
    """

    def __init__(self, message: str, *, context: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} [{self.context}]"
        return self.message


# ---------------------------------------------------------------------------
# Input errors
# ---------------------------------------------------------------------------


class InputError(APKForgeError):
    """Raised when the provided input (APK path, URL, data) is invalid.

    This covers:
    - File not found
    - File that is not a valid APK/ZIP
    - Oversized inputs that exceed configured limits
    """


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


class ConfigurationError(APKForgeError):
    """Raised when the APKForge configuration is missing or invalid.

    Examples:
    - Required field missing from config file
    - Value out of accepted range
    - Conflicting settings
    """


# ---------------------------------------------------------------------------
# Analysis errors
# ---------------------------------------------------------------------------


class AnalysisError(APKForgeError):
    """Raised when an analysis operation fails.

    Security invariant: a caller that catches AnalysisError must record the
    analysis status as FAILED, never as COMPLETE.
    """


class ExtractionError(AnalysisError):
    """Raised when APK/ZIP extraction fails or violates safety limits.

    Covers:
    - Zip-slip path traversal attempts
    - Maximum size exceeded
    - Corrupt archive
    """


class ParsingError(AnalysisError):
    """Raised when parsing a component of the APK fails.

    Examples:
    - Malformed AndroidManifest.xml
    - Corrupt DEX file
    - Invalid resource table
    """


# ---------------------------------------------------------------------------
# Plugin errors
# ---------------------------------------------------------------------------


class PluginError(APKForgeError):
    """Base class for plugin-related errors."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin cannot be found in the registry."""

    def __init__(self, plugin_name: str) -> None:
        super().__init__(f"Plugin not found: {plugin_name!r}", context="plugin-registry")
        self.plugin_name = plugin_name


class PluginInitError(PluginError):
    """Raised when a plugin fails to initialise."""

    def __init__(self, plugin_name: str, reason: str) -> None:
        super().__init__(
            f"Plugin {plugin_name!r} failed to initialise: {reason}",
            context="plugin-init",
        )
        self.plugin_name = plugin_name
        self.reason = reason


# ---------------------------------------------------------------------------
# Modification errors
# ---------------------------------------------------------------------------


class ModificationError(APKForgeError):
    """Raised when a modification operation fails or is unsafe.

    APKForge will not apply a modification that could corrupt the APK in a
    way that cannot be rolled back.
    """


# ---------------------------------------------------------------------------
# Toolchain errors
# ---------------------------------------------------------------------------


class ToolchainError(APKForgeError):
    """Raised when external toolchain tools (Java, Apktool, zipalign, apksigner) fail or are missing."""


# ---------------------------------------------------------------------------
# Build errors
# ---------------------------------------------------------------------------


class BuildError(APKForgeError):
    """Raised when the APK build/repack step fails."""


# ---------------------------------------------------------------------------
# Verification errors
# ---------------------------------------------------------------------------


class VerificationError(APKForgeError):
    """Raised when post-build verification of an APK fails.

    Examples:
    - Signature verification failed
    - Hash mismatch after rebuild
    """


# ---------------------------------------------------------------------------
# Workspace errors
# ---------------------------------------------------------------------------


class WorkspaceError(APKForgeError):
    """Raised when workspace creation, initialisation, or cleanup fails.

    The workspace holds working copies of extracted APK contents.
    """
