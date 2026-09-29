"""APKForge plugin architecture.

Plugin interface
----------------
All APKForge plugins implement the :class:`Plugin` Protocol.  The concrete
plugin types extend the base with additional methods appropriate to their role:

:class:`AnalyzerPlugin`
    Produces :class:`~apkforge.core.models.AnalysisResult` findings.
:class:`ModifierPlugin`
    Produces :class:`~apkforge.core.models.ModificationStep` items.
:class:`BuilderPlugin`
    Converts a workspace into a rebuilt APK.
:class:`VerifierPlugin`
    Produces :class:`~apkforge.core.models.VerificationResult`.
:class:`IntegrationPlugin`
    Bridges an external tool (e.g. JADX, VirusTotal) into the pipeline.
:class:`ReporterPlugin`
    Renders a :class:`~apkforge.core.models.Report` to an output format.

Plugin registry
---------------
:class:`PluginRegistry` is the central, instance-based registry.  There is no
global mutable singleton — callers create a registry, register plugins into
it, and pass it explicitly to services that need it.  This makes unit testing
straightforward: each test can construct its own registry.

Discovery
---------
Phase 0 supports manual registration only.  Phase 1+ will add:
- ``importlib.metadata`` entry-point discovery for installed packages.
- Filesystem scanning of configured ``plugin_directories``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from apkforge.core.exceptions import PluginInitError, PluginNotFoundError

__all__ = [
    "AnalyzerPlugin",
    "BuilderPlugin",
    "IntegrationPlugin",
    "ModifierPlugin",
    "Plugin",
    "PluginRegistry",
    "ReporterPlugin",
    "VerifierPlugin",
]


# ===========================================================================
# Base plugin Protocol
# ===========================================================================


@runtime_checkable
class Plugin(Protocol):
    """Base protocol that every APKForge plugin must satisfy.

    A Protocol is used (rather than an ABC) so that third-party plugins can
    satisfy the interface without importing from APKForge internals.

    Attributes:
        name: Unique, stable, machine-readable identifier.
            Convention: ``{domain}.{name}`` (e.g. ``analysis.dex_strings``).
        version: Plugin version string (SemVer recommended).
    """

    @property
    def name(self) -> str:
        """Unique stable identifier for this plugin."""
        ...

    @property
    def version(self) -> str:
        """Version string for this plugin."""
        ...

    def capabilities(self) -> list[str]:
        """Return a list of capability tags this plugin provides.

        Example capability tags::

            ["analyzer", "static", "manifest"]
            ["reporter", "json"]
            ["modifier", "smali"]

        Returns:
            list[str]: Capability tags.
        """
        ...

    def is_available(self) -> bool:
        """Return whether this plugin's dependencies are satisfied.

        Some plugins depend on external tools (e.g. JADX, apktool) that may
        not be installed.  This method lets the registry surface availability
        without raising an error at discovery time.

        Returns:
            bool: True if the plugin can operate.
        """
        ...


# ===========================================================================
# Specialised plugin protocols
# ===========================================================================

# These protocols extend Plugin by adding the domain-specific entry point.
# Each phase will add implementations; Phase 0 only establishes the contract.


@runtime_checkable
class AnalyzerPlugin(Plugin, Protocol):
    """Plugin that analyses an APK and returns structured findings.

    Phase 1+ will define the ``analyze`` signature properly once the
    workspace abstraction is finalised.  For now, the protocol is a marker.
    """

    def analyze(self) -> None:
        """Analyse an APK.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


@runtime_checkable
class ModifierPlugin(Plugin, Protocol):
    """Plugin that transforms APK components.

    Phase 1+ will define the ``modify`` signature.
    """

    def modify(self) -> None:
        """Apply a modification to an APK workspace.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


@runtime_checkable
class BuilderPlugin(Plugin, Protocol):
    """Plugin that rebuilds/repacks an APK from a workspace."""

    def build(self) -> None:
        """Build a modified APK.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


@runtime_checkable
class VerifierPlugin(Plugin, Protocol):
    """Plugin that verifies a rebuilt APK."""

    def verify(self) -> None:
        """Verify a rebuilt APK.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


@runtime_checkable
class IntegrationPlugin(Plugin, Protocol):
    """Plugin that bridges an external tool into the APKForge pipeline."""

    def run(self) -> None:
        """Invoke the external integration.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


@runtime_checkable
class ReporterPlugin(Plugin, Protocol):
    """Plugin that renders a Report to an output format."""

    def render(self) -> None:
        """Render a report.

        Phase 0 stub — signature will be finalised in Phase 1.
        """
        ...


# ===========================================================================
# Plugin registry
# ===========================================================================


class PluginRegistry:
    """Instance-based registry for APKForge plugins.

    Design principles:
    - No global mutable state.  Create one registry per application context.
    - Plugins are validated at registration time.
    - Lookup raises :class:`~apkforge.core.exceptions.PluginNotFoundError`
      rather than returning ``None`` so that callers cannot accidentally use
      a missing plugin.

    Example::

        registry = PluginRegistry()
        registry.register(my_plugin)
        plugin = registry.get("analysis.dex_strings")
    """

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: Plugin) -> None:
        """Register a plugin.

        Args:
            plugin: Any object that satisfies the :class:`Plugin` protocol.

        Raises:
            PluginInitError: If the plugin does not satisfy the Protocol or
                its ``name`` conflicts with an already-registered plugin.
            TypeError: If the supplied object does not implement Plugin.
        """
        if not isinstance(plugin, Plugin):
            msg = (
                f"Object {plugin!r} does not implement the Plugin protocol. "
                "It must have 'name', 'version', 'capabilities', and 'is_available' members."
            )
            raise TypeError(msg)

        name = plugin.name
        if not name or not isinstance(name, str):
            raise PluginInitError("(unknown)", "Plugin name must be a non-empty string.")

        if name in self._plugins:
            raise PluginInitError(
                name,
                f"A plugin with name {name!r} is already registered.",
            )

        self._plugins[name] = plugin

    def unregister(self, name: str) -> None:
        """Remove a plugin from the registry.

        Args:
            name: The plugin name to remove.

        Raises:
            PluginNotFoundError: If no plugin with that name is registered.
        """
        if name not in self._plugins:
            raise PluginNotFoundError(name)
        del self._plugins[name]

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> Plugin:
        """Return the plugin registered under *name*.

        Args:
            name: Plugin identifier.

        Returns:
            Plugin: The registered plugin.

        Raises:
            PluginNotFoundError: If no plugin with that name is registered.
        """
        try:
            return self._plugins[name]
        except KeyError:
            raise PluginNotFoundError(name) from None

    def get_by_capability(self, capability: str) -> list[Plugin]:
        """Return all plugins that advertise a given capability.

        Args:
            capability: Capability tag to filter by (e.g. ``"analyzer"``).

        Returns:
            list[Plugin]: Matching plugins (may be empty).
        """
        return [p for p in self._plugins.values() if capability in p.capabilities()]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def names(self) -> list[str]:
        """Return sorted list of all registered plugin names."""
        return sorted(self._plugins.keys())

    def __len__(self) -> int:
        return len(self._plugins)

    def __contains__(self, name: object) -> bool:
        return name in self._plugins

    def __repr__(self) -> str:
        return f"PluginRegistry({self.names!r})"
