"""Unit tests — Plugin architecture."""

from __future__ import annotations

import pytest

from apkforge.core.exceptions import PluginInitError, PluginNotFoundError
from apkforge.core.plugins import Plugin, PluginRegistry

# ---------------------------------------------------------------------------
# Test plugin implementations
# ---------------------------------------------------------------------------


class _GoodPlugin:
    """Minimal valid plugin satisfying the Plugin protocol."""

    @property
    def name(self) -> str:
        return "test.good_plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    def capabilities(self) -> list[str]:
        return ["analyzer", "static"]

    def is_available(self) -> bool:
        return True


class _AnotherPlugin:
    """A second plugin for collision testing."""

    @property
    def name(self) -> str:
        return "test.another_plugin"

    @property
    def version(self) -> str:
        return "0.5.0"

    def capabilities(self) -> list[str]:
        return ["reporter"]

    def is_available(self) -> bool:
        return True


class _BadPlugin:
    """Deliberately broken plugin that does NOT implement the Protocol."""

    pass  # no name, version, capabilities, is_available


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPluginProtocol:
    @pytest.mark.unit()
    def test_good_plugin_satisfies_protocol(self) -> None:
        assert isinstance(_GoodPlugin(), Plugin)

    @pytest.mark.unit()
    def test_bad_plugin_does_not_satisfy_protocol(self) -> None:
        assert not isinstance(_BadPlugin(), Plugin)


class TestPluginRegistry:
    @pytest.mark.unit()
    def test_empty_registry(self, plugin_registry: PluginRegistry) -> None:
        assert len(plugin_registry) == 0
        assert plugin_registry.names == []

    @pytest.mark.unit()
    def test_register_plugin(self, plugin_registry: PluginRegistry) -> None:
        plugin = _GoodPlugin()
        plugin_registry.register(plugin)
        assert len(plugin_registry) == 1
        assert "test.good_plugin" in plugin_registry

    @pytest.mark.unit()
    def test_get_plugin(self, plugin_registry: PluginRegistry) -> None:
        plugin = _GoodPlugin()
        plugin_registry.register(plugin)
        retrieved = plugin_registry.get("test.good_plugin")
        assert retrieved is plugin

    @pytest.mark.unit()
    def test_get_missing_plugin_raises(self, plugin_registry: PluginRegistry) -> None:
        with pytest.raises(PluginNotFoundError):
            plugin_registry.get("nonexistent.plugin")

    @pytest.mark.unit()
    def test_duplicate_registration_raises(self, plugin_registry: PluginRegistry) -> None:
        plugin_registry.register(_GoodPlugin())
        with pytest.raises(PluginInitError):
            plugin_registry.register(_GoodPlugin())  # same name → collision

    @pytest.mark.unit()
    def test_register_non_plugin_raises_type_error(self, plugin_registry: PluginRegistry) -> None:
        with pytest.raises(TypeError):
            plugin_registry.register(_BadPlugin())  # type: ignore[arg-type]

    @pytest.mark.unit()
    def test_unregister_plugin(self, plugin_registry: PluginRegistry) -> None:
        plugin_registry.register(_GoodPlugin())
        plugin_registry.unregister("test.good_plugin")
        assert "test.good_plugin" not in plugin_registry

    @pytest.mark.unit()
    def test_unregister_missing_raises(self, plugin_registry: PluginRegistry) -> None:
        with pytest.raises(PluginNotFoundError):
            plugin_registry.unregister("nonexistent.plugin")

    @pytest.mark.unit()
    def test_get_by_capability(self, plugin_registry: PluginRegistry) -> None:
        plugin_registry.register(_GoodPlugin())
        plugin_registry.register(_AnotherPlugin())
        analyzers = plugin_registry.get_by_capability("analyzer")
        assert len(analyzers) == 1
        assert analyzers[0].name == "test.good_plugin"

    @pytest.mark.unit()
    def test_get_by_capability_empty(self, plugin_registry: PluginRegistry) -> None:
        result = plugin_registry.get_by_capability("nonexistent_capability")
        assert result == []

    @pytest.mark.unit()
    def test_names_are_sorted(self, plugin_registry: PluginRegistry) -> None:
        plugin_registry.register(_AnotherPlugin())
        plugin_registry.register(_GoodPlugin())
        names = plugin_registry.names
        assert names == sorted(names)

    @pytest.mark.unit()
    def test_registries_are_independent(self) -> None:
        """Each registry is a separate instance — no shared global state."""
        r1 = PluginRegistry()
        r2 = PluginRegistry()
        r1.register(_GoodPlugin())
        assert len(r1) == 1
        assert len(r2) == 0

    @pytest.mark.unit()
    def test_repr(self, plugin_registry: PluginRegistry) -> None:
        plugin_registry.register(_GoodPlugin())
        assert "test.good_plugin" in repr(plugin_registry)
