"""Shared test fixtures and helpers.

This conftest.py is placed at the ``tests/`` root so that fixtures are
available to both unit and integration test directories.
"""

from __future__ import annotations

import pytest

from apkforge.core.config import APKForgeConfig, load_default_config
from apkforge.core.plugins import PluginRegistry


@pytest.fixture()
def default_config() -> APKForgeConfig:
    """Return a default APKForgeConfig for use in tests."""
    return load_default_config()


@pytest.fixture()
def plugin_registry() -> PluginRegistry:
    """Return a fresh, empty PluginRegistry for each test."""
    return PluginRegistry()
