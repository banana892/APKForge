"""ModKit discovery and registry.

:class:`ModKitManager` knows which adapters exist (registered factories) and how
they are configured (:class:`~apkforge.modkit.config.ModKitConfigSet`). Discovery
is deterministic (sorted by id) and conservative: a ModKit is AVAILABLE only when
its adapter confirmed the executable exists, its dependencies are present and it
reported a supported version. A configuration entry alone never makes a ModKit
available, and an entry without a registered adapter is reported as
CONFIGURATION_INVALID instead of being guessed at.

The reference ``test-modkit`` is registered only when explicitly enabled (environment
``APKFORGE_ENABLE_TEST_MODKIT=1`` or a ``[modkits.test-modkit]`` entry); it never ships
in production use. The Morphe adapter (H.8) is always registered: APKForge still never
installs or downloads Morphe, so it reports NOT_INSTALLED until the user configures
``[modkits.morphe].executable_path``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from apkforge.modkit.config import ModKitConfig, ModKitConfigSet, load_modkit_config
from apkforge.modkit.contract import ExternalProcessAdapter, ModKitAdapter
from apkforge.modkit.executor import ModKitExecutor
from apkforge.modkit.masking import is_sensitive_name
from apkforge.modkit.models import (
    MODKIT_ID_PATTERN,
    AvailabilityReport,
    AvailabilityStatus,
    FailureCategory,
    ModKitExecutionResult,
    ModKitIdentity,
    ModKitInfo,
    ModKitResultStatus,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.modkit.models import ExecutionRequest

__all__ = [
    "TEST_MODKIT_ENV_VAR",
    "AdapterFactory",
    "ModKitManager",
    "contract_problems",
    "default_manager",
]

TEST_MODKIT_ENV_VAR = "APKFORGE_ENABLE_TEST_MODKIT"

#: Builds an adapter from its (optional) configuration; an adapter class qualifies.
AdapterFactory = Callable[[ModKitConfig | None], ModKitAdapter]


def contract_problems(adapter: ModKitAdapter, modkit_id: str | None = None) -> list[str]:
    """Violations of the adapter contract (empty: consistent)."""
    out: list[str] = []
    if modkit_id is not None and adapter.modkit_id != modkit_id:
        out.append(f"adapter id {adapter.modkit_id!r} != registered id {modkit_id!r}")
    if not MODKIT_ID_PATTERN.fullmatch(adapter.modkit_id):
        out.append(f"invalid adapter id {adapter.modkit_id!r}")
    caps = set(adapter.capabilities())
    seen: set[str] = set()
    for op in adapter.operations():
        if op.id in seen:
            out.append(f"duplicate operation {op.id!r}")
        seen.add(op.id)
        undeclared = sorted(set(op.capabilities) - caps)
        if undeclared:
            out.append(f"operation {op.id!r} uses unverified capabilities {undeclared}")
        names = [p.name for p in op.parameters]
        if len(names) != len(set(names)):
            out.append(f"operation {op.id!r} declares a parameter twice")
    if isinstance(adapter, ExternalProcessAdapter):
        leaked = [n for n in adapter.inherit_environment if is_sensitive_name(n)]
        if leaked:
            out.append(f"adapter inherits secret-looking environment variables {leaked}")
    return out


class ModKitManager:
    """Registry + discovery + execution entry point."""

    def __init__(
        self,
        config: ModKitConfigSet | None = None,
        *,
        executor: ModKitExecutor | None = None,
    ) -> None:
        self.config = config or ModKitConfigSet()
        self.executor = executor or ModKitExecutor()
        self._factories: dict[str, AdapterFactory] = {}
        self._adapters: dict[str, ModKitAdapter] = {}
        self._errors: dict[str, str] = {}
        self._discovered: list[ModKitInfo] | None = None

    def register(self, modkit_id: str, factory: AdapterFactory) -> None:
        if not MODKIT_ID_PATTERN.fullmatch(modkit_id):
            raise ValueError(f"invalid modkit id {modkit_id!r}")
        if modkit_id in self._factories:
            raise ValueError(f"ModKit {modkit_id!r} is already registered")
        self._factories[modkit_id] = factory
        self._discovered = None

    def registered_ids(self) -> list[str]:
        return sorted(self._factories)

    # -- adapters -------------------------------------------------------------------

    def get(self, modkit_id: str) -> ModKitAdapter | None:
        """The (configured) adapter for *modkit_id*, or None if unknown/broken."""
        if modkit_id in self._adapters:
            return self._adapters[modkit_id]
        factory = self._factories.get(modkit_id)
        if factory is None:
            return None
        try:
            adapter = factory(self.config.get(modkit_id))
        except Exception as exc:  # adapter construction is third-party-facing code
            self._errors[modkit_id] = f"adapter construction failed: {type(exc).__name__}: {exc}"
            return None
        problems = contract_problems(adapter, modkit_id)
        if problems:
            self._errors[modkit_id] = "adapter contract violation: " + "; ".join(problems)
            return None
        self._adapters[modkit_id] = adapter
        return adapter

    # -- discovery ------------------------------------------------------------------

    def info(self, modkit_id: str) -> ModKitInfo | None:
        known = modkit_id in self._factories or modkit_id in self.config.ids()
        if not known:
            return None
        cfg = self.config.get(modkit_id)
        issues = tuple(str(i) for i in self.config.issues_for(modkit_id))
        common: dict[str, Any] = {
            "configured": modkit_id in self.config.ids(),
            "enabled": cfg.enabled if cfg is not None else True,
            "config_source": self.config.source if modkit_id in self.config.ids() else None,
            "config_errors": issues,
        }
        if modkit_id not in self._factories:
            return ModKitInfo(
                identity=ModKitIdentity(
                    modkit_id=modkit_id, display_name=modkit_id, adapter_version="none"
                ),
                availability=AvailabilityReport(
                    status=AvailabilityStatus.CONFIGURATION_INVALID,
                    reason="configured, but no adapter is registered for this ModKit",
                ),
                adapter_registered=False,
                **common,
            )
        adapter = self.get(modkit_id)
        if adapter is None:
            return ModKitInfo(
                identity=ModKitIdentity(
                    modkit_id=modkit_id, display_name=modkit_id, adapter_version="unknown"
                ),
                availability=AvailabilityReport(
                    status=AvailabilityStatus.EXECUTION_UNAVAILABLE,
                    reason=self._errors.get(modkit_id, "adapter unavailable"),
                ),
                **common,
            )
        if issues:
            avail = AvailabilityReport(
                status=AvailabilityStatus.CONFIGURATION_INVALID, reason="; ".join(issues)
            )
            adapter._availability = avail  # never probe a misconfigured tool
        else:
            avail = adapter.availability()
        return ModKitInfo(
            identity=adapter.identity(),
            availability=avail,
            capabilities=adapter.capabilities(),
            requirements=adapter.requirements(),
            operations=adapter.operations(),
            **common,
        )

    def discover(self) -> list[ModKitInfo]:
        """Probe every registered/configured ModKit (sorted by id)."""
        ids = sorted(set(self._factories) | set(self.config.ids()))
        infos = [i for i in (self.info(m) for m in ids) if i is not None]
        self._discovered = infos
        return infos

    def list(self) -> list[ModKitInfo]:
        """The last discovery (runs :meth:`discover` the first time)."""
        return list(self._discovered) if self._discovered is not None else self.discover()

    # -- execution ------------------------------------------------------------------

    def execute(self, modkit_id: str, request: ExecutionRequest) -> ModKitExecutionResult:
        info = self.info(modkit_id)
        adapter = self.get(modkit_id)
        if info is None or adapter is None:
            identity = (
                info.identity
                if info is not None
                else ModKitIdentity(
                    modkit_id=modkit_id, display_name=modkit_id, adapter_version="none"
                )
            )
            return ModKitExecutionResult(
                status=ModKitResultStatus.NOT_AVAILABLE,
                failure=FailureCategory.NOT_AVAILABLE,
                reason=(info.availability.reason if info else f"unknown ModKit {modkit_id!r}"),
                execution_id="-",
                identity=identity,
                operation=request.operation,
            )
        return self.executor.run(adapter, request)


def default_manager(
    config_path: Path | None = None, *, executor: ModKitExecutor | None = None
) -> ModKitManager:
    """Manager with the configuration from disk and every built-in adapter."""
    config = load_modkit_config(config_path)
    manager = ModKitManager(config, executor=executor)
    from apkforge.modkit.morphe import MORPHE_MODKIT_ID, MorpheAdapter
    from apkforge.modkit.testing import TEST_MODKIT_ID, TestModKitAdapter

    manager.register(MORPHE_MODKIT_ID, MorpheAdapter)
    if os.environ.get(TEST_MODKIT_ENV_VAR) == "1" or TEST_MODKIT_ID in config.ids():
        manager.register(TEST_MODKIT_ID, TestModKitAdapter)
    return manager
