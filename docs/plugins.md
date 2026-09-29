# APKForge Plugin System

## Overview

APKForge is plugin-oriented from the ground up.  All analytical, modification,
build, verification, integration, and reporting capabilities are implemented as
plugins registered into a `PluginRegistry`.

This document describes the plugin architecture as designed in Phase 0 and how
future phases are expected to implement concrete plugins.

---

## Plugin Protocol

Every plugin must satisfy the `Plugin` protocol defined in
`src/apkforge/core/plugins.py`:

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class Plugin(Protocol):
    @property
    def name(self) -> str: ...  # e.g. "analysis.manifest"

    @property
    def version(self) -> str: ...  # e.g. "1.0.0"

    def capabilities(self) -> list[str]: ...

    def is_available(self) -> bool: ...
```

### Name Convention

Plugin names follow the convention `{domain}.{identifier}`:

| Domain | Example |
|--------|---------|
| `analysis` | `analysis.manifest` |
| `security` | `security.crypto_misuse` |
| `privacy` | `privacy.tracker_sdk` |
| `diff` | `diff.dex` |
| `modifier` | `modifier.smali_patch` |
| `builder` | `builder.apktool` |
| `verifier` | `verifier.signature` |
| `integration` | `integration.jadx` |
| `reporting` | `reporting.json` |

### Capability Tags

Capability tags allow the application to query plugins by function:

```python
registry.get_by_capability("analyzer")  # all analyser plugins
registry.get_by_capability("reporter")  # all reporter plugins
registry.get_by_capability("static")  # all static-analysis plugins
```

---

## Specialised Plugin Types

### AnalyzerPlugin (Phase 1+)

```python
class AnalyzerPlugin(Plugin, Protocol):
    def analyze(self, workspace: Workspace, config: APKForgeConfig) -> AnalysisResult: ...
```

An `AnalyzerPlugin` receives a populated `Workspace` and returns an
`AnalysisResult` containing zero or more `Finding` objects.

Key rules:
- Must set `status` to `FAILED` (not `COMPLETE`) if a fatal error occurs.
- Must never execute any file from the workspace.
- Must respect `config.analysis.timeout_seconds`.

### ModifierPlugin (Phase 3+)

```python
class ModifierPlugin(Plugin, Protocol):
    def modify(self, step: ModificationStep, workspace: Workspace) -> ModificationStep: ...
```

Returns the step with its `status` updated.

### BuilderPlugin (Phase 3+)

```python
class BuilderPlugin(Plugin, Protocol):
    def build(self, workspace: Workspace, output_path: Path) -> Path: ...
```

### VerifierPlugin (Phase 3+)

```python
class VerifierPlugin(Plugin, Protocol):
    def verify(self, apk_path: Path) -> VerificationResult: ...
```

### ReporterPlugin (Phase 1+)

```python
class ReporterPlugin(Plugin, Protocol):
    def render(self, report: Report, *, verbose: bool = False) -> None: ...
```

---

## Plugin Registry

```python
from apkforge.core.plugins import PluginRegistry

registry = PluginRegistry()

# Register
registry.register(my_plugin)

# Retrieve by name
plugin = registry.get("analysis.manifest")

# Query by capability
analyzers = registry.get_by_capability("analyzer")

# Remove
registry.unregister("analysis.manifest")

# Introspect
print(registry.names)  # sorted list
print(len(registry))  # count
print("x" in registry)  # membership
```

The registry is **instance-based** — there is no global singleton.  Create one
per application context and pass it explicitly to services.

---

## Writing a Plugin (Phase 1+)

### Minimal Example

```python
# src/apkforge/analysis/my_analyzer.py

from apkforge.core.models import AnalysisResult, AnalysisStatus


class MyAnalyzerPlugin:
    @property
    def name(self) -> str:
        return "analysis.my_analyzer"

    @property
    def version(self) -> str:
        return "0.1.0"

    def capabilities(self) -> list[str]:
        return ["analyzer", "static"]

    def is_available(self) -> bool:
        return True  # or check for required external tools

    def analyze(self, workspace, config):
        findings = []
        # ... perform analysis on workspace contents ...
        return AnalysisResult(
            module_name=self.name,
            status=AnalysisStatus.COMPLETE,
            findings=findings,
        )
```

### Registration

```python
from apkforge.core.plugins import PluginRegistry
from apkforge.analysis.my_analyzer import MyAnalyzerPlugin

registry = PluginRegistry()
registry.register(MyAnalyzerPlugin())
```

---

## Discovery (Phase 1+)

Phase 1 will add automatic discovery via `importlib.metadata` entry points.
Plugin packages will declare themselves in their `pyproject.toml`:

```toml
[project.entry-points."apkforge.plugins"]
my_analyzer = "my_package.plugin:MyAnalyzerPlugin"
```

APKForge will discover and auto-register all such entry points at startup.

---

## Security Requirements for Plugins

All plugins must follow these rules:

1. **No execution** — plugins must never call `subprocess.run`, `os.system`,
   `exec()`, or any equivalent with data from the workspace.
2. **No network** — plugins must not make outbound network calls unless
   explicitly configured and the user has consented.
3. **Status honesty** — if an analysis fails, return `AnalysisStatus.FAILED`,
   not `COMPLETE`.
4. **Respect limits** — plugins must not bypass `ExtractionLimits` when
   reading workspace data.
5. **No secrets in logs** — never log raw APK bytes, extracted strings, or
   anything that could contain credentials.
