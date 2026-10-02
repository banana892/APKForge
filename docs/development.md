# APKForge Development Guide

## Environment Setup

### Requirements

- Python 3.11 or later
- `git`
- A virtual environment manager (built-in `venv` or `uv`)

### Clone and Install

```bash
git clone https://github.com/apkforge/apkforge.git
cd apkforge

# Using venv
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# Install package + dev dependencies
pip install -e ".[dev]"
```

Or with `uv`:

```bash
uv sync --extra dev
```

### Validation environment

Corpus and security validation run in a locked environment
(`requirements/validation.lock`, Python 3.14.7). See
[validation-environment.md](validation-environment.md) for how to recreate it.

### APK build toolchain (Phase C.2)

`apkforge build` and the BuildService integration tests need Java, Apktool >= 3.0.3,
and Android SDK build-tools + a platform (35 validated). Configuration is by
environment variable; see [build-service.md](build-service.md) and
[examples/build-service.env.example](examples/build-service.env.example).
Check what was discovered with `apkforge build <apk> --show-toolchain`.
The full 9-APK rebuild test is opt-in: `APKFORGE_CORPUS_BUILD=1 pytest tests/integration`.

---

## Running the CLI

After installation, the `apkforge` command is available in your PATH:

```bash
apkforge --help
apkforge version
python -m apkforge --help
```

---

## Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run with coverage
pytest --cov=src/apkforge --cov-report=term-missing

# Run a specific test file
pytest tests/unit/test_models.py

# Run a specific test
pytest tests/unit/test_models.py::TestAPKInput::test_valid_apk_input
```

---

## Linting

APKForge uses [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting.

```bash
# Check for lint errors
ruff check src/ tests/

# Auto-fix safe issues
ruff check --fix src/ tests/

# Check formatting
ruff format --check src/ tests/

# Apply formatting
ruff format src/ tests/
```

The Ruff configuration is in `pyproject.toml` under `[tool.ruff]`.

---

## Type Checking

```bash
mypy src/
```

The Mypy configuration is in `pyproject.toml` under `[tool.mypy]`.

---

## Project Structure

```
APKForge/
├── src/apkforge/       — main package (src layout)
├── tests/
│   ├── unit/           — fast, isolated unit tests
│   └── integration/    — tests requiring real files (Phase 1+)
├── docs/               — architecture and developer documentation
├── rules/              — analysis rules (Phase 1+)
├── samples/            — sample APKs for testing (never commit malicious samples)
└── pyproject.toml      — single source of truth for project config
```

---

## Adding a New Module

1. Create the module inside the appropriate package (e.g. `src/apkforge/analysis/my_module.py`).
2. Implement the appropriate `Plugin` protocol (see `src/apkforge/core/plugins.py`).
3. Register the plugin via the `PluginRegistry`.
4. Add unit tests under `tests/unit/`.
5. Run `ruff check` and `mypy` before committing.

---

## Coding Standards

- **Type hints** on every public function and method.
- **Docstrings** on every public class and function.
- **No global mutable state** — pass config and registry explicitly.
- **Business logic belongs in core services**, not in CLI commands.
- **Exception handling**: catch the most specific exception; never swallow `APKForgeError` silently.
- **Security**: never log raw APK content, extracted bytes, or secrets.

---

## Git Workflow

```bash
# Create a feature branch
git checkout -b feature/phase-1-manifest-parser

# After work, run the full check suite
ruff check src/ tests/
ruff format src/ tests/
mypy src/
pytest

# Commit
git add -A
git commit -m "feat(analysis): add manifest parser plugin"
```

---

## Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scope): short description
fix(scope): short description
docs(scope): short description
test(scope): short description
refactor(scope): short description
chore(scope): short description
```
