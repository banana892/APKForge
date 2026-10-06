"""ModKit configuration.

ModKits are *user-managed*: APKForge never downloads or installs one, it only
drives a tool the user installed and pointed it at. The configuration is a TOML
file::

    [modkits.example-kit]
    enabled = true
    executable_path = "/opt/example-kit/bin/example-kit"
    working_directory = "/var/tmp/apkforge-modkits"   # base for execution workspaces
    timeout_seconds = 1800

    [modkits.example-kit.environment]                 # non-secret variables only
    EXAMPLE_KIT_LOG_LEVEL = "info"

    [modkits.example-kit.options]                     # adapter-specific, validated by it
    some_option = "value"

Lookup order: an explicit path (``--config``), ``$APKFORGE_MODKIT_CONFIG``, then
``$XDG_CONFIG_HOME/apkforge/modkits.toml`` (``~/.config/...``) when it exists. No
file means no configuration, which is valid.

Secrets are never accepted: an environment entry or option whose name looks like a
credential is a configuration error (H.7 has no credential model at all). Invalid
entries are reported as structured :class:`ConfigIssue` records and never abort
discovery of the other ModKits.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from apkforge.modkit.masking import is_sensitive_name
from apkforge.modkit.models import MODKIT_ID_PATTERN

__all__ = [
    "CONFIG_ENV_VAR",
    "ConfigIssue",
    "ModKitConfig",
    "ModKitConfigSet",
    "default_config_path",
    "load_modkit_config",
    "parse_modkit_config",
]

CONFIG_ENV_VAR = "APKFORGE_MODKIT_CONFIG"
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_OPTION_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# The child environment is built by the framework; these are never overridable.
_RESERVED_ENV = frozenset({"PATH", "HOME", "TMPDIR", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"})


class ConfigIssue(BaseModel):
    model_config = ConfigDict(frozen=True)

    modkit_id: str | None = None
    field: str | None = None
    message: str

    def __str__(self) -> str:
        where = ".".join(p for p in (self.modkit_id, self.field) if p)
        return f"{where}: {self.message}" if where else self.message


def _abs_path(v: object) -> Path | None:
    if v is None:
        return None
    if not isinstance(v, (str, Path)):
        raise ValueError("must be a path string")
    text = str(v)
    if not text or _CONTROL.search(text):
        raise ValueError("must be a non-empty path without control characters")
    p = Path(os.path.expanduser(text))
    if not p.is_absolute():
        raise ValueError(f"must be an absolute path, got {text!r}")
    return p


class ModKitConfig(BaseModel):
    """Validated configuration of one ModKit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    modkit_id: str
    enabled: bool = True
    executable_path: Path | None = None
    working_directory: Path | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    options: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=1800, ge=1, le=86_400)

    @field_validator("modkit_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not MODKIT_ID_PATTERN.fullmatch(v) or len(v) > 64:
            raise ValueError(f"invalid modkit id {v!r}: lowercase slug [a-z0-9-], max 64 chars")
        return v

    @field_validator("executable_path", "working_directory", mode="before")
    @classmethod
    def _paths(cls, v: object) -> Path | None:
        return _abs_path(v)

    @field_validator("environment")
    @classmethod
    def _env(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            if not _ENV_NAME.fullmatch(key):
                raise ValueError(f"invalid environment variable name {key!r}")
            if key.upper() in _RESERVED_ENV:
                raise ValueError(f"environment variable {key!r} is controlled by APKForge")
            if is_sensitive_name(key):
                raise ValueError(
                    f"environment variable {key!r} looks like a secret; secrets must not be "
                    "stored in the ModKit configuration"
                )
            if _CONTROL.search(value):
                raise ValueError(f"environment variable {key!r} contains control characters")
        return dict(sorted(v.items()))

    @field_validator("options")
    @classmethod
    def _options(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            if not _OPTION_NAME.fullmatch(key):
                raise ValueError(f"invalid option name {key!r}")
            if is_sensitive_name(key):
                raise ValueError(f"option {key!r} looks like a secret; secrets are not supported")
            if _CONTROL.search(value):
                raise ValueError(f"option {key!r} contains control characters")
        return dict(sorted(v.items()))


class ModKitConfigSet(BaseModel):
    """Every configured ModKit plus the issues found while loading."""

    model_config = ConfigDict(frozen=True)

    source: str | None = None
    entries: dict[str, ModKitConfig] = Field(default_factory=dict)
    issues: tuple[ConfigIssue, ...] = ()

    def get(self, modkit_id: str) -> ModKitConfig | None:
        return self.entries.get(modkit_id)

    def issues_for(self, modkit_id: str) -> tuple[ConfigIssue, ...]:
        return tuple(i for i in self.issues if i.modkit_id == modkit_id)

    def ids(self) -> list[str]:
        """Every id mentioned (valid or invalid entry), sorted."""
        ids = set(self.entries) | {i.modkit_id for i in self.issues if i.modkit_id}
        return sorted(ids)


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "apkforge" / "modkits.toml"


def _issues(modkit_id: str, exc: ValidationError) -> list[ConfigIssue]:
    out = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or None
        msg = str(err["msg"]).removeprefix("Value error, ")
        out.append(ConfigIssue(modkit_id=modkit_id, field=loc, message=msg))
    return out


def parse_modkit_config(data: dict[str, Any], *, source: str | None = None) -> ModKitConfigSet:
    """Validate an already-parsed TOML document."""
    issues: list[ConfigIssue] = []
    entries: dict[str, ModKitConfig] = {}
    unknown = sorted(set(data) - {"modkits"})
    if unknown:
        issues.append(ConfigIssue(message=f"unknown top-level keys: {', '.join(unknown)}"))
    section = data.get("modkits", {})
    if not isinstance(section, dict):
        issues.append(ConfigIssue(field="modkits", message="must be a table"))
        section = {}
    for raw_id in sorted(section):
        body = section[raw_id]
        mid = str(raw_id)
        if not isinstance(body, dict):
            issues.append(ConfigIssue(modkit_id=mid, message="must be a table"))
            continue
        if "modkit_id" in body and body["modkit_id"] != mid:
            issues.append(
                ConfigIssue(modkit_id=mid, field="modkit_id", message="does not match table name")
            )
            continue
        try:
            entries[mid] = ModKitConfig.model_validate({**body, "modkit_id": mid})
        except ValidationError as exc:
            issues.extend(_issues(mid, exc))
    return ModKitConfigSet(source=source, entries=entries, issues=tuple(issues))


def load_modkit_config(path: Path | None = None) -> ModKitConfigSet:
    """Load the ModKit configuration (see module docstring for the lookup order).

    Never raises for a bad file: problems become :class:`ConfigIssue` records.
    """
    explicit = path is not None or bool(os.environ.get(CONFIG_ENV_VAR))
    if path is None:
        env = os.environ.get(CONFIG_ENV_VAR)
        path = Path(os.path.expanduser(env)) if env else default_config_path()
    if not path.exists():
        if explicit:
            return ModKitConfigSet(
                source=str(path),
                issues=(ConfigIssue(message=f"configuration file {path} does not exist"),),
            )
        return ModKitConfigSet()
    if path.is_symlink() or not path.is_file():
        return ModKitConfigSet(
            source=str(path),
            issues=(ConfigIssue(message=f"configuration path {path} is not a regular file"),),
        )
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return ModKitConfigSet(
            source=str(path),
            issues=(ConfigIssue(message=f"cannot parse {path}: {exc}"),),
        )
    return parse_modkit_config(data, source=str(path))
