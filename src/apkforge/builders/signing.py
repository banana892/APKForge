"""Signing configuration and the APKForge development signing key.

Rules enforced here:

- No password exists in source code. A password is read at build time from a
  file (``password_file``) or from a named environment variable (``password_env``).
- Passwords never appear on a command line: ``apksigner`` and ``keytool`` receive
  them through an environment variable (``--ks-pass env:NAME`` / ``-storepass:env NAME``),
  and the runner masks them in every captured output and log.
- The development key lives in the per-user data directory
  (``$XDG_DATA_HOME/apkforge/dev-signing``), never inside the repository, with a
  random password stored in a ``0600`` file next to it. Its certificate subject
  says it is not for release.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.builders.runner import CommandRunner
from apkforge.builders.toolchain import default_data_dir
from apkforge.core.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "DEV_KEY_ALIAS",
    "DEV_KEY_DNAME",
    "SECRET_ENV_VAR",
    "SigningConfig",
    "certificate_sha256",
    "default_dev_key_dir",
    "ensure_dev_keystore",
]

DEV_KEY_ALIAS = "apkforge-dev"
DEV_KEY_DNAME = "CN=APKForge Development Key - NOT FOR RELEASE, O=APKForge"
DEV_KEYSTORE_NAME = "apkforge-dev.p12"
DEV_PASSWORD_NAME = "apkforge-dev.password"  # noqa: S105 - a filename
#: Variable used to hand the password to apksigner/keytool child processes only.
SECRET_ENV_VAR = "APKFORGE_INTERNAL_KEYSTORE_PASSWORD"  # noqa: S105 - a variable name


@dataclass(frozen=True)
class SigningConfig:
    """Explicit signing configuration. Holds *where* the password is, never the password."""

    keystore: Path
    alias: str
    password_file: Path | None = None
    password_env: str | None = None
    development_key: bool = False

    def validate(self, environ: Mapping[str, str] | None = None) -> list[str]:
        env = os.environ if environ is None else environ
        errors: list[str] = []
        if not self.keystore.is_file():
            errors.append(f"Keystore not found: {self.keystore}")
        if not self.alias:
            errors.append("Key alias must not be empty.")
        if self.password_file is None and self.password_env is None:
            errors.append("No password source configured (password_file or password_env).")
        elif self.password_file is not None and not self.password_file.is_file():
            errors.append(f"Password file not found: {self.password_file}")
        elif self.password_file is None and not env.get(self.password_env or ""):
            errors.append(f"Password environment variable {self.password_env} is not set.")
        return errors

    def resolve_password(self, environ: Mapping[str, str] | None = None) -> str:
        env = os.environ if environ is None else environ
        if self.password_file is not None:
            pw = self.password_file.read_text(encoding="utf-8").rstrip("\r\n")
        elif self.password_env is not None:
            pw = env.get(self.password_env, "")
        else:
            pw = ""
        if not pw:
            raise ConfigurationError("Signing password source is empty.", context="signing")
        return pw

    def describe(self) -> str:
        source = f"file {self.password_file}" if self.password_file else f"env ${self.password_env}"
        kind = "development key" if self.development_key else "configured key"
        return f"{kind}: {self.keystore} (alias {self.alias}, password from {source})"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> SigningConfig | None:
        """Build a config from ``APKFORGE_SIGNING_*`` variables, or ``None`` if unset.

        - ``APKFORGE_SIGNING_KEYSTORE``: keystore path (required to opt in)
        - ``APKFORGE_SIGNING_ALIAS``: key alias
        - ``APKFORGE_SIGNING_PASSWORD_FILE``: file containing the password, or
        - ``APKFORGE_SIGNING_PASSWORD_ENV``: name of the variable holding the password
        """
        env = os.environ if environ is None else environ
        ks = env.get("APKFORGE_SIGNING_KEYSTORE")
        if not ks:
            return None
        pw_file = env.get("APKFORGE_SIGNING_PASSWORD_FILE")
        return cls(
            keystore=Path(ks).expanduser().resolve(),
            alias=env.get("APKFORGE_SIGNING_ALIAS", ""),
            password_file=Path(pw_file).expanduser().resolve() if pw_file else None,
            password_env=env.get("APKFORGE_SIGNING_PASSWORD_ENV") if not pw_file else None,
        )


def default_dev_key_dir(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    override = env.get("APKFORGE_DEV_KEY_DIR")
    return Path(override).expanduser() if override else default_data_dir(env) / "dev-signing"


def ensure_dev_keystore(
    keytool: Path,
    directory: Path | None = None,
    *,
    runner: CommandRunner | None = None,
) -> SigningConfig:
    """Return the development signing config, generating key + random password once."""
    directory = (directory or default_dev_key_dir()).resolve()
    keystore = directory / DEV_KEYSTORE_NAME
    pw_file = directory / DEV_PASSWORD_NAME
    config = SigningConfig(
        keystore=keystore, alias=DEV_KEY_ALIAS, password_file=pw_file, development_key=True
    )
    if keystore.is_file() and pw_file.is_file():
        return config

    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    password = secrets.token_urlsafe(32)
    fd = os.open(pw_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(password)
    keystore.unlink(missing_ok=True)

    res = (runner or CommandRunner(default_timeout=120)).run(
        [
            str(keytool),
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storetype",
            "PKCS12",
            "-alias",
            DEV_KEY_ALIAS,
            "-keyalg",
            "RSA",
            "-keysize",
            "3072",
            "-validity",
            "10000",
            "-storepass:env",
            SECRET_ENV_VAR,
            "-keypass:env",
            SECRET_ENV_VAR,
            "-dname",
            DEV_KEY_DNAME,
        ],
        env_overrides={SECRET_ENV_VAR: password},
    )
    if not res.ok or not keystore.is_file():
        pw_file.unlink(missing_ok=True)
        raise ConfigurationError(
            f"Failed to generate development keystore (exit {res.returncode}): "
            f"{res.stderr.strip()[-300:]}",
            context="signing",
        )
    os.chmod(keystore, 0o600)
    return config


def certificate_sha256(
    keytool: Path,
    signing: SigningConfig,
    password: str,
    runner: CommandRunner,
) -> tuple[str | None, str]:
    """SHA-256 of the signing certificate (DER), as apksigner reports it.

    Returns ``(digest_or_None, error_message)``.
    """
    res = runner.run(
        [
            str(keytool),
            "-exportcert",
            "-rfc",
            "-keystore",
            str(signing.keystore),
            "-alias",
            signing.alias,
            "-storepass:env",
            SECRET_ENV_VAR,
        ],
        env_overrides={SECRET_ENV_VAR: password},
        timeout=60,
    )
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", res.stdout, re.S)
    if not res.ok or not m:
        return (
            None,
            f"keytool -exportcert failed (exit {res.returncode}): {res.stderr.strip()[-300:]}",
        )
    der = base64.b64decode("".join(m.group(1).split()))
    return hashlib.sha256(der).hexdigest(), ""
