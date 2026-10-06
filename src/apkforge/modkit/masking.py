"""Secret masking for ModKit command records, parameters and logs.

Three layers, all applied before anything is stored:

1. *Known secrets*: values the adapter marks sensitive (sensitive parameters,
   sensitive environment values) are replaced wherever they appear.
2. *Sensitive names*: an environment variable or ``--option`` whose name looks like
   a credential (``*PASSWORD*``, ``*TOKEN*``, ``*SECRET*``, ...) has its value masked
   even when nobody declared it sensitive.
3. *Inline forms*: ``--password=value`` / ``token=value`` inside one argument.

The record stays useful for debugging (executable, argument positions, non-secret
values, environment *names*) without ever becoming a credential dump.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from apkforge.builders.runner import MASK

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

__all__ = ["MASK", "SecretMasker", "is_sensitive_name"]

_SENSITIVE = re.compile(
    r"(PASS(WORD|WD|PHRASE)?|TOKEN|SECRET|CREDENTIAL|PRIVATE|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"AUTH|COOKIE|SESSION|KEYSTORE|KS[_-]?PASS|KEY[_-]?PASS|SIGNING[_-]?KEY|BEARER)",
    re.IGNORECASE,
)
_INLINE = re.compile(r"^(--?[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)=(.+)$", re.DOTALL)


def is_sensitive_name(name: str) -> bool:
    """True if *name* (env var, option or parameter name) looks like a credential."""
    return bool(_SENSITIVE.search(name))


class SecretMasker:
    """Masks a fixed set of secrets plus anything name-based in argv/env."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        # Longest first so a secret containing another one is masked whole.
        self._secrets = sorted({s for s in secrets if s and len(s) >= 3}, key=len, reverse=True)

    def add(self, *secrets: str) -> None:
        self._secrets = sorted(
            {*self._secrets, *(s for s in secrets if s and len(s) >= 3)}, key=len, reverse=True
        )

    def text(self, value: str) -> str:
        for s in self._secrets:
            value = value.replace(s, MASK)
        return value

    def argv(self, argv: Sequence[str]) -> tuple[list[str], int]:
        """Masked copy of *argv* and the number of arguments that were masked."""
        out: list[str] = []
        masked = 0
        mask_next = False
        for arg in argv:
            if mask_next:
                out.append(MASK)
                masked += 1
                mask_next = False
                continue
            m = _INLINE.match(arg)
            if m and is_sensitive_name(m.group(1)):
                out.append(f"{m.group(1)}={MASK}")
                masked += 1
                continue
            if arg.startswith("-") and "=" not in arg and is_sensitive_name(arg):
                out.append(arg)
                mask_next = True
                continue
            new = self.text(arg)
            if new != arg:
                masked += 1
            out.append(new)
        return out, masked

    def environment(self, env: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
        """Masked copy of *env* (sorted) and the names whose values were masked."""
        out: dict[str, str] = {}
        masked: list[str] = []
        for key in sorted(env):
            value = env[key]
            if is_sensitive_name(key) or self.text(value) != value:
                out[key] = MASK
                masked.append(key)
            else:
                out[key] = value
        return out, masked
