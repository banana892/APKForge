"""Subprocess execution abstraction for APKForge builders.

Every external tool invocation made by BuildService goes through
:class:`CommandRunner` so that:

- commands are always argument arrays (never ``shell=True``),
- stdin is closed (``/dev/null``) so no tool can block waiting for input,
- the child runs in its own process group so a timeout kills the whole tree
  (Apktool spawns ``aapt2``),
- partial output survives a timeout for diagnosis,
- secrets are masked in the returned result *and* in log files,
- only the *names* of environment overrides are recorded, never their values.

Tests substitute a fake runner with the same ``run`` signature.
"""

from __future__ import annotations

import datetime
import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

__all__ = [
    "EXEC_ERROR_RETURNCODE",
    "MASK",
    "TIMEOUT_RETURNCODE",
    "CommandResult",
    "CommandRunner",
]

TIMEOUT_RETURNCODE = -999
EXEC_ERROR_RETURNCODE = -1
MASK = "********"


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


@dataclass
class CommandResult:
    """Result of a single external command execution (already secret-masked)."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    start_time: str
    end_time: str
    cwd: str | None = None
    env_overrides: list[str] = field(default_factory=list)
    timed_out: bool = False
    exec_error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.exec_error is None

    def to_log_text(self) -> str:
        return (
            f"COMMAND: {shlex.join(self.argv)}\n"
            f"CWD: {self.cwd or '(inherited)'}\n"
            f"ENV OVERRIDES: {', '.join(self.env_overrides) or '(none)'}\n"
            f"EXIT CODE: {self.returncode}\n"
            f"TIMED OUT: {self.timed_out}\n"
            f"START TIME: {self.start_time}\n"
            f"END TIME: {self.end_time}\n"
            f"DURATION: {self.duration_seconds:.2f}s\n"
            + (f"EXEC ERROR: {self.exec_error}\n" if self.exec_error else "")
            + f"\n=== STDOUT ===\n{self.stdout}\n\n=== STDERR ===\n{self.stderr}\n"
        )


def _decode(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


class CommandRunner:
    """Runs external build tools safely and records what happened."""

    def __init__(self, *, default_timeout: int = 900) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        argv: Sequence[str | Path],
        *,
        cwd: Path | None = None,
        env_overrides: Mapping[str, str] | None = None,
        timeout: int | None = None,
        log_path: Path | None = None,
        mask_strings: Sequence[str] | None = None,
    ) -> CommandResult:
        """Execute *argv* (an argument array) and capture its output.

        Args:
            argv: Program and arguments. Never interpreted by a shell.
            cwd: Working directory for the child.
            env_overrides: Variables added to the inherited environment. Use this
                to hand secrets to tools that read them from the environment
                (``apksigner --ks-pass env:NAME``) instead of from argv.
            timeout: Seconds before the process group is killed.
            log_path: If given, a full (masked) execution log is written here.
            mask_strings: Secrets replaced with ``********`` everywhere in the result.
        """
        masks = [m for m in (mask_strings or []) if m]
        if env_overrides:
            masks.extend(v for v in env_overrides.values() if v)

        def _mask(text: str) -> str:
            for m in masks:
                text = text.replace(m, MASK)
            return text

        str_argv = [str(a) for a in argv]
        effective_timeout = timeout if timeout is not None else self.default_timeout
        env = {**os.environ, **env_overrides} if env_overrides else None

        start_iso = _utc_now()
        t_start = time.monotonic()
        stdout = stderr = ""
        returncode = EXEC_ERROR_RETURNCODE
        timed_out = False
        exec_error: str | None = None

        try:
            proc = subprocess.Popen(  # noqa: S603 - argv array, no shell
                str_argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                start_new_session=True,
            )
        except OSError as exc:
            exec_error = f"{type(exc).__name__}: {exc}"
        else:
            try:
                stdout, stderr = proc.communicate(timeout=effective_timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                # Retrying communicate() after a timeout loses no output.
                out, err = proc.communicate()
                stdout, stderr = _decode(out), _decode(err)
                returncode = TIMEOUT_RETURNCODE
                stderr += (
                    f"\n[CommandRunner] Command timed out after {effective_timeout} seconds; "
                    "process group killed."
                )

        result = CommandResult(
            argv=[_mask(a) for a in str_argv],
            returncode=returncode,
            stdout=_mask(stdout),
            stderr=_mask(
                stderr if exec_error is None else f"Command failed to execute: {exec_error}"
            ),
            duration_seconds=time.monotonic() - t_start,
            start_time=start_iso,
            end_time=_utc_now(),
            cwd=str(cwd) if cwd else None,
            env_overrides=sorted(env_overrides) if env_overrides else [],
            timed_out=timed_out,
            exec_error=_mask(exec_error) if exec_error else None,
        )

        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(result.to_log_text(), encoding="utf-8")

        return result
