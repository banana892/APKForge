"""Controlled external-process execution for ModKit adapters.

Unlike the build :class:`~apkforge.builders.runner.CommandRunner` (which drives
APKForge's own pinned toolchain and inherits the environment), a ModKit is
untrusted third-party software, so :class:`ModKitProcessRunner`:

- runs an argument vector only (``shell=False``, ``argv[0]`` an absolute path),
- closes stdin and starts the child in its own session, so a timeout kills the
  whole process group,
- builds the child environment from scratch: a short allowlist from the parent
  (``PATH``, locale) plus the adapter's/configuration's non-secret variables, with
  ``HOME`` and ``TMPDIR`` pointing inside the workspace. Nothing else of the
  parent environment (tokens, keystore passwords, ...) reaches the ModKit,
- streams stdout/stderr to files (never unbounded memory) and kills the process
  group when either exceeds ``max_log_bytes``,
- masks known secrets in the logs and in the returned :class:`CommandRecord`,
- never retries.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.modkit.masking import SecretMasker
from apkforge.modkit.models import CommandRecord, ExecutionOutcome, FailureCategory

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apkforge.modkit.workspace import ModKitWorkspace

__all__ = ["INHERITED_ENVIRONMENT", "CommandSpec", "ModKitProcessRunner", "strip_ansi"]

#: Parent variables a ModKit inherits (values are not secret).
INHERITED_ENVIRONMENT = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[@-Z\\-_]")
_TAIL = 4096
_POLL = 0.05


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


@dataclass(frozen=True)
class CommandSpec:
    """An argument vector an external adapter wants to run.

    ``argv[0]`` must be an absolute path; nothing is ever passed through a shell.
    ``sensitive_values`` are masked everywhere they appear (logs, records).
    """

    argv: tuple[str, ...]
    environment: Mapping[str, str] = field(default_factory=dict)
    sensitive_values: tuple[str, ...] = ()
    #: Extra parent variables to inherit (adapter-declared, must be non-secret).
    inherit: tuple[str, ...] = ()

    def problems(self) -> list[str]:
        out: list[str] = []
        if not self.argv:
            return ["empty argument vector"]
        for i, a in enumerate(self.argv):
            if not isinstance(a, str):
                out.append(f"argument {i} is not a string")
            elif "\x00" in a:
                out.append(f"argument {i} contains a NUL byte")
        if isinstance(self.argv[0], str) and not Path(self.argv[0]).is_absolute():
            out.append(f"executable {self.argv[0]!r} is not an absolute path")
        return out


def _tail(path: Path, masker: SecretMasker) -> tuple[int, str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            f.seek(max(0, size - _TAIL))
            data = f.read().decode("utf-8", errors="replace")
    except OSError:
        return 0, ""
    return size, strip_ansi(masker.text(data))


def _mask_file(path: Path, masker: SecretMasker) -> None:
    """Rewrite a log with known secrets masked (a ModKit may echo its arguments)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        masked = masker.text(text)
        if masked != text:
            path.write_text(masked, encoding="utf-8")
    except OSError:
        pass


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
    proc.wait()


class ModKitProcessRunner:
    """Runs one ModKit command inside a :class:`ModKitWorkspace`."""

    def __init__(self, *, max_log_bytes: int = 64 * 1024 * 1024) -> None:
        self.max_log_bytes = max_log_bytes

    def _over_limit(self, *logs: Path) -> bool:
        return any(log.stat().st_size > self.max_log_bytes for log in logs)

    def environment(
        self,
        workspace: ModKitWorkspace,
        spec: CommandSpec,
        config_environment: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        env = {k: os.environ[k] for k in (*INHERITED_ENVIRONMENT, *spec.inherit) if k in os.environ}
        env.setdefault("PATH", os.defpath)
        env.update(config_environment or {})
        env.update(spec.environment)
        env["HOME"] = str(workspace.home_dir)
        env["TMPDIR"] = str(workspace.tmp_dir)
        return env

    def run(
        self,
        spec: CommandSpec,
        workspace: ModKitWorkspace,
        *,
        timeout_seconds: float,
        config_environment: Mapping[str, str] | None = None,
    ) -> ExecutionOutcome:
        masker = SecretMasker(spec.sensitive_values)
        env = self.environment(workspace, spec, config_environment)
        masked_argv, masked_args = masker.argv(list(spec.argv))
        masked_env, masked_names = masker.environment(env)
        # The record keeps the variables the ModKit-specific layers set plus HOME/TMPDIR;
        # inherited PATH/locale are recorded too (they matter for reproducibility).
        command = CommandRecord(
            executable=masked_argv[0] if masked_argv else "",
            argv=tuple(masked_argv),
            cwd=str(workspace.working_dir),
            environment=masked_env,
            masked_environment=tuple(masked_names),
            masked_arguments=masked_args,
        )
        stdout_log = workspace.logs_dir / "stdout.log"
        stderr_log = workspace.logs_dir / "stderr.log"
        start = _now()
        t0 = time.monotonic()
        problems = spec.problems()
        if problems:
            return ExecutionOutcome(
                error=FailureCategory.ADAPTER_ERROR,
                error_detail="; ".join(problems),
                start_time=start,
                end_time=_now(),
                command=command,
            )

        exit_code: int | None = None
        sig: int | None = None
        timed_out = False
        error: FailureCategory | None = None
        detail = ""
        with stdout_log.open("wb") as out, stderr_log.open("wb") as err:
            try:
                proc = subprocess.Popen(  # noqa: S603 - argv array, no shell, absolute executable
                    list(spec.argv),
                    cwd=workspace.working_dir,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    start_new_session=True,
                    close_fds=True,
                )
            except FileNotFoundError as exc:
                error, detail = FailureCategory.MISSING_EXECUTABLE, str(exc)
            except PermissionError as exc:
                error, detail = FailureCategory.PERMISSION_DENIED, str(exc)
            except OSError as exc:
                error, detail = FailureCategory.PROCESS_CRASH, f"{type(exc).__name__}: {exc}"
            else:
                deadline = t0 + timeout_seconds
                try:
                    while proc.poll() is None:
                        if time.monotonic() >= deadline:
                            timed_out = True
                            _kill_group(proc)
                            break
                        if self._over_limit(stdout_log, stderr_log):
                            _kill_group(proc)
                            error = FailureCategory.RESOURCE_LIMIT
                            detail = f"output exceeded {self.max_log_bytes} bytes; killed"
                            break
                        time.sleep(_POLL)
                except KeyboardInterrupt:
                    _kill_group(proc)
                    error, detail = FailureCategory.CANCELLED, "interrupted; process group killed"
                else:
                    # Reap any process-group members left behind by a clean exit.
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.killpg(proc.pid, signal.SIGKILL)
                rc = proc.returncode
                if error is None and not timed_out and self._over_limit(stdout_log, stderr_log):
                    # exited between two polls: the limit applies all the same
                    error = FailureCategory.RESOURCE_LIMIT
                    detail = f"output exceeded {self.max_log_bytes} bytes"
                if timed_out:
                    error = FailureCategory.TIMEOUT
                    detail = f"timed out after {timeout_seconds:g} s; process group killed"
                elif error is None and rc is not None and rc < 0:
                    sig = -rc
                    error = FailureCategory.PROCESS_CRASH
                    detail = f"terminated by signal {sig}"
                elif error is None and rc:
                    error = FailureCategory.NON_ZERO_EXIT
                    detail = f"exit code {rc}"
                exit_code = rc
        end = _now()
        _mask_file(stdout_log, masker)
        _mask_file(stderr_log, masker)
        out_size, out_tail = _tail(stdout_log, masker)
        err_size, err_tail = _tail(stderr_log, masker)
        outcome = ExecutionOutcome(
            exit_code=exit_code,
            timed_out=timed_out,
            signal=sig,
            error=error,
            error_detail=masker.text(detail),
            start_time=start,
            end_time=end,
            duration_seconds=round(time.monotonic() - t0, 3),
            command=command,
            stdout_log=str(stdout_log),
            stderr_log=str(stderr_log),
            stdout_bytes=out_size,
            stderr_bytes=err_size,
            stdout_tail=out_tail,
            stderr_tail=err_tail,
        )
        (workspace.logs_dir / "execution.log").write_text(
            outcome.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        return outcome
