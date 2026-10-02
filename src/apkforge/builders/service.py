"""BuildService — the single APK rebuild abstraction for APKForge.

Each stage is a public method that takes explicit paths and returns a
:class:`StageResult`; :meth:`BuildService.build_pipeline` composes them::

    prepare_workspace -> decode -> build -> align -> sign -> verify
    (input, output,      apktool   apktool  zipalign apksigner zipalign -c,
     toolchain, signing, d         b                 sign      apksigner verify,
     workspace,                                                expected signer,
     framework)                                                zip integrity

Stage methods never raise for tool or internal failures: every outcome is a
``StageResult`` with a :class:`BuildFailureCategory`. A tool exiting 0 is never
enough on its own; each stage checks that its expected output exists.

The pipeline performs a *no-op* rebuild: nothing is modified between decode and
build. Modification is a later phase and is not part of this module.

Security properties:
- Tools receive only a private copy of the input; the original is hashed before
  and after the pipeline and must be unchanged. Stages refuse to write over
  their own input.
- Every tool runs through :class:`CommandRunner` with an argument array, closed
  stdin, a timeout and secret masking. APK-derived data is only ever passed as
  a file path inside the workspace, never interpreted by a shell.
- The signing password is passed to tools via an environment variable, never argv.
- Nothing from the APK is executed.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import time
import traceback
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.builders.classify import classify_stage_failure
from apkforge.builders.models import (
    DEFAULT_STAGE_TIMEOUT_SECONDS,
    BuildFailureCategory,
    BuildOptions,
    BuildResult,
    BuildStage,
    BuildVerificationResult,
    CertificateInfo,
    StageResult,
    StageStatus,
)
from apkforge.builders.runner import CommandResult, CommandRunner
from apkforge.builders.signing import SECRET_ENV_VAR, SigningConfig, certificate_sha256
from apkforge.builders.toolchain import (
    ToolchainCheckResult,
    ToolchainConfig,
    ensure_framework,
    validate_toolchain,
)
from apkforge.builders.workspace import BuildWorkspace, new_build_id
from apkforge.core.config import load_default_config
from apkforge.core.exceptions import ConfigurationError, WorkspaceError
from apkforge.core.logging import get_logger

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["BuildService"]

_log = get_logger(__name__)

PIPELINE: tuple[BuildStage, ...] = (
    BuildStage.DECODE,
    BuildStage.BUILD,
    BuildStage.ALIGN,
    BuildStage.SIGN,
    BuildStage.VERIFY,
)

_ZIPALIGN_OK = re.compile(r"Verification succes+ful")

C = BuildFailureCategory


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _zipalign_verified(res: CommandResult) -> bool:
    # zipalign -c exits 0 even when it prints "Verification FAILED", and prints
    # its verdict only with -v, so require the explicit success line.
    return (
        res.ok and bool(_ZIPALIGN_OK.search(res.stdout)) and "Verification FAILED" not in res.stdout
    )


def _nonempty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def _symlinks_under(root: Path) -> list[Path]:
    """Symlinks anywhere below *root* (decoded APK content must contain none)."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in (*dirnames, *filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                found.append(p)
    return found


class _StageRecorder:
    """Collects one stage's events, commands and outcome, and writes its logs.

    Used as a context manager: an exception raised inside the block becomes an
    ``UNEXPECTED_FAILURE`` result (type, message and traceback are kept) instead
    of propagating. ``sr`` is always the stage's result object.
    """

    def __init__(
        self,
        stage: BuildStage,
        ws: BuildWorkspace | None,
        *,
        timeout: int,
        masks: list[str],
    ) -> None:
        self.stage = stage
        self.ws: BuildWorkspace | None = None
        self.timeout = timeout
        self.masks = masks
        self.commands: list[CommandResult] = []
        self.sr = StageResult(stage=stage, start_time=_utc_now())
        self._t0 = time.monotonic()
        if ws is not None:
            self.attach(ws)

    def __enter__(self) -> _StageRecorder:
        self.event("starting")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        if exc is None or not isinstance(exc, Exception):
            return False  # success, or KeyboardInterrupt/SystemExit: propagate
        _log.error("BuildService %s stage raised", self.stage, exc_info=exc)
        self.write("".join(traceback.format_exception(exc)))
        self.failed(
            C.UNEXPECTED_FAILURE,
            f"Internal error in {self.stage} stage: {type(exc).__name__}: {exc}",
            classified=False,
        )
        return True

    def attach(self, ws: BuildWorkspace) -> None:
        """Start writing to *ws* (master log + stage log), replaying earlier events."""
        self.ws = ws
        self.sr.log_file = ws.stage_log(str(self.stage))
        for line in self.sr.events:
            self._append_master(line)
            self.write(line + "\n")

    def event(self, message: str) -> None:
        line = f"[{self.stage.upper()}] {message}"
        self.sr.events.append(line)
        _log.debug("%s", line)
        self._append_master(line)
        self.write(line + "\n")

    def record(self, res: CommandResult) -> None:
        self.commands.append(res)
        self.write(res.to_log_text() + "\n")

    def passed(self, output_path: Path | None, message: str = "completed") -> StageResult:
        self.sr.output_path = output_path
        self._finish(StageStatus.PASS)
        self.event(f"{message} ({self.sr.duration_seconds:.2f}s)")
        return self.sr

    def failed(
        self,
        category: BuildFailureCategory,
        cause: str,
        *,
        evidence: str | None = None,
        classified: bool = True,
        command: CommandResult | None = None,
    ) -> StageResult:
        sr = self.sr
        sr.failure_category, sr.failure_cause = category, cause
        sr.evidence, sr.classified = evidence, classified
        sr.failed_command = command.argv if command is not None else None
        self._finish(StageStatus.FAIL)
        self.event(f"FAILED {category}: {cause}")
        return sr

    def failed_tool(self, res: CommandResult, detail: str = "") -> StageResult:
        """Fail from a tool result, classifying its output."""
        diag = classify_stage_failure(self.stage, res, detail)
        return self.failed(
            diag.category,
            diag.cause,
            evidence=diag.evidence,
            classified=diag.classified,
            command=res,
        )

    def _finish(self, status: StageStatus) -> None:
        sr = self.sr
        sr.status = status
        sr.duration_seconds = time.monotonic() - self._t0
        sr.end_time = _utc_now()
        if self.commands:
            primary = next((r for r in self.commands if not r.ok), self.commands[-1])
            sr.commands = [r.argv for r in self.commands]
            sr.exit_code = primary.returncode
            sr.stdout = "\n".join(r.stdout for r in self.commands)
            sr.stderr = "\n".join(r.stderr for r in self.commands)

    def _append_master(self, line: str) -> None:
        if self.ws is None:
            return
        try:
            self.ws.append_log(line)
        except OSError as exc:  # logging must never decide the build outcome
            _log.warning("Cannot write %s: %s", self.ws.master_log, exc)

    def write(self, text: str) -> None:
        if self.sr.log_file is None:
            return
        try:
            with self.sr.log_file.open("a", encoding="utf-8") as f:
                f.write(text)
        except OSError as exc:
            _log.warning("Cannot write %s: %s", self.sr.log_file, exc)


class BuildService:
    """Rebuilds an APK through the validated Apktool 3 / build-tools pipeline.

    ``signing`` may be omitted for decode/build/align/verify-only use; signing and
    the full pipeline then fail with ``CONFIGURATION_FAILURE`` instead of picking
    a key implicitly.
    """

    def __init__(
        self,
        toolchain: ToolchainConfig,
        signing: SigningConfig | None = None,
        *,
        runner: CommandRunner | None = None,
        work_dir: Path | None = None,
    ) -> None:
        self.toolchain = toolchain
        self.signing = signing
        self.runner = runner or CommandRunner()
        self.work_dir = work_dir or load_default_config().workspace.base_directory / "builds"
        self._toolchain_check: ToolchainCheckResult | None = None
        self._framework_ready: tuple[Path | None, Path | None] | None = None

    # ------------------------------------------------------------------
    # Toolchain
    # ------------------------------------------------------------------

    def check_toolchain(self, *, refresh: bool = False) -> ToolchainCheckResult:
        """Validate the toolchain (cached per service instance)."""
        if self._toolchain_check is None or refresh:
            self._toolchain_check = validate_toolchain(self.toolchain, runner=self.runner)
        return self._toolchain_check

    # ------------------------------------------------------------------
    # Stages (public, independently callable)
    # ------------------------------------------------------------------

    def prepare_workspace(
        self, *, work_dir: Path | None = None, build_id: str | None = None
    ) -> tuple[BuildWorkspace | None, StageResult]:
        """Create a fresh, unique workspace under *work_dir* (default: the service's).

        Never reuses or deletes an existing directory. The workspace is ``None``
        when the stage failed.
        """
        rec = self._recorder(BuildStage.PREPARE, None)
        with rec:
            ws = self._create_workspace(rec, work_dir or self.work_dir, build_id)
            if ws is None:
                return None, rec.sr
            return ws, rec.passed(ws.root, "workspace ready")
        return rec.ws, rec.sr

    def decode(
        self, input_apk: Path | str, workspace: BuildWorkspace, *, timeout: int | None = None
    ) -> StageResult:
        """Decode *input_apk* into ``workspace.decoded_dir`` with Apktool.

        The APK is first copied into the workspace; Apktool never sees the original.
        """
        rec = self._recorder(BuildStage.DECODE, workspace, timeout)
        with rec:
            return self._decode(rec, Path(input_apk).expanduser().resolve(), workspace)
        return rec.sr

    def build(
        self,
        decoded_project: Path | str,
        output_apk: Path | str,
        *,
        workspace: BuildWorkspace | None = None,
        overwrite: bool = False,
        timeout: int | None = None,
    ) -> StageResult:
        """Build an Apktool project directory into *output_apk* (unaligned, unsigned)."""
        rec = self._recorder(BuildStage.BUILD, workspace, timeout)
        with rec:
            return self._build(
                rec,
                Path(decoded_project).expanduser().resolve(),
                Path(output_apk).expanduser().absolute(),
                overwrite,
            )
        return rec.sr

    def align(
        self,
        input_apk: Path | str,
        output_apk: Path | str,
        *,
        workspace: BuildWorkspace | None = None,
        overwrite: bool = False,
        timeout: int | None = None,
    ) -> StageResult:
        """zipalign *input_apk* into *output_apk* and verify the alignment."""
        rec = self._recorder(BuildStage.ALIGN, workspace, timeout)
        with rec:
            return self._align(
                rec,
                Path(input_apk).expanduser().resolve(),
                Path(output_apk).expanduser().absolute(),
                overwrite,
            )
        return rec.sr

    def sign(
        self,
        input_apk: Path | str,
        output_apk: Path | str,
        signing: SigningConfig | None = None,
        *,
        workspace: BuildWorkspace | None = None,
        overwrite: bool = False,
        timeout: int | None = None,
    ) -> StageResult:
        """Sign *input_apk* into *output_apk* with *signing* (default: the service's).

        On success ``StageResult.certificate_sha256`` is the configured certificate's
        digest, which :meth:`verify` can require as the expected signer.
        """
        cfg = signing or self.signing
        rec = self._recorder(BuildStage.SIGN, workspace, timeout, cfg)
        with rec:
            return self._sign(
                rec,
                Path(input_apk).expanduser().resolve(),
                Path(output_apk).expanduser().absolute(),
                cfg,
                overwrite,
            )
        return rec.sr

    def verify(
        self,
        apk: Path | str,
        *,
        expected_certificate_sha256: str | None = None,
        workspace: BuildWorkspace | None = None,
        timeout: int | None = None,
    ) -> StageResult:
        """Verify alignment, signature, signer and ZIP integrity of *apk*.

        The details are in ``StageResult.verification``. When
        *expected_certificate_sha256* is given, exactly one signer with that
        certificate digest is required.
        """
        rec = self._recorder(BuildStage.VERIFY, workspace, timeout)
        with rec:
            return self._verify(rec, Path(apk).expanduser().resolve(), expected_certificate_sha256)
        return rec.sr

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def build_pipeline(
        self, apk_path: Path | str, options: BuildOptions | None = None
    ) -> BuildResult:
        """Run prepare -> decode -> build -> align -> sign -> verify on *apk_path*.

        Stops at the first failed stage (later stages are ``SKIPPED``). Never
        raises for tool or internal failures; every outcome is a ``BuildResult``.
        """
        t0 = time.monotonic()
        opts = options or BuildOptions()
        input_apk = Path(apk_path).expanduser().resolve()
        result = BuildResult(success=False, build_id=new_build_id(), input_apk=input_apk)
        result.toolchain = self.toolchain.to_dict()
        try:
            self._pipeline(input_apk, opts, result)
        except Exception as exc:  # orchestration bug: report it, never raise
            _log.exception("BuildService pipeline raised")
            result.success = False
            result.output_apk = None
            result.failure_category = C.UNEXPECTED_FAILURE
            result.failure_cause = f"Internal pipeline error: {type(exc).__name__}: {exc}"
            result.errors.append(result.failure_cause)
        result.duration_seconds = time.monotonic() - t0
        if result.workspace is not None:
            _write_result(result.workspace / "metadata" / "result.json", result)
        return result

    def _pipeline(self, input_apk: Path, opts: BuildOptions, result: BuildResult) -> None:
        prepare, ws = self._pipeline_prepare(input_apk, opts, result)
        result.stages.append(prepare)
        result.logs.extend(prepare.events)
        if ws is None or not prepare.passed:
            self._fail(result, prepare)
            result.stages.extend(StageResult(stage=s, status=StageStatus.SKIPPED) for s in PIPELINE)
            return
        assert self.signing is not None  # checked by prepare

        timeout = opts.stage_timeout_seconds
        failed: StageResult | None = None
        expected_cert: str | None = None
        for stage in PIPELINE:
            if failed is not None:
                result.stages.append(StageResult(stage=stage, status=StageStatus.SKIPPED))
                continue
            if stage == BuildStage.DECODE:
                sr = self.decode(input_apk, ws, timeout=timeout)
            elif stage == BuildStage.BUILD:
                sr = self.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws, timeout=timeout)
            elif stage == BuildStage.ALIGN:
                sr = self.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws, timeout=timeout)
            elif stage == BuildStage.SIGN:
                sr = self.sign(ws.aligned_apk, ws.signed_apk, workspace=ws, timeout=timeout)
                expected_cert = sr.certificate_sha256
                if sr.passed:
                    result.signing_mode = self.signing.mode
            else:
                sr = self.verify(
                    ws.signed_apk,
                    expected_certificate_sha256=expected_cert,
                    workspace=ws,
                    timeout=timeout,
                )
                result.verification = sr.verification
            result.stages.append(sr)
            result.logs.extend(sr.events)
            if not sr.passed:
                failed = sr

        ver = result.verification
        result.certificate = ver.certificate if ver else None
        if ver:
            result.warnings.extend(_summarize_apksigner_warnings(ver.apksigner_warnings))

        # Input integrity: the original must be byte-identical after the build.
        result.input_unchanged = input_apk.is_file() and _sha256(input_apk) == result.input_sha256
        if not result.input_unchanged:
            result.errors.append("Input APK changed during the build.")

        exported = False
        if failed is None and result.input_unchanged:
            result.output_apk = ws.signed_apk
            if opts.output_apk is not None:
                dest = opts.output_apk.expanduser().resolve()
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ws.signed_apk, dest)
                result.output_apk = dest
                exported = True
            result.success = True
            self._pipeline_log(ws, result, f"SUCCESS  output={result.output_apk}")
        elif failed is not None:
            self._fail(result, failed)
            self._pipeline_log(
                ws, result, f"FAILED   stage={failed.stage} category={failed.failure_category}"
            )
            self._pipeline_log(ws, result, f"Workspace retained for diagnosis: {ws.root}")
        else:
            result.failure_stage = BuildStage.VERIFY
            result.failure_category = C.INPUT_FAILURE
            result.failure_cause = "Input APK changed during the build."

        ws.apply_retention(
            success=result.success,
            keep=(
                opts.keep_workspace_on_success if result.success else opts.keep_workspace_on_failure
            ),
            exported=exported,
        )
        if result.success and not ws.signed_apk.exists() and not exported:
            result.output_apk = None

    def _pipeline_prepare(
        self, input_apk: Path, opts: BuildOptions, result: BuildResult
    ) -> tuple[StageResult, BuildWorkspace | None]:
        """Pipeline preflight: input, output, toolchain, signing, workspace, framework."""
        rec = self._recorder(BuildStage.PREPARE, None, opts.stage_timeout_seconds)
        with rec:
            self._pipeline_prepare_body(rec, input_apk, opts, result)
        return rec.sr, rec.ws

    def _pipeline_prepare_body(
        self, rec: _StageRecorder, input_apk: Path, opts: BuildOptions, result: BuildResult
    ) -> None:
        if self._check_input_apk(rec, input_apk):
            return
        result.input_sha256 = _sha256(input_apk)

        if opts.output_apk is not None:
            dest = opts.output_apk.expanduser().resolve()
            if dest == input_apk:
                rec.failed(
                    C.CONFIGURATION_FAILURE,
                    "Output path equals the input APK; refusing to overwrite it.",
                )
                return
            if dest.exists() and not opts.overwrite_output:
                rec.failed(
                    C.CONFIGURATION_FAILURE,
                    f"Output already exists: {dest} (use overwrite_output).",
                )
                return

        check = self.check_toolchain()
        result.warnings.extend(check.warnings)
        if not check.valid:
            result.errors.extend(check.errors)
            rec.failed(
                check.failure_category, "Toolchain validation failed: " + "; ".join(check.errors)
            )
            return

        if self.signing is None:
            rec.failed(C.CONFIGURATION_FAILURE, "No signing configuration was provided.")
            return
        sign_errors = self.signing.validate()
        if sign_errors:
            result.errors.extend(sign_errors)
            rec.failed(
                C.CONFIGURATION_FAILURE, "Invalid signing configuration: " + "; ".join(sign_errors)
            )
            return
        try:
            self.signing.resolve_password()
        except (ConfigurationError, OSError) as exc:
            rec.failed(C.CONFIGURATION_FAILURE, f"Cannot read signing password: {exc}")
            return

        ws = self._create_workspace(rec, opts.work_dir or self.work_dir, result.build_id)
        if ws is None:
            return
        result.workspace, result.log_file = ws.root, ws.master_log
        ws.append_log(f"APKForge BuildService  build_id={result.build_id}")
        ws.append_log(f"input      {input_apk}  sha256={result.input_sha256}")
        for key, value in self.toolchain.to_dict().items():
            ws.append_log(f"{key:18} {value}")
        for name, tool in check.tools.items():
            ws.append_log(f"tool {name:16} {tool.status:13} {tool.version or ''}")
        ws.append_log(f"signing    {self.signing.mode}: {self.signing.describe()}\n")

        if self._ensure_framework(rec):
            return
        rec.passed(ws.root, "workspace ready")

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _create_workspace(
        self, rec: _StageRecorder, base: Path, build_id: str | None
    ) -> BuildWorkspace | None:
        try:
            ws = BuildWorkspace.create(base, build_id)
        except (WorkspaceError, OSError) as exc:
            rec.failed(C.WORKSPACE_FAILURE, f"Cannot create workspace under {base}: {exc}")
            return None
        rec.attach(ws)
        problems = ws.problems()
        if problems:
            rec.failed(C.WORKSPACE_FAILURE, "Workspace unusable: " + "; ".join(problems))
            return None
        rec.event(f"workspace created: {ws.root}")
        return ws

    def _decode(self, rec: _StageRecorder, src: Path, ws: BuildWorkspace) -> StageResult:
        if failure := self._check_input_apk(rec, src):
            return failure
        problems = ws.problems()
        if problems:
            return rec.failed(C.WORKSPACE_FAILURE, "Workspace unusable: " + "; ".join(problems))
        if ws.decoded_dir.exists() or ws.decoded_dir.is_symlink():
            return rec.failed(
                C.WORKSPACE_FAILURE,
                f"Decoded output already exists at {ws.decoded_dir}; "
                "decode into a fresh workspace (prepare_workspace()).",
            )
        if failure := self._require_tools(rec, "java", "apktool"):
            return failure
        if src.is_relative_to(ws.input_dir):
            private = src
        else:
            try:
                private = ws.import_input(src)
            except OSError as exc:
                return rec.failed(C.WORKSPACE_FAILURE, f"Cannot copy input into workspace: {exc}")
            rec.event(f"input copied to {private}")
        if failure := self._ensure_framework(rec):
            return failure

        res = self._run(
            rec,
            [
                *self.toolchain.apktool_command(),
                "d",
                "-o",
                str(ws.decoded_dir),
                "-p",
                str(self.toolchain.framework_dir),
                str(private),
            ],
        )
        if not res.ok:
            return rec.failed_tool(res)
        if not (
            (ws.decoded_dir / "AndroidManifest.xml").is_file()
            and (ws.decoded_dir / "apktool.yml").is_file()
        ):
            return rec.failed(
                C.OUTPUT_MISSING,
                "Apktool exited 0 but produced no decoded AndroidManifest.xml/apktool.yml.",
                command=res,
            )
        links = _symlinks_under(ws.decoded_dir)
        if links:
            return rec.failed(
                C.DECODE_FAILURE,
                f"Decoded project contains {len(links)} symlink(s) (first: {links[0]}); "
                "refusing untrusted links.",
                command=res,
            )
        return rec.passed(ws.decoded_dir)

    def _build(self, rec: _StageRecorder, project: Path, out: Path, overwrite: bool) -> StageResult:
        if not (
            project.is_dir()
            and (project / "apktool.yml").is_file()
            and (project / "AndroidManifest.xml").is_file()
        ):
            return rec.failed(
                C.INPUT_FAILURE,
                f"Not an Apktool project (needs apktool.yml and AndroidManifest.xml): {project}",
            )
        if out.resolve().is_relative_to(project):
            return rec.failed(
                C.CONFIGURATION_FAILURE, "Output APK must not be inside the decoded project."
            )
        if failure := self._require_tools(rec, "java", "apktool"):
            return failure
        if failure := self._claim_output(rec, out, [], overwrite):
            return failure
        if failure := self._ensure_framework(rec):
            return failure

        res = self._run(
            rec,
            [
                *self.toolchain.apktool_command(),
                "b",
                "-o",
                str(out),
                "-p",
                str(self.toolchain.framework_dir),
                str(project),
            ],
        )
        if not res.ok:
            return rec.failed_tool(res)
        if not _nonempty_file(out):
            return rec.failed(
                C.OUTPUT_MISSING, f"Apktool exited 0 but produced no APK at {out}.", command=res
            )
        if not zipfile.is_zipfile(out):
            return rec.failed(
                C.BUILD_FAILURE, f"Apktool output is not a valid ZIP/APK: {out}", command=res
            )
        rec.sr.notes.append("Output is unaligned and unsigned.")
        return rec.passed(out)

    def _align(self, rec: _StageRecorder, src: Path, out: Path, overwrite: bool) -> StageResult:
        if failure := self._check_input_apk(rec, src, "APK to align"):
            return failure
        if failure := self._require_tools(rec, "zipalign"):
            return failure
        if failure := self._claim_output(rec, out, [src], overwrite):
            return failure

        zipalign = str(self.toolchain.zipalign)
        align = self._run(rec, [zipalign, "-f", "-p", "4", str(src), str(out)])
        if not align.ok:
            return rec.failed_tool(align)
        if not _nonempty_file(out):
            return rec.failed(
                C.OUTPUT_MISSING, f"zipalign exited 0 but produced no APK at {out}.", command=align
            )
        check = self._run(rec, [zipalign, "-c", "-v", "-p", "4", str(out)])
        if not _zipalign_verified(check):
            return rec.failed_tool(check, "zipalign -c reported the aligned APK as not aligned.")
        rec.sr.notes.append("Output is aligned and unsigned.")
        return rec.passed(out)

    def _sign(
        self,
        rec: _StageRecorder,
        src: Path,
        out: Path,
        cfg: SigningConfig | None,
        overwrite: bool,
    ) -> StageResult:
        if cfg is None:
            return rec.failed(
                C.CONFIGURATION_FAILURE,
                "No signing configuration was provided; the APK remains unsigned.",
            )
        errors = cfg.validate()
        if errors:
            return rec.failed(
                C.CONFIGURATION_FAILURE, "Invalid signing configuration: " + "; ".join(errors)
            )
        try:
            password = cfg.resolve_password()
        except (ConfigurationError, OSError) as exc:
            return rec.failed(C.CONFIGURATION_FAILURE, f"Cannot read signing password: {exc}")
        if failure := self._check_input_apk(rec, src, "APK to sign"):
            return failure
        if failure := self._require_tools(rec, "keytool", "apksigner"):
            return failure
        if failure := self._claim_output(rec, out, [src], overwrite):
            return failure

        rec.event(f"signing mode {cfg.mode}: {cfg.describe()}")
        assert self.toolchain.keytool is not None and self.toolchain.apksigner is not None
        digest, err = certificate_sha256(self.toolchain.keytool, cfg, password, self.runner)
        if digest is None:
            return rec.failed(C.SIGNING_FAILURE, f"Could not read signing certificate: {err}")

        res = self._run(
            rec,
            [
                str(self.toolchain.apksigner),
                "sign",
                "--ks",
                str(cfg.keystore),
                "--ks-key-alias",
                cfg.alias,
                "--ks-pass",
                f"env:{SECRET_ENV_VAR}",
                "--key-pass",
                f"env:{SECRET_ENV_VAR}",
                "--out",
                str(out),
                str(src),
            ],
            env={SECRET_ENV_VAR: password},
        )
        if not res.ok:
            return rec.failed_tool(res)
        if not _nonempty_file(out):
            return rec.failed(
                C.OUTPUT_MISSING, f"apksigner exited 0 but produced no APK at {out}.", command=res
            )
        rec.sr.certificate_sha256 = digest
        rec.sr.notes.append(
            f"Signing mode: {cfg.mode}; signer: {cfg.describe()}; "
            f"expected certificate sha256 {digest}"
        )
        return rec.passed(out)

    def _verify(self, rec: _StageRecorder, apk: Path, expected: str | None) -> StageResult:
        if failure := self._check_input_apk(rec, apk, "APK to verify"):
            return failure
        if failure := self._require_tools(rec, "zipalign", "apksigner"):
            return failure

        ver = BuildVerificationResult(expected_certificate_sha256=expected)
        rec.sr.verification = ver
        align = self._run(rec, [str(self.toolchain.zipalign), "-c", "-v", "-p", "4", str(apk)])
        ver.zipalign_verified = _zipalign_verified(align)
        if not ver.zipalign_verified:
            ver.errors.append(
                "zipalign -c: final APK is not 4-byte aligned (with page-aligned .so)."
            )

        sig = self._run(
            rec, [str(self.toolchain.apksigner), "verify", "--verbose", "--print-certs", str(apk)]
        )
        ver.apksigner_output = sig.stdout
        cert = _parse_apksigner_verify(sig.stdout)
        ver.certificate = cert
        ver.apksigner_warnings = [
            ln.removeprefix("WARNING:").strip()
            for ln in sig.stdout.splitlines()
            if ln.startswith("WARNING:")
        ]
        first = next((ln.strip() for ln in sig.stdout.splitlines() if ln.strip()), "")
        ver.signature_verified = (
            sig.ok and first == "Verifies" and (cert.v1_scheme or cert.v2_scheme or cert.v3_scheme)
        )
        if not ver.signature_verified:
            ver.errors.append(f"apksigner verify did not verify the APK (exit {sig.returncode}).")
        if expected is not None:
            ver.expected_signer_matched = (
                cert.signer_count == 1
                and cert.sha256_digest is not None
                and cert.sha256_digest == expected
            )
            if ver.signature_verified and not ver.expected_signer_matched:
                ver.errors.append(
                    f"Signer mismatch: expected exactly one signer with sha256 {expected}, "
                    f"got {cert.signer_count} signer(s), first {cert.sha256_digest}."
                )

        try:
            with zipfile.ZipFile(apk) as z:
                bad = z.testzip()
                ver.zip_integrity_verified = bad is None
                if bad:
                    ver.errors.append(f"Corrupt ZIP entry: {bad}")
                ver.manifest_present = "AndroidManifest.xml" in z.NameToInfo
                if not ver.manifest_present:
                    ver.errors.append("AndroidManifest.xml missing from final APK.")
        except (zipfile.BadZipFile, OSError) as exc:
            ver.errors.append(f"Final APK unreadable as ZIP: {exc}")

        ver.valid = all(
            (
                ver.zipalign_verified,
                ver.signature_verified,
                ver.expected_signer_matched is not False,
                ver.zip_integrity_verified,
                ver.manifest_present,
            )
        )
        rec.write(
            "\n=== VERIFICATION SUMMARY ===\n"
            + json.dumps({k: v for k, v in ver.to_dict().items() if k != "apksigner_output"},
                         indent=2)
            + "\n"
        )  # fmt: skip
        if not ver.valid:
            return rec.failed_tool(sig if ver.zipalign_verified else align, "; ".join(ver.errors))
        return rec.passed(apk, "passed")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _recorder(
        self,
        stage: BuildStage,
        ws: BuildWorkspace | None,
        timeout: int | None = None,
        signing: SigningConfig | None = None,
    ) -> _StageRecorder:
        # Mask the signing password(s) in every stage's captured output, not just sign's.
        masks: list[str] = []
        for cfg in {c for c in (self.signing, signing) if c is not None}:
            with contextlib.suppress(ConfigurationError, OSError):
                masks.append(cfg.resolve_password())
        return _StageRecorder(
            stage, ws, timeout=timeout or DEFAULT_STAGE_TIMEOUT_SECONDS, masks=masks
        )

    def _run(
        self, rec: _StageRecorder, argv: list[str], *, env: dict[str, str] | None = None
    ) -> CommandResult:
        res = self.runner.run(
            argv,
            cwd=rec.ws.root if rec.ws else None,
            env_overrides=env,
            mask_strings=rec.masks,
            timeout=rec.timeout,
        )
        rec.record(res)
        return res

    @staticmethod
    def _check_input_apk(
        rec: _StageRecorder, path: Path, what: str = "Input APK"
    ) -> StageResult | None:
        if not path.is_file():
            return rec.failed(C.INPUT_FAILURE, f"{what} not found or not a file: {path}")
        if not zipfile.is_zipfile(path):
            return rec.failed(C.INPUT_FAILURE, f"{what} is not a ZIP/APK archive: {path}")
        return None

    def _require_tools(self, rec: _StageRecorder, *names: str) -> StageResult | None:
        missing = self.toolchain.unavailable(*names)
        if missing:
            return rec.failed(
                C.TOOL_UNAVAILABLE,
                f"Required tool(s) not available: {', '.join(missing)} "
                "(configure APKFORGE_* / ANDROID_HOME / JAVA_HOME; see docs/build-service.md).",
            )
        return None

    @staticmethod
    def _claim_output(
        rec: _StageRecorder, out: Path, inputs: list[Path], overwrite: bool
    ) -> StageResult | None:
        """Make *out* safe to write: never an input, never silently replaced.

        With *overwrite*, an existing file is removed *before* the tool runs, so a
        stale file can never be mistaken for this stage's output.
        """
        if any(out.resolve() == i.resolve() for i in inputs):
            return rec.failed(
                C.CONFIGURATION_FAILURE, f"Output path equals the input ({out}); refusing."
            )
        if out.is_dir():
            return rec.failed(C.CONFIGURATION_FAILURE, f"Output path is a directory: {out}")
        if out.exists() or out.is_symlink():
            if not overwrite:
                return rec.failed(
                    C.CONFIGURATION_FAILURE, f"Output already exists: {out} (pass overwrite=True)."
                )
            out.unlink()
            rec.event(f"removed existing output {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        return None

    def _ensure_framework(self, rec: _StageRecorder) -> StageResult | None:
        """Provision the Apktool framework once per service (and per platform)."""
        key = (self.toolchain.framework_dir, self.toolchain.android_platform)
        if self._framework_ready == key:
            return None
        res: CommandResult | None
        try:
            ok, res, message = ensure_framework(self.toolchain, self.runner)
        except OSError as exc:
            ok, res, message = False, None, f"Cannot install Apktool framework: {exc}"
        if res is not None:
            rec.record(res)
        rec.sr.notes.append(message)
        if not ok:
            diag = classify_stage_failure(rec.stage, res) if res is not None else None
            timed_out = diag is not None and diag.category == C.TIMEOUT
            return rec.failed(
                C.TIMEOUT if timed_out else C.FRAMEWORK_FAILURE,
                message,
                evidence=diag.evidence if diag else None,
                command=res,
            )
        rec.event(message)
        self._framework_ready = key
        return None

    @staticmethod
    def _pipeline_log(ws: BuildWorkspace, result: BuildResult, line: str) -> None:
        result.logs.append(line)
        ws.append_log(line)

    @staticmethod
    def _fail(result: BuildResult, stage: StageResult) -> None:
        result.success = False
        result.failure_stage = stage.stage
        result.failure_category = stage.failure_category or C.UNEXPECTED_FAILURE
        result.failure_cause = stage.failure_cause
        result.failure_evidence = stage.evidence
        result.failure_command = stage.failed_command
        if stage.failure_cause and stage.failure_cause not in result.errors:
            result.errors.append(stage.failure_cause)


def _write_result(path: Path, result: BuildResult) -> None:
    try:
        path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    except OSError as exc:
        _log.warning("Could not write %s: %s", path, exc)


def _summarize_apksigner_warnings(warnings: list[str]) -> list[str]:
    """Collapse the per-entry "not protected by signature" family into one line."""
    unprotected = [w for w in warnings if "not protected by signature" in w]
    out = [f"apksigner: {w}" for w in warnings if w not in unprotected]
    if unprotected:
        out.append(
            f"apksigner: {len(unprotected)} META-INF entr{'y' if len(unprotected) == 1 else 'ies'} "
            "not covered by the v1 signature (non-signature files carried over from the "
            "original APK; see verification.apksigner_warnings)."
        )
    return out


def _parse_apksigner_verify(stdout: str) -> CertificateInfo:
    cert = CertificateInfo()
    schemes = {
        "v1 scheme": "v1_scheme",
        "v2 scheme": "v2_scheme",
        "v3 scheme": "v3_scheme",
        "v3.1 scheme": "v31_scheme",
        "v4 scheme": "v4_scheme",
    }
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("Verified using "):
            for key, attr in schemes.items():
                if f"using {key} " in line:
                    setattr(cert, attr, line.lower().endswith("true"))
        elif line.startswith("Number of signers:"):
            with contextlib.suppress(ValueError):
                cert.signer_count = int(line.split(":", 1)[1])
        elif line.startswith("Signer #1 certificate DN:"):
            cert.subject_dn = line.split(":", 1)[1].strip()
        elif line.startswith("Signer #1 certificate SHA-256 digest:"):
            cert.sha256_digest = line.split(":", 1)[1].strip().lower()
    return cert
