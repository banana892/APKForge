"""BuildService — the single APK rebuild abstraction for APKForge.

Pipeline (each stage is a separate method and a separate :class:`StageResult`)::

    prepare  -> decode -> build -> align -> sign -> verify
    (input,     apktool   apktool  zipalign apksigner zipalign -c,
     toolchain, d         b                 sign      apksigner verify,
     signing,                                         expected signer,
     workspace,                                       zip integrity
     framework)

Phase C.2 performs a *no-op* rebuild only: nothing is modified between decode
and build. Later phases will hook modifications in between.

Security properties:
- Tools receive only a private copy of the input; the original is hashed before
  and after the build and must be unchanged.
- Every tool runs through :class:`CommandRunner` with an argument array, closed
  stdin, a timeout and secret masking. APK-derived data is only ever passed as
  a file path inside the workspace, never interpreted by a shell.
- The signing password is passed to tools via an environment variable, never argv.
- Nothing from the APK is executed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from apkforge.builders.classify import FailureDiagnosis, classify_stage_failure
from apkforge.builders.models import (
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
from apkforge.core.exceptions import ConfigurationError
from apkforge.core.logging import get_logger

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


@dataclass
class _BuildContext:
    """Mutable per-build state shared between stage methods."""

    ws: BuildWorkspace
    options: BuildOptions
    password: str = field(repr=False, default="")
    expected_cert_sha256: str | None = None
    verification: BuildVerificationResult | None = None


class BuildService:
    """Rebuilds an APK through the validated Apktool 3 / build-tools pipeline."""

    def __init__(
        self,
        toolchain: ToolchainConfig,
        signing: SigningConfig,
        *,
        runner: CommandRunner | None = None,
        work_dir: Path | None = None,
    ) -> None:
        self.toolchain = toolchain
        self.signing = signing
        self.runner = runner or CommandRunner()
        self.work_dir = work_dir or load_default_config().workspace.base_directory / "builds"
        self._toolchain_check: ToolchainCheckResult | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_toolchain(self, *, refresh: bool = False) -> ToolchainCheckResult:
        """Validate the toolchain (cached per service instance)."""
        if self._toolchain_check is None or refresh:
            self._toolchain_check = validate_toolchain(self.toolchain, runner=self.runner)
        return self._toolchain_check

    def build(self, apk_path: Path | str, options: BuildOptions | None = None) -> BuildResult:
        """Run the no-op rebuild pipeline on *apk_path*. Never raises for tool failures."""
        t0 = time.monotonic()
        opts = options or BuildOptions()
        input_apk = Path(apk_path).expanduser().resolve()
        result = BuildResult(success=False, build_id=new_build_id(), input_apk=input_apk)
        result.toolchain = self.toolchain.to_dict()

        ctx, prepare = self._prepare(input_apk, opts, result)
        result.stages.append(prepare)
        if ctx is None:
            self._fail(result, prepare)
            result.duration_seconds = time.monotonic() - t0
            if result.workspace is not None:
                _write_result(result.workspace / "metadata" / "result.json", result)
            return result

        ws = ctx.ws
        result.workspace = ws.root
        result.log_file = ws.master_log
        steps = {
            BuildStage.DECODE: self._decode,
            BuildStage.BUILD: self._build,
            BuildStage.ALIGN: self._align,
            BuildStage.SIGN: self._sign,
            BuildStage.VERIFY: self._verify,
        }
        failed: StageResult | None = None
        for stage in PIPELINE:
            if failed is not None:
                result.stages.append(StageResult(stage=stage, status=StageStatus.SKIPPED))
                continue
            try:
                sr = steps[stage](ctx)
            except Exception as exc:  # never let an internal error escape build()
                _log.exception("BuildService %s stage raised", stage)
                diag = classify_stage_failure(
                    stage, None, f"Internal error: {type(exc).__name__}: {exc}"
                )
                sr = StageResult(
                    stage=stage,
                    status=StageStatus.FAIL,
                    failure_category=diag.category,
                    failure_cause=diag.cause,
                    classified=False,
                    log_file=ws.stage_log(str(stage)),
                )
            result.stages.append(sr)
            ws.append_log(
                f"[{stage.upper():7}] {sr.status:4} {sr.duration_seconds:7.2f}s"
                + (f"  {sr.failure_category}: {sr.failure_cause}" if not sr.passed else "")
            )
            if not sr.passed:
                failed = sr

        result.verification = ctx.verification
        result.certificate = ctx.verification.certificate if ctx.verification else None
        if ctx.verification:
            result.warnings.extend(
                _summarize_apksigner_warnings(ctx.verification.apksigner_warnings)
            )

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
            ws.append_log(f"\nSUCCESS  output={result.output_apk}")
        elif failed is not None:
            self._fail(result, failed)
            ws.append_log(f"\nFAILED   stage={failed.stage} category={failed.failure_category}")
            ws.append_log(f"Workspace retained for diagnosis: {ws.root}")
        else:
            result.failure_stage = BuildStage.VERIFY
            result.failure_category = BuildFailureCategory.INPUT_FAILURE
            result.failure_cause = "Input APK changed during the build."

        result.duration_seconds = time.monotonic() - t0
        ws.apply_retention(
            success=result.success,
            keep=opts.keep_workspace_on_success
            if result.success
            else opts.keep_workspace_on_failure,
            exported=exported,
        )
        if result.success and not ws.signed_apk.exists() and not exported:
            result.output_apk = None
        _write_result(ws.result_json, result)
        return result

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _prepare(
        self, input_apk: Path, opts: BuildOptions, result: BuildResult
    ) -> tuple[_BuildContext | None, StageResult]:
        """Validate input, output, toolchain and signing; create workspace; provision framework."""
        sr = StageResult(
            stage=BuildStage.PREPARE, start_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )
        t0 = time.monotonic()

        def _stop(
            category: BuildFailureCategory, cause: str, evidence: str | None = None
        ) -> tuple[None, StageResult]:
            sr.status, sr.failure_category, sr.failure_cause, sr.evidence = (
                StageStatus.FAIL,
                category,
                cause,
                evidence,
            )
            sr.duration_seconds = time.monotonic() - t0
            return None, sr

        if not input_apk.is_file():
            return _stop(BuildFailureCategory.INPUT_FAILURE, f"Input APK not found: {input_apk}")
        if not zipfile.is_zipfile(input_apk):
            return _stop(
                BuildFailureCategory.INPUT_FAILURE, f"Input is not a ZIP/APK archive: {input_apk}"
            )
        result.input_sha256 = _sha256(input_apk)

        if opts.output_apk is not None:
            dest = opts.output_apk.expanduser().resolve()
            if dest == input_apk:
                return _stop(
                    BuildFailureCategory.CONFIGURATION_FAILURE,
                    "Output path equals the input APK; refusing to overwrite it.",
                )
            if dest.exists() and not opts.overwrite_output:
                return _stop(
                    BuildFailureCategory.CONFIGURATION_FAILURE,
                    f"Output already exists: {dest} (use overwrite_output).",
                )

        check = self.check_toolchain()
        result.warnings.extend(check.warnings)
        if not check.valid:
            result.errors.extend(check.errors)
            return _stop(
                check.failure_category, "Toolchain validation failed: " + "; ".join(check.errors)
            )

        sign_errors = self.signing.validate()
        if sign_errors:
            result.errors.extend(sign_errors)
            return _stop(
                BuildFailureCategory.CONFIGURATION_FAILURE,
                "Invalid signing configuration: " + "; ".join(sign_errors),
            )

        try:
            password = self.signing.resolve_password()
        except (ConfigurationError, OSError) as exc:
            return _stop(
                BuildFailureCategory.CONFIGURATION_FAILURE, f"Cannot read signing password: {exc}"
            )
        try:
            ws = BuildWorkspace.create(opts.work_dir or self.work_dir, result.build_id)
        except OSError as exc:
            return _stop(
                BuildFailureCategory.CONFIGURATION_FAILURE, f"Cannot create workspace: {exc}"
            )
        ctx = _BuildContext(ws=ws, options=opts, password=password)
        sr.log_file = ws.stage_log("prepare")

        ws.append_log(f"APKForge BuildService  build_id={result.build_id}")
        ws.append_log(f"input      {input_apk}  sha256={result.input_sha256}")
        for key, value in self.toolchain.to_dict().items():
            ws.append_log(f"{key:18} {value}")
        for name, tool in check.tools.items():
            ws.append_log(f"tool {name:16} {tool.status:13} {tool.version or ''}")
        ws.append_log(f"signing    {self.signing.describe()}")
        ws.append_log(f"workspace  {ws.root}\n")

        result.workspace, result.log_file = ws.root, ws.master_log
        try:
            ws.import_input(input_apk)
        except OSError as exc:
            return _stop(BuildFailureCategory.CONFIGURATION_FAILURE, f"Cannot copy input: {exc}")
        try:
            ok, fw_res, message = ensure_framework(
                self.toolchain, self.runner, log_path=sr.log_file
            )
        except OSError as exc:
            ok, fw_res, message = False, None, f"Cannot install Apktool framework: {exc}"
        sr.notes.append(message)
        if fw_res is not None:
            sr.commands.append(fw_res.argv)
            sr.exit_code, sr.stdout, sr.stderr = fw_res.returncode, fw_res.stdout, fw_res.stderr
        if not ok:
            ws.append_log(f"[PREPARE] FAIL    framework: {message}")
            diag = classify_stage_failure(BuildStage.PREPARE, fw_res)
            timed_out = diag.category == BuildFailureCategory.TIMEOUT
            return _stop(
                diag.category if timed_out else BuildFailureCategory.FRAMEWORK_FAILURE,
                message,
                diag.evidence,
            )
        if fw_res is None:
            sr.log_file.write_text(message + "\n", encoding="utf-8")
        ws.append_log(f"[PREPARE] PASS    {message}")

        sr.status = StageStatus.PASS
        sr.duration_seconds = time.monotonic() - t0
        sr.end_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return ctx, sr

    def _decode(self, ctx: _BuildContext) -> StageResult:
        ws = ctx.ws
        assert ws.input_apk is not None
        res = self._run(
            BuildStage.DECODE,
            ctx,
            [
                *self.toolchain.apktool_command(),
                "d",
                "-o",
                str(ws.decoded_dir),
                "-p",
                str(self.toolchain.framework_dir),
                str(ws.input_apk),
            ],
        )
        ok = (
            res.ok
            and (ws.decoded_dir / "AndroidManifest.xml").is_file()
            and (ws.decoded_dir / "apktool.yml").is_file()
        )
        return self._stage_result(
            BuildStage.DECODE,
            [res],
            ok,
            ctx,
            detail=""
            if ok or not res.ok
            else "Apktool exited 0 but produced no decoded manifest/apktool.yml.",
        )

    def _build(self, ctx: _BuildContext) -> StageResult:
        ws = ctx.ws
        res = self._run(
            BuildStage.BUILD,
            ctx,
            [
                *self.toolchain.apktool_command(),
                "b",
                "-o",
                str(ws.unaligned_apk),
                "-p",
                str(self.toolchain.framework_dir),
                str(ws.decoded_dir),
            ],
        )
        ok = res.ok and ws.unaligned_apk.is_file() and zipfile.is_zipfile(ws.unaligned_apk)
        return self._stage_result(
            BuildStage.BUILD,
            [res],
            ok,
            ctx,
            detail="" if ok or not res.ok else "Apktool exited 0 but produced no valid APK.",
        )

    def _align(self, ctx: _BuildContext) -> StageResult:
        ws = ctx.ws
        zipalign = str(self.toolchain.zipalign)
        align = self._run(
            BuildStage.ALIGN,
            ctx,
            [zipalign, "-f", "-p", "4", str(ws.unaligned_apk), str(ws.aligned_apk)],
        )
        if not align.ok or not ws.aligned_apk.is_file():
            return self._stage_result(BuildStage.ALIGN, [align], False, ctx)
        check = self._run(
            BuildStage.ALIGN,
            ctx,
            [zipalign, "-c", "-v", "-p", "4", str(ws.aligned_apk)],
            append=True,
        )
        ok = _zipalign_verified(check)
        return self._stage_result(
            BuildStage.ALIGN,
            [align, check],
            ok,
            ctx,
            detail="" if ok else "zipalign -c reported the aligned APK as not aligned.",
        )

    def _sign(self, ctx: _BuildContext) -> StageResult:
        ws = ctx.ws
        assert self.toolchain.keytool is not None
        digest, err = certificate_sha256(
            self.toolchain.keytool, self.signing, ctx.password, self.runner
        )
        if digest is None:
            sr = StageResult(
                stage=BuildStage.SIGN,
                status=StageStatus.FAIL,
                log_file=ws.stage_log("sign"),
                failure_category=BuildFailureCategory.SIGNING_FAILURE,
                failure_cause=f"Could not read signing certificate: {err}",
            )
            ws.stage_log("sign").write_text(sr.failure_cause + "\n", encoding="utf-8")
            return sr
        ctx.expected_cert_sha256 = digest
        res = self._run(
            BuildStage.SIGN,
            ctx,
            [
                str(self.toolchain.apksigner),
                "sign",
                "--ks",
                str(self.signing.keystore),
                "--ks-key-alias",
                self.signing.alias,
                "--ks-pass",
                f"env:{SECRET_ENV_VAR}",
                "--key-pass",
                f"env:{SECRET_ENV_VAR}",
                "--out",
                str(ws.signed_apk),
                str(ws.aligned_apk),
            ],
            secret=True,
        )
        ok = res.ok and ws.signed_apk.is_file()
        sr = self._stage_result(BuildStage.SIGN, [res], ok, ctx)
        sr.notes.append(f"Signer: {self.signing.describe()}; expected certificate sha256 {digest}")
        return sr

    def _verify(self, ctx: _BuildContext) -> StageResult:
        ws = ctx.ws
        ver = BuildVerificationResult(expected_certificate_sha256=ctx.expected_cert_sha256)
        ctx.verification = ver
        apk = str(ws.signed_apk)

        align = self._run(
            BuildStage.VERIFY, ctx, [str(self.toolchain.zipalign), "-c", "-v", "-p", "4", apk]
        )
        ver.zipalign_verified = _zipalign_verified(align)
        if not ver.zipalign_verified:
            ver.errors.append(
                "zipalign -c: final APK is not 4-byte aligned (with page-aligned .so)."
            )

        sig = self._run(
            BuildStage.VERIFY,
            ctx,
            [str(self.toolchain.apksigner), "verify", "--verbose", "--print-certs", apk],
            append=True,
        )
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
        ver.expected_signer_matched = (
            cert.signer_count == 1
            and cert.sha256_digest is not None
            and cert.sha256_digest == ctx.expected_cert_sha256
        )
        if ver.signature_verified and not ver.expected_signer_matched:
            ver.errors.append(
                "Signer mismatch: expected exactly one signer with sha256 "
                f"{ctx.expected_cert_sha256}, "
                f"got {cert.signer_count} signer(s), first {cert.sha256_digest}."
            )

        try:
            with zipfile.ZipFile(ws.signed_apk) as z:
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
                ver.expected_signer_matched,
                ver.zip_integrity_verified,
                ver.manifest_present,
            )
        )
        with ws.stage_log("verify").open("a", encoding="utf-8") as f:
            f.write("\n=== VERIFICATION SUMMARY ===\n" + json.dumps(ver.to_dict(), indent=2) + "\n")
        return self._stage_result(
            BuildStage.VERIFY, [align, sig], ver.valid, ctx, detail="; ".join(ver.errors)
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run(
        self,
        stage: BuildStage,
        ctx: _BuildContext,
        argv: list[str],
        *,
        append: bool = False,
        secret: bool = False,
    ) -> CommandResult:
        log = ctx.ws.stage_log(str(stage))
        res = self.runner.run(
            argv,
            cwd=ctx.ws.root,
            env_overrides={SECRET_ENV_VAR: ctx.password} if secret else None,
            mask_strings=[ctx.password],
            timeout=ctx.options.stage_timeout_seconds,
        )
        with log.open("a" if append else "w", encoding="utf-8") as f:
            f.write(res.to_log_text() + "\n")
        return res

    def _stage_result(
        self,
        stage: BuildStage,
        results: list[CommandResult],
        ok: bool,
        ctx: _BuildContext,
        *,
        detail: str = "",
    ) -> StageResult:
        primary = next((r for r in results if not r.ok), results[-1])
        sr = StageResult(
            stage=stage,
            status=StageStatus.PASS if ok else StageStatus.FAIL,
            duration_seconds=sum(r.duration_seconds for r in results),
            commands=[r.argv for r in results],
            exit_code=primary.returncode,
            stdout="\n".join(r.stdout for r in results),
            stderr="\n".join(r.stderr for r in results),
            start_time=results[0].start_time,
            end_time=results[-1].end_time,
            log_file=ctx.ws.stage_log(str(stage)),
        )
        if not ok:
            diag: FailureDiagnosis = classify_stage_failure(stage, primary, detail)
            sr.failure_category, sr.failure_cause = diag.category, diag.cause
            sr.evidence, sr.classified = diag.evidence, diag.classified
        return sr

    @staticmethod
    def _fail(result: BuildResult, stage: StageResult) -> None:
        result.success = False
        result.failure_stage = stage.stage
        result.failure_category = stage.failure_category or BuildFailureCategory.BUILD_FAILURE
        result.failure_cause = stage.failure_cause
        result.failure_evidence = stage.evidence
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
