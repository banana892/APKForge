"""The ModKit execution lifecycle (APKForge-owned).

::

    availability ─▶ request validation ─▶ SHA-256 of the original
        ─▶ fresh workspace ─▶ stage + verify input ─▶ prepare ─▶ execute (once)
        ─▶ original/staged input unchanged? ─▶ process outcome
        ─▶ collect_output (a claim) ─▶ independent output validation
        ─▶ publish (copy + verify) ─▶ provenance ─▶ cleanup ─▶ retention

Every failure maps to a :class:`~apkforge.modkit.models.ModKitResultStatus` plus
a :class:`~apkforge.modkit.models.FailureCategory`; nothing is published unless
validation passed. Nothing is ever retried.
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import apkforge
from apkforge.core.config import ExtractionLimits, WorkspaceSettings
from apkforge.core.exceptions import WorkspaceError
from apkforge.modkit.contract import ExecutionContext
from apkforge.modkit.masking import MASK, is_sensitive_name
from apkforge.modkit.models import (
    ArtifactRecord,
    AvailabilityStatus,
    ExecutionOutcome,
    FailureCategory,
    ModKitExecutionResult,
    ModKitIdentity,
    ModKitResultStatus,
    OperationSpec,
    ProvenanceRecord,
    ValidationCheck,
)
from apkforge.modkit.validation import WorkspaceSnapshot, validate_apk_archive, validate_output
from apkforge.modkit.workspace import ModKitWorkspace, new_execution_id, sha256_file

if TYPE_CHECKING:
    from apkforge.modkit.contract import ModKitAdapter
    from apkforge.modkit.models import ExecutionRequest

__all__ = ["DEFAULT_TIMEOUT_SECONDS", "ModKitExecutor", "validate_request"]

DEFAULT_TIMEOUT_SECONDS = 1800
_OUTPUT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}\.apk")

R = ModKitResultStatus
F = FailureCategory

_AVAILABILITY_RESULT = {
    AvailabilityStatus.CONFIGURATION_INVALID: (R.CONFIGURATION_ERROR, F.CONFIGURATION_INVALID),
    AvailabilityStatus.DEPENDENCY_MISSING: (R.DEPENDENCY_ERROR, F.DEPENDENCY_MISSING),
}
_OUTCOME_RESULT = {
    F.TIMEOUT: R.TIMEOUT,
    F.CANCELLED: R.CANCELLED,
}


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _mask_params(op: OperationSpec, params: dict[str, str]) -> dict[str, str]:
    sensitive = {p.name for p in op.parameters if p.sensitive}
    return {
        k: (MASK if k in sensitive or is_sensitive_name(k) else v)
        for k, v in sorted(params.items())
    }


def validate_request(
    request: ExecutionRequest, adapter: ModKitAdapter
) -> tuple[OperationSpec | None, list[str], list[str]]:
    """(operation, request problems, input problems) - generic checks only."""
    req: list[str] = []
    inp: list[str] = []
    ops = {o.id: o for o in adapter.operations()}
    op = ops.get(request.operation)
    if op is None:
        req.append(
            f"unknown operation {request.operation!r} (supported: {', '.join(sorted(ops)) or '-'})"
        )
    else:
        specs = {p.name: p for p in op.parameters}
        for name in sorted(set(request.parameters) - set(specs)):
            req.append(f"unknown parameter {name!r} for operation {op.id!r}")
        for spec in op.parameters:
            value = request.parameters.get(spec.name)
            if value is None:
                if spec.required:
                    req.append(f"missing required parameter {spec.name!r}")
                continue
            if spec.choices and value not in spec.choices:
                req.append(f"parameter {spec.name!r} must be one of {', '.join(spec.choices)}")
            elif not re.fullmatch(spec.pattern, value):
                shown = "<masked>" if spec.sensitive else repr(value[:80])
                req.append(f"parameter {spec.name!r} has an invalid value {shown}")
        extra_caps = sorted(set(request.capabilities) - set(op.capabilities))
        if extra_caps:
            req.append(
                f"operation {op.id!r} does not provide capabilities: {', '.join(extra_caps)}"
            )
    if request.output_name is not None and not _OUTPUT_NAME.fullmatch(request.output_name):
        req.append(f"output_name {request.output_name!r} must be a plain '<name>.apk' file name")

    apk = request.input_apk
    if not apk.exists():
        inp.append(f"input {apk} does not exist")
    elif not apk.is_file():
        inp.append(f"input {apk} is not a regular file")
    else:
        inp.extend(f"input is not a valid APK: {p}" for p in validate_apk_archive(apk))
    return op, req, inp


class ModKitExecutor:
    """Runs one adapter for one request, owning the whole lifecycle."""

    def __init__(
        self,
        *,
        workspace_settings: WorkspaceSettings | None = None,
        limits: ExtractionLimits | None = None,
    ) -> None:
        self.settings = workspace_settings or WorkspaceSettings()
        self.limits = limits or ExtractionLimits()

    def workspace_base(self, adapter: ModKitAdapter, request: ExecutionRequest) -> Path:
        if request.workspace_base is not None:
            return request.workspace_base
        if adapter.config is not None and adapter.config.working_directory is not None:
            return adapter.config.working_directory
        return self.settings.base_directory / "modkits"

    def run(self, adapter: ModKitAdapter, request: ExecutionRequest) -> ModKitExecutionResult:
        execution_id = new_execution_id()
        identity = adapter.identity()
        base: dict[str, Any] = {
            "execution_id": execution_id,
            "identity": identity,
            "operation": request.operation,
        }

        # 1. availability ---------------------------------------------------------
        avail = adapter.availability()
        if not avail.available:
            status, failure = _AVAILABILITY_RESULT.get(
                avail.status, (R.NOT_AVAILABLE, F.NOT_AVAILABLE)
            )
            return ModKitExecutionResult(
                **base,
                status=status,
                failure=failure,
                reason=f"{identity.modkit_id} is {avail.status}: {avail.reason}".rstrip(": "),
            )

        # 2. request + input --------------------------------------------------------
        op, req_problems, inp_problems = validate_request(request, adapter)
        if req_problems or op is None:
            return ModKitExecutionResult(
                **base,
                status=R.INVALID_INPUT,
                failure=F.INVALID_REQUEST,
                reason="; ".join(req_problems),
            )
        if inp_problems:
            return ModKitExecutionResult(
                **base,
                status=R.INVALID_INPUT,
                failure=F.INVALID_INPUT,
                reason="; ".join(inp_problems),
            )
        try:
            adapter_problems = adapter.validate_input(request, op)
        except Exception as exc:  # adapter code is not trusted to be bug-free
            adapter_problems = [f"adapter validate_input failed: {type(exc).__name__}: {exc}"]
        if adapter_problems:
            return ModKitExecutionResult(
                **base,
                status=R.INVALID_INPUT,
                failure=F.INVALID_INPUT,
                reason="; ".join(adapter_problems),
            )
        original = request.input_apk.resolve()
        out_name = request.output_name or f"{original.stem}.{identity.modkit_id}.apk"
        if not _OUTPUT_NAME.fullmatch(out_name):
            out_name = f"output.{identity.modkit_id}.apk"
        destination = request.output_dir.resolve() / out_name
        if destination.exists() or destination.is_symlink():
            return ModKitExecutionResult(
                **base,
                status=R.INVALID_INPUT,
                failure=F.INVALID_REQUEST,
                reason=f"refusing to overwrite existing {destination}",
            )
        if destination == original:
            return ModKitExecutionResult(
                **base,
                status=R.INVALID_INPUT,
                failure=F.INVALID_REQUEST,
                reason="the output would replace the input",
            )

        # 3. original provenance ----------------------------------------------------
        orig_sha = sha256_file(original)
        orig_rec = ArtifactRecord(
            role="original", path=str(original), sha256=orig_sha, size=original.stat().st_size
        )
        base["original"] = orig_rec

        # 4. workspace + staging ----------------------------------------------------
        try:
            ws = ModKitWorkspace.create(self.workspace_base(adapter, request), execution_id)
        except WorkspaceError as exc:
            return ModKitExecutionResult(
                **base, status=R.EXECUTION_FAILED, failure=F.WORKSPACE_FAILURE, reason=str(exc)
            )
        base["workspace_path"] = str(ws.root)
        try:
            staged, staged_sha = ws.stage_input(original, orig_sha)
        except WorkspaceError as exc:
            return self._finish(
                ws, request, base, status=R.EXECUTION_FAILED, failure=F.STAGING_MISMATCH,
                reason=str(exc),
            )  # fmt: skip
        staged_rec = ArtifactRecord(
            role="staged_input", path=str(staged), sha256=staged_sha, size=staged.stat().st_size
        )
        base["staged_input"] = staged_rec
        timeout = float(
            request.timeout_seconds
            or (adapter.config.timeout_seconds if adapter.config else DEFAULT_TIMEOUT_SECONDS)
        )
        ctx = ExecutionContext(
            execution_id=execution_id,
            request=request,
            operation=op,
            workspace=ws,
            staged_input=staged,
            timeout_seconds=timeout,
            config=adapter.config,
        )
        masked_params = _mask_params(op, request.parameters)
        (ws.metadata_dir / "request.json").write_text(
            json.dumps(
                {
                    "execution_id": execution_id,
                    "modkit_id": identity.modkit_id,
                    "operation": op.id,
                    "parameters": masked_params,
                    "capabilities": [str(c) for c in request.capabilities],
                    "expect_change": request.expect_change,
                    "timeout_seconds": timeout,
                    "input_sha256": orig_sha,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        # 5. prepare + execute (exactly once), then validate; cleanup always runs
        fin: dict[str, Any]
        messages: list[str] = []
        try:
            fin = self._execute(adapter, ctx, base, orig_sha, staged_sha, masked_params,
                                destination)  # fmt: skip
        finally:
            try:
                adapter.cleanup(ctx)
            except Exception as exc:  # cleanup must not mask the result
                messages.append(f"adapter cleanup failed: {type(exc).__name__}: {exc}")
        return self._finish(ws, request, base, messages=messages, **fin)

    def _execute(
        self,
        adapter: ModKitAdapter,
        ctx: ExecutionContext,
        base: dict[str, Any],
        orig_sha: str,
        staged_sha: str,
        masked_params: dict[str, str],
        destination: Path,
    ) -> dict[str, Any]:
        """Run, check integrity, validate and publish; returns ``_finish`` arguments."""
        ws, op, request = ctx.workspace, ctx.operation, ctx.request
        identity: ModKitIdentity = base["identity"]
        orig_rec: ArtifactRecord = base["original"]
        original = Path(orig_rec.path)
        start = _now()
        snapshot = WorkspaceSnapshot.take(ws)
        outcome: ExecutionOutcome
        try:
            adapter.prepare(ctx)
            snapshot = WorkspaceSnapshot.take(ws)
            outcome = adapter.execute(ctx)
        except KeyboardInterrupt:
            outcome = ExecutionOutcome(error=F.CANCELLED, error_detail="interrupted")
        except Exception as exc:  # adapter code is not trusted to be bug-free
            outcome = ExecutionOutcome(
                error=F.ADAPTER_ERROR, error_detail=f"{type(exc).__name__}: {exc}"
            )
        base["outcome"] = outcome
        end = _now()

        def provenance(output: ArtifactRecord | None = None) -> ProvenanceRecord:
            return ProvenanceRecord(
                execution_id=ctx.execution_id,
                modkit_id=identity.modkit_id,
                modkit_version=identity.installed_version,
                adapter_version=identity.adapter_version,
                apkforge_version=apkforge.__version__,
                requested_operation=op.id,
                capabilities=request.capabilities or op.capabilities,
                parameters=masked_params,
                input_sha256=orig_sha,
                input_size=orig_rec.size,
                input_path=str(original),
                output_sha256=output.sha256 if output else None,
                output_size=output.size if output else None,
                start_time=outcome.start_time or start,
                end_time=outcome.end_time or end,
                exit_code=outcome.exit_code,
                toolchain={
                    "python": platform.python_version(),
                    "platform": platform.system(),
                    **adapter.toolchain(),
                },
                workspace_id=ws.execution_id,
                workspace_path=str(ws.root),
                command=outcome.command,
            )

        # 6. input integrity ----------------------------------------------------------
        orig_after = sha256_file(original) if original.is_file() else None
        base["original_unchanged"] = orig_after == orig_sha
        if orig_after != orig_sha:
            return {
                "status": R.EXECUTION_FAILED,
                "failure": F.ORIGINAL_MUTATED,
                "reason": "the original APK changed during ModKit execution",
                "provenance": provenance(),
            }
        staged = ctx.staged_input
        if not staged.is_file() or staged.is_symlink() or sha256_file(staged) != staged_sha:
            return {
                "status": R.EXECUTION_FAILED,
                "failure": F.INPUT_MUTATED,
                "reason": "the ModKit modified its staged input in place",
                "provenance": provenance(),
            }

        # 7. process outcome -----------------------------------------------------------
        if outcome.error is not None:
            return {
                "status": _OUTCOME_RESULT.get(outcome.error, R.EXECUTION_FAILED),
                "failure": outcome.error,
                "reason": outcome.error_detail or str(outcome.error),
                "provenance": provenance(),
            }

        # 8. collect (a claim) + validate (the truth) ---------------------------------
        try:
            declaration = adapter.collect_output(ctx)
        except Exception as exc:  # adapter code is not trusted to be bug-free
            return {
                "status": R.OUTPUT_INVALID,
                "failure": F.ADAPTER_ERROR,
                "reason": f"collect_output failed: {type(exc).__name__}: {exc}",
                "provenance": provenance(),
            }
        base["declaration"] = declaration
        v = validate_output(
            ws,
            declaration,
            operation=op,
            input_sha256=staged_sha,
            expect_change=request.expect_change,
            snapshot=snapshot,
            limits=self.limits,
        )
        base["validation"] = tuple(v.checks)
        cand_rec: ArtifactRecord | None = None
        if v.candidate is not None:
            cand_rec = ArtifactRecord(
                role="candidate",
                path=str(v.candidate),
                sha256=sha256_file(v.candidate),
                size=v.candidate.stat().st_size,
            )
            base["candidate"] = cand_rec
        if not v.ok:
            return {
                "status": v.status,
                "failure": v.failure,
                "reason": v.reason,
                "provenance": provenance(),
            }
        if v.status is R.NO_OP:
            return {"status": R.NO_OP, "reason": v.reason, "provenance": provenance(cand_rec)}

        # 9. publish (copy + verify; the ModKit's file name is never used) -------------
        assert v.candidate is not None and cand_rec is not None
        try:
            published = self._publish(v.candidate, cand_rec.sha256, destination)
        except OSError as exc:
            return {
                "status": R.OUTPUT_INVALID,
                "failure": F.PUBLISH_FAILED,
                "reason": f"publishing failed: {exc}",
                "provenance": provenance(cand_rec),
            }
        base["validation"] = (
            *base["validation"],
            ValidationCheck(id="published_sha256_verified", passed=True),
        )
        return {
            "status": R.SUCCESS,
            "reason": f"validated output published to {published.path}",
            "provenance": provenance(published),
            "published": published,
        }

    # -- helpers --------------------------------------------------------------------

    @staticmethod
    def _publish(candidate: Path, sha: str, destination: Path) -> ArtifactRecord:
        """Copy the validated candidate to *destination* without trusting its name."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_name(f".{destination.name}.partial")
        tmp.unlink(missing_ok=True)
        try:
            with candidate.open("rb") as src, tmp.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            if sha256_file(tmp) != sha:
                raise OSError("published copy does not match the validated candidate")
            # link() refuses to replace an existing destination (no silent overwrite).
            os.link(tmp, destination)
        finally:
            tmp.unlink(missing_ok=True)
        return ArtifactRecord(
            role="published", path=str(destination), sha256=sha, size=destination.stat().st_size
        )

    def _finish(
        self,
        ws: ModKitWorkspace,
        request: ExecutionRequest,
        base: dict[str, Any],
        *,
        status: ModKitResultStatus,
        reason: str,
        failure: FailureCategory | None = None,
        provenance: ProvenanceRecord | None = None,
        published: ArtifactRecord | None = None,
        messages: list[str] | None = None,
    ) -> ModKitExecutionResult:
        success = status in (R.SUCCESS, R.NO_OP)
        limitations = (
            "ModKit output is third-party and untrusted: APKForge validated the archive, "
            "inputs and boundaries, not the semantic safety of the transformation.",
            "Writes outside the workspace cannot be observed without an OS-level sandbox.",
        )
        draft = ModKitExecutionResult(
            **base,
            status=status,
            failure=failure,
            reason=reason,
            provenance=provenance,
            published=published,
            messages=tuple(messages or ()),
            limitations=limitations,
            workspace_retained=True,
        )
        try:
            (ws.metadata_dir / "result.json").write_text(draft.to_json() + "\n", encoding="utf-8")
            if provenance is not None:
                (ws.metadata_dir / "provenance.json").write_text(
                    provenance.model_dump_json(indent=2) + "\n", encoding="utf-8"
                )
        except OSError:
            pass
        retained = ws.apply_retention(
            success=success,
            keep=request.keep_workspace,
            keep_on_failure=self.settings.keep_on_failure,
        )
        return draft.model_copy(update={"workspace_retained": retained})
