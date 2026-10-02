"""C.5 controlled modification pipeline: disable an APK's boot receiver end to end.

::

    original APK -> baseline inspection -> prepare_workspace -> decode
      -> inspect decoded manifest -> plan -> apply (+ source-level self-check)
      -> build -> align -> sign -> verify            (all BuildService)
      -> re-analyse (DiffEngine, original vs modified)
      -> expected-vs-actual classification against the plan and the APK's
         semantic no-op baseline
      -> original SHA-256 unchanged

The modifier only edits the decoded manifest; every tool invocation goes through
BuildService. ``VERIFIED`` requires every stage to pass, the expected changes to be
observed, no unexplained or unclassifiable change, and the original to be
byte-identical. A refused plan (``REFUSED``) never touches the decoded project.
"""

from __future__ import annotations

import hashlib
import shutil
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import ExpectationVerdict, verify_expectations
from apkforge.inspection.engine import InspectionEngine
from apkforge.modification.boot_receiver import (
    ApplyResult,
    BootReceiverPlan,
    apply_plan,
    discover,
    plan_disable_boot_receiver,
)

if TYPE_CHECKING:
    from apkforge.builders.models import StageResult
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.service import BuildService

__all__ = ["ControlledModificationResult", "ModificationStatus", "run_disable_boot_receiver"]


class ModificationStatus(StrEnum):
    VERIFIED = "VERIFIED"  # built, signed, verified, and semantically as planned
    REFUSED = "REFUSED"  # preconditions not met; nothing was modified
    FAILED = "FAILED"  # a stage or a check failed


class StageSummary(BaseModel):
    stage: str
    status: str
    failure_category: str | None = None
    failure_cause: str | None = None
    log_file: str | None = None


class ControlledModificationResult(BaseModel):
    status: ModificationStatus
    failures: list[str] = Field(default_factory=list)
    apk: str
    original_sha256_before: str
    original_sha256_after: str | None = None
    original_preserved: bool = False
    toolchain: dict[str, Any] = Field(default_factory=dict)
    signing_mode: str | None = None
    baseline: dict[str, Any] = Field(default_factory=dict)
    plan: BootReceiverPlan | None = None
    apply: ApplyResult | None = None
    stages: list[StageSummary] = Field(default_factory=list)
    verification: dict[str, Any] | None = None
    output_apk: str | None = None
    output_sha256: str | None = None
    noise_floor: dict[str, Any] = Field(default_factory=dict)
    verdict: ExpectationVerdict | None = None
    workspace: str | None = None
    workspace_kept: bool = False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _summary(sr: StageResult) -> StageSummary:
    return StageSummary(
        stage=str(sr.stage),
        status=str(sr.status),
        failure_category=str(sr.failure_category) if sr.failure_category else None,
        failure_cause=sr.failure_cause,
        log_file=str(sr.log_file) if sr.log_file else None,
    )


def run_disable_boot_receiver(
    service: BuildService,
    apk: Path,
    *,
    noop_baseline: NoopSemanticBaseline | None,
    work_dir: Path | None = None,
    receiver: str | None = None,
    output_apk: Path | None = None,
    keep_workspace: bool = False,
    diff_engine: DiffEngine | None = None,
) -> ControlledModificationResult:
    """Run the C.5 modification on *apk*. Never modifies *apk*; never raises for stage failures.

    Args:
        service: configured BuildService (toolchain + signing).
        noop_baseline: semantic no-op baseline. The APK's own entry restricts accepted
            noise to what its no-op round trip produced. ``None`` falls back to the
            global noise rules and is recorded as a failure (noise floor not established).
        work_dir: parent for the BuildService workspace (default: the service's).
        receiver: explicit boot receiver when the manifest has several.
        output_apk: copy the verified APK here.
        keep_workspace: keep the BuildService workspace (debugging); otherwise it is
            removed on every exit path.
    """
    apk = Path(apk).expanduser().resolve()
    sha_before = _sha256(apk)
    result = ControlledModificationResult(
        status=ModificationStatus.FAILED,
        apk=str(apk),
        original_sha256_before=sha_before,
        toolchain=service.toolchain.to_dict(),
    )
    try:
        _run(service, apk, result, noop_baseline, work_dir, receiver, output_apk, diff_engine)
    finally:
        sha_after = _sha256(apk) if apk.is_file() else None
        result.original_sha256_after = sha_after
        result.original_preserved = sha_after == sha_before
        if not result.original_preserved:
            result.failures.append("Original APK changed during the run.")
            result.status = ModificationStatus.FAILED
        if result.workspace is not None:  # set as soon as the workspace exists
            ws_root = Path(result.workspace)
            result.workspace_kept = keep_workspace
            if not keep_workspace:
                shutil.rmtree(ws_root, ignore_errors=True)
                if result.output_apk and Path(result.output_apk).is_relative_to(ws_root):
                    result.output_apk = None  # removed with the workspace; not exported
    if result.failures and result.status == ModificationStatus.VERIFIED:
        result.status = ModificationStatus.FAILED
    return result


def _run(
    service: BuildService,
    apk: Path,
    result: ControlledModificationResult,
    noop_baseline: NoopSemanticBaseline | None,
    work_dir: Path | None,
    receiver: str | None,
    output_apk: Path | None,
    diff_engine: DiffEngine | None,
) -> None:
    """Pipeline body; records the workspace on *result* as soon as it exists."""
    fail = result.failures.append

    # 1. Baseline inspection of the original (read-only).
    insp = InspectionEngine().inspect(apk, enabled_inspectors={"manifest"}, keep_workspace=False)
    m = insp.manifest
    result.baseline = {
        "package": insp.metadata.package_name,
        "version_name": insp.metadata.version_name,
        "version_code": insp.metadata.version_code,
        "uses_permissions": sorted(p.name for p in m.permissions) if m else [],
        "receivers": {r.name: {"enabled": r.enabled, "exported": r.exported} for r in m.receivers}
        if m
        else {},
        "inspection_status": str(insp.status),
    }

    # 2. Noise floor for this APK.
    allowances = noop_baseline.allowances(result.original_sha256_before) if noop_baseline else None
    if allowances is None:
        fail(
            "No usable semantic no-op baseline for this APK (SHA-256); the noise floor is "
            "not established."
        )
        rules: set[str] | None = None
        residue: set[tuple[str, str, str]] | None = None
    else:
        rules, residue = allowances
    result.noise_floor = {
        "source": "semantic no-op baseline" if allowances else None,
        "allowed_noise_rules": sorted(rules) if rules is not None else None,
        "allowed_residue": sorted(residue) if residue is not None else None,
    }

    # 3. Workspace + decode (BuildService).
    ws, prep = service.prepare_workspace(work_dir=work_dir)
    result.stages.append(_summary(prep))
    if ws is None or not prep.passed:
        fail(f"prepare: {prep.failure_cause}")
        return
    result.workspace = str(ws.root)
    dec = service.decode(apk, ws)
    result.stages.append(_summary(dec))
    if not dec.passed:
        fail(f"decode: {dec.failure_category}: {dec.failure_cause}")
        return

    # 4. Inspect decoded manifest, plan.
    manifest = ws.decoded_dir / "AndroidManifest.xml"
    plan = plan_disable_boot_receiver(
        discover(manifest.read_text(encoding="utf-8")),
        target_apk=str(apk),
        target_sha256=result.original_sha256_before,
        receiver=receiver,
    )
    result.plan = plan
    if not plan.ready:
        result.status = ModificationStatus.REFUSED
        fail(f"plan refused ({plan.status}): " + "; ".join(plan.problems))
        return
    if result.baseline["package"] != plan.package:
        fail(f"decoded package {plan.package} != inspected package {result.baseline['package']}")
        return

    # 5. Apply + source-level self-check.
    applied = apply_plan(plan, manifest)
    result.apply = applied
    if not applied.applied:
        fail("apply: " + "; ".join(applied.errors))
        return

    # 6. build -> align -> sign -> verify (BuildService).
    built = service.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws)
    result.stages.append(_summary(built))
    if not built.passed:
        fail(f"build: {built.failure_category}: {built.failure_cause}")
        return
    aligned = service.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws)
    result.stages.append(_summary(aligned))
    if not aligned.passed:
        fail(f"align: {aligned.failure_category}: {aligned.failure_cause}")
        return
    signed = service.sign(ws.aligned_apk, ws.signed_apk, workspace=ws)
    result.stages.append(_summary(signed))
    if not signed.passed:
        fail(f"sign: {signed.failure_category}: {signed.failure_cause}")
        return
    result.signing_mode = str(service.signing.mode) if service.signing else None
    verified = service.verify(
        ws.signed_apk, expected_certificate_sha256=signed.certificate_sha256, workspace=ws
    )
    result.stages.append(_summary(verified))
    v = verified.verification
    if v is not None:
        result.verification = {
            k: val for k, val in v.to_dict().items() if k not in ("apksigner_output",)
        }
    if not verified.passed:
        fail(f"verify: {verified.failure_category}: {verified.failure_cause}")
        return
    result.output_sha256 = _sha256(ws.signed_apk)
    result.output_apk = str(ws.signed_apk)

    # 7. Re-analyse and compare with the plan.
    diff = (diff_engine or DiffEngine()).diff(apk, ws.signed_apk)
    verdict = verify_expectations(
        diff, plan.expected_changes, allowed_noise_rules=rules, allowed_residue=residue
    )
    result.verdict = verdict
    result.failures.extend(f"semantic: {f}" for f in verdict.failures)

    if not result.failures:
        if output_apk is not None:
            dest = Path(output_apk).expanduser().resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ws.signed_apk, dest)
            result.output_apk = str(dest)
        result.status = ModificationStatus.VERIFIED
