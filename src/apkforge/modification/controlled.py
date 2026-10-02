"""C.5 controlled modification pipeline: disable an APK's boot receiver end to end.

::

    original APK -> baseline inspection -> prepare_workspace -> decode
      -> inspect decoded manifest -> plan -> apply (+ source-level self-check)
      -> build -> align -> sign -> verify            (all BuildService)
      -> re-analyse (DiffEngine, original vs modified)
      -> expected-vs-actual classification against the plan and the APK's
         semantic no-op baseline
      -> original SHA-256 unchanged

Since Phase D this is a thin wrapper: the run is executed by the general
:class:`~apkforge.modification.pipeline.ModificationPipeline` with the single
:class:`~apkforge.modification.builtin.BootReceiverModifier`, and the result is mapped
back to the C.5 result model. The modifier only edits the decoded manifest; every tool
invocation goes through BuildService. ``VERIFIED`` requires every stage to pass, the
expected changes to be observed, no unexplained or unclassifiable change, the modifier's
own verification to pass, and the original to be byte-identical. A refused plan
(``REFUSED``) never touches the decoded project.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.diff.expectations import ExpectationVerdict  # noqa: TC001 - pydantic field
from apkforge.modification.boot_receiver import (
    MODIFIER_ID,
    ApplyResult,
    BootReceiverPlan,
)
from apkforge.modification.builtin import BootReceiverModifier
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
    PipelineStatus,
    StageSummary,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.service import BuildService
    from apkforge.diff.engine import DiffEngine

__all__ = ["ControlledModificationResult", "ModificationStatus", "run_disable_boot_receiver"]


class ModificationStatus(StrEnum):
    VERIFIED = "VERIFIED"  # built, signed, verified, and semantically as planned
    REFUSED = "REFUSED"  # preconditions not met; nothing was modified
    FAILED = "FAILED"  # a stage or a check failed


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
    params = {"receiver": receiver} if receiver is not None else {}
    pipeline = ModificationPipeline(
        service, ModifierCatalog([BootReceiverModifier()]), diff_engine=diff_engine
    )
    res = pipeline.run(
        apk,
        [ModifierRequest(modifier_id=MODIFIER_ID, parameters=params)],
        noop_baseline=noop_baseline,
        work_dir=work_dir,
        output_apk=output_apk,
        keep_workspace=keep_workspace,
    )
    return _from_pipeline(res)


_STATUS = {
    PipelineStatus.VERIFIED: ModificationStatus.VERIFIED,
    PipelineStatus.SKIPPED: ModificationStatus.REFUSED,
    PipelineStatus.REFUSED: ModificationStatus.REFUSED,
}


def _from_pipeline(res: PipelineResult) -> ControlledModificationResult:
    """Map a single-modifier pipeline result onto the C.5 result model."""
    (run,) = res.modifiers
    native = run.plan.details.get("boot_receiver_plan") if run.plan else None
    plan = BootReceiverPlan.model_validate(native) if native else None
    applied = run.apply.details.get("apply_result") if run.apply else None
    failures = list(res.failures)
    status = _STATUS.get(res.status, ModificationStatus.FAILED)
    if status == ModificationStatus.REFUSED and plan is not None:
        failures.append(f"plan refused ({plan.status}): " + "; ".join(plan.problems))
    return ControlledModificationResult(
        status=status,
        failures=failures,
        apk=res.apk,
        original_sha256_before=res.original_sha256_before,
        original_sha256_after=res.original_sha256_after,
        original_preserved=res.original_preserved,
        toolchain=res.toolchain,
        signing_mode=res.signing_mode,
        baseline=res.baseline,
        plan=plan,
        apply=ApplyResult.model_validate(applied) if applied else None,
        stages=res.stages,
        verification=res.verification,
        output_apk=res.output_apk,
        output_sha256=res.output_sha256,
        noise_floor=res.noise_floor,
        verdict=res.verdict,
        workspace=res.workspace,
        workspace_kept=res.workspace_kept,
    )
