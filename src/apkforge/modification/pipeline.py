"""Phase D modification pipeline: run one or more modifiers through the C.5 workflow.

::

    original APK (never written; SHA-256 re-checked at every checkpoint)
      -> baseline inspection (InspectionEngine, manifest)
      -> noise floor (semantic no-op baseline of this APK)
      -> BuildService.prepare_workspace() -> decode()
      -> per modifier, in request order: inspect -> plan (+ preconditions)
      -> plan validation, conflict detection          (nothing written so far)
      -> per modifier: re-plan -> apply -> source check (files + manifest edits)
           failure: roll back every applied modifier, later ones are not attempted
      -> BuildService.build() -> align() -> sign() -> verify()    (APK verification)
      -> DiffEngine.diff(original, rebuilt)
      -> expected-vs-actual classification of the combined plan  (verify_expectations)
      -> per modifier: its expected changes observed? its own verify()
                                                     (modification verification)
      -> aggregate result

Responsibilities stay separated: modifiers decide *what* changes and edit decoded
files; BuildService runs every tool; DiffEngine and :mod:`apkforge.diff.expectations`
compare; this module orders, checks, rolls back and aggregates. It runs no
subprocess itself.

Step statuses reuse :class:`~apkforge.modification.modifiers.base.StepStatus` and
:class:`~apkforge.modification.modifiers.base.ModificationStepResult`: a skipped step
is never a success, a step not reached stays ``PENDING`` (not attempted), and a step
is ``verified`` only when the modifier's own verification ran and passed.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
import zipfile
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.builders.semantic_baseline import (
    BaselineCheck,
    BaselineStatus,
    current_toolchain_identity,
)
from apkforge.core.exceptions import InputError, ModificationError
from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import ExpectationVerdict, ExpectedChange  # noqa: TC001 (pydantic)
from apkforge.diff.normalization import ToolchainIdentity, archive_entries_for
from apkforge.diff.security import build_security_diff
from apkforge.inspection.engine import InspectionEngine
from apkforge.modification.catalog import ModifierCatalog, default_catalog
from apkforge.modification.contract import (
    MANIFEST,
    ApplyOutcome,
    FileAction,
    ModifierInfo,
    ModifierPlan,
    PlannedFileChange,
    ProjectContext,
    VerificationEvidence,
    VerificationOutcome,
    validate_relative_path,
)
from apkforge.modification.edits import SourceEdit, manifest_edits, same_edits
from apkforge.modification.modifiers.base import (
    ModificationResult,
    ModificationStepResult,
    StepStatus,
)
from apkforge.verification.checks import signature_check, structural_check
from apkforge.verification.matrix import build_matrix
from apkforge.verification.models import (
    CheckStatus,
    OverallStatus,
    VerificationCheck,
    VerificationMatrix,
)
from apkforge.verification.pair import check_baseline, classify
from apkforge.verification.report import VerificationReport, build_report

if TYPE_CHECKING:
    from apkforge.builders.models import StageResult
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.service import BuildService
    from apkforge.builders.workspace import BuildWorkspace
    from apkforge.modification.contract import APKModifier

__all__ = [
    "Conflict",
    "ModificationPipeline",
    "ModifierRequest",
    "ModifierRun",
    "PipelineResult",
    "PipelineStatus",
    "SourceCheck",
    "StageSummary",
    "detect_conflicts",
    "measure_noise_floor",
]

ORIGINAL_CHANGED = "Original APK changed during the run."


class PipelineStatus(StrEnum):
    """Overall outcome of a pipeline run.

    - ``VERIFIED``: every requested modifier executed and was verified, the APK was
      built, aligned, signed and verified, the diff matched the combined plan, and the
      original is byte-identical.
    - ``UNVERIFIED``: as ``VERIFIED``, but at least one modifier has no verification;
      it is reported *not verified*.
    - ``PARTIAL``: ``allow_partial`` was set and some modifiers were skipped (failed
      preconditions); the others completed as above.
    - ``DRY_RUN``: planned and checked only; nothing was applied or built.
    - ``SKIPPED``: nothing was executed: every modifier's preconditions failed.
    - ``REFUSED``: nothing was executed: plans conflict, or some modifier was skipped
      and partial execution was not allowed.
    - ``FAILED``: anything else (a stage, a modifier, a check, or the original changed).
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIAL = "partial"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"
    REFUSED = "refused"
    FAILED = "failed"


class ModifierRequest(BaseModel):
    modifier_id: str
    parameters: dict[str, str] = Field(default_factory=dict)


class Conflict(BaseModel):
    """Two plans that cannot be applied together."""

    kind: str  # target | file | expected_change
    modifiers: list[str]
    subject: str
    reason: str


class SourceCheck(BaseModel):
    """Framework check of what one ``apply`` actually changed in the decoded project."""

    passed: bool
    added: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    unplanned: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    manifest_edits: list[SourceEdit] = Field(default_factory=list)
    manifest_matches_plan: bool | None = None
    problems: list[str] = Field(default_factory=list)


class StageSummary(BaseModel):
    stage: str
    status: str
    failure_category: str | None = None
    failure_cause: str | None = None
    log_file: str | None = None


class ModifierRun(BaseModel):
    """Everything recorded about one requested modifier."""

    order: int
    info: ModifierInfo
    parameters: dict[str, str] = Field(default_factory=dict)
    findings: dict[str, Any] = Field(default_factory=dict)
    plan: ModifierPlan | None = None
    step: ModificationStepResult
    apply: ApplyOutcome | None = None
    source_check: SourceCheck | None = None
    expected_observed: list[ExpectedChange] = Field(default_factory=list)
    expected_missing: list[ExpectedChange] = Field(default_factory=list)
    verification: VerificationOutcome | None = None

    @property
    def verification_state(self) -> str:
        """``verified`` / ``verification_failed`` / ``not_verified`` / ``not_executed``."""
        if not self.step.executed:
            return "not_executed"
        if self.step.verified is True:
            return "verified"
        if self.step.verified is False:
            return "verification_failed"
        return "not_verified"


class PipelineResult(BaseModel):
    run_id: str
    status: PipelineStatus = PipelineStatus.FAILED
    dry_run: bool = False
    allow_partial: bool = False
    apk: str
    original_sha256_before: str
    original_sha256_after: str | None = None
    original_preserved: bool = False
    original_checkpoints: list[str] = Field(
        default_factory=list, description="Checkpoints at which the original SHA-256 matched."
    )
    toolchain: dict[str, Any] = Field(default_factory=dict)
    signing_mode: str | None = None
    baseline: dict[str, Any] = Field(default_factory=dict)
    noise_floor: dict[str, Any] = Field(default_factory=dict)
    order: list[str] = Field(default_factory=list)
    modifiers: list[ModifierRun] = Field(default_factory=list)
    conflicts: list[Conflict] = Field(default_factory=list)
    rollback: dict[str, Any] | None = None
    stages: list[StageSummary] = Field(default_factory=list)
    build_passed: bool | None = None  # None: not attempted
    apk_verified: bool | None = None  # BuildService verify stage; None: not attempted
    verification: dict[str, Any] | None = None
    verdict: ExpectationVerdict | None = None
    #: Phase E: toolchain identity, baseline compatibility, verification matrix, report
    toolchain_identity: ToolchainIdentity | None = None
    baseline_check: BaselineCheck | None = None
    signer_sha256: str | None = None
    verification_matrix: VerificationMatrix | None = None
    report: VerificationReport | None = None
    output_apk: str | None = None
    output_sha256: str | None = None
    workspace: str | None = None
    workspace_kept: bool = False
    failures: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def execution(self) -> ModificationResult:
        """The modifier steps as a legacy-compatible ``ModificationResult``."""
        return ModificationResult(
            plan_id=self.run_id,
            dry_run=self.dry_run,
            planned_steps=len(self.modifiers),
            steps=[r.step for r in self.modifiers],
            original_apk_path=self.apk,
        )

    @property
    def modification_verified(self) -> bool:
        """True only if every requested modifier executed and was verified."""
        return bool(self.modifiers) and all(r.step.verified is True for r in self.modifiers)

    def counts(self) -> dict[str, int]:
        ex = self.execution()
        steps = [r.step for r in self.modifiers]
        return {
            "requested": len(steps),
            "planned": sum(1 for r in self.modifiers if r.plan is not None and r.plan.ready),
            "executed": ex.executed_steps,
            "dry_run": sum(1 for s in steps if s.status == StepStatus.DRY_RUN),
            "skipped": ex.skipped_steps,
            "failed": ex.failed_steps,
            "verified": ex.verified_steps,
            "verification_failed": sum(1 for s in steps if s.verified is False),
            "not_verified": sum(1 for s in steps if s.executed and s.verified is None),
            "not_attempted": ex.not_attempted_steps,
            "rolled_back": ex.rolled_back_steps,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


_SYMLINK = "<symlink>"


def _snapshot(root: Path) -> dict[str, str]:
    """POSIX relative path -> SHA-256 of every file under *root* (symlinks marked)."""
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in [*dirnames, *filenames]:
            p = base / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out[rel] = _SYMLINK
            elif name in filenames:
                out[rel] = _sha256(p)
    return out


def _step(order: int, modifier_id: str) -> ModificationStepResult:
    return ModificationStepResult(
        change_id=f"{order}:{modifier_id}",
        modifier_id=modifier_id,
        status=StepStatus.PENDING,
        message="Not attempted.",
    )


def _not_attempted(runs: list[ModifierRun], reason: str) -> None:
    for r in runs:
        if r.step.status == StepStatus.PENDING:
            r.step.message = f"Not attempted: {reason}"


class _OriginalChanged(Exception):
    pass


def detect_conflicts(plans: list[ModifierPlan]) -> list[Conflict]:
    """Pairwise conflicts between ready plans (in order; deterministic).

    - ``target``: both plans name the same target (kind + identifier) and at least one
      writes it (add/modify/remove).
    - ``file``: both plans touch the same file and not both only modify it (modifying a
      shared file such as the manifest is allowed; the targets decide).
    - ``expected_change``: both plans expect an observation for the same category and
      identifier, so the rebuilt APK could not attribute it to one of them.
    """
    found: list[Conflict] = []
    for i, a in enumerate(plans):
        for b in plans[i + 1 :]:
            pair = [a.modifier_id, b.modifier_id]
            for ta in a.targets:
                for tb in b.targets:
                    if (ta.kind, ta.identifier) == (tb.kind, tb.identifier) and (
                        ta.writes or tb.writes
                    ):
                        found.append(
                            Conflict(
                                kind="target",
                                modifiers=pair,
                                subject=f"{ta.kind}:{ta.identifier}",
                                reason=f"{a.modifier_id} {ta.access} / {b.modifier_id} "
                                f"{tb.access} the same target",
                            )
                        )
            files_b = {f.path: f.action for f in b.file_changes}
            for fa in a.file_changes:
                fb = files_b.get(fa.path)
                if fb is not None and not (fa.action == fb == FileAction.MODIFY):
                    found.append(
                        Conflict(
                            kind="file",
                            modifiers=pair,
                            subject=fa.path,
                            reason=f"{a.modifier_id} {fa.action}s / {b.modifier_id} {fb}s "
                            "the same file",
                        )
                    )
            keys_b = {(e.category, e.identifier) for e in b.expected_changes}
            for ea in a.expected_changes:
                if (ea.category, ea.identifier) in keys_b:
                    found.append(
                        Conflict(
                            kind="expected_change",
                            modifiers=pair,
                            subject=f"{ea.category}:{ea.identifier}",
                            reason="both plans expect a change of the same item; the "
                            "combined effect could not be attributed",
                        )
                    )
    # One entry per (kind, pair, subject).
    unique: dict[tuple[str, ...], Conflict] = {}
    for c in found:
        unique.setdefault((c.kind, *c.modifiers, c.subject), c)
    return list(unique.values())


def _validate_plan(plan: ModifierPlan, modifier: APKModifier, project: ProjectContext) -> list[str]:
    """Structural problems that make a plan unusable (empty list: valid)."""
    problems: list[str] = []
    if plan.modifier_id != modifier.id:
        problems.append(f"plan names modifier {plan.modifier_id!r}, not {modifier.id!r}")
    if plan.target_sha256 != project.original_sha256:
        problems.append("plan target SHA-256 does not match the original APK")
    paths: set[str] = set()
    for fc in plan.file_changes:
        try:
            validate_relative_path(fc.path)
            project.path(fc.path)
        except ModificationError as exc:
            problems.append(str(exc))
        if fc.path in paths:
            problems.append(f"file {fc.path} is listed twice")
        paths.add(fc.path)
    if not plan.ready:
        return problems
    if not plan.file_changes:
        problems.append("a ready plan must declare the files it changes")
    if plan.manifest_edits and PlannedFileChange(path=MANIFEST, action=FileAction.MODIFY) not in (
        plan.file_changes
    ):
        problems.append("manifest edits are planned but AndroidManifest.xml is not declared")
    return problems


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class _Applied:
    """Rollback record for one applied modifier."""

    def __init__(
        self, run: ModifierRun, before: dict[str, str], backup: dict[str, bytes | None]
    ) -> None:
        self.run = run
        self.before = before
        self.backup = backup


class ModificationPipeline:
    """Runs requested modifiers against one APK. See the module docstring.

    Args:
        service: a configured BuildService (any object with its stage methods).
        catalog: modifiers that may be requested (default: :func:`default_catalog`).
        diff_engine: DiffEngine for the expected-vs-actual comparison.
    """

    def __init__(
        self,
        service: BuildService,
        catalog: ModifierCatalog | None = None,
        *,
        diff_engine: DiffEngine | None = None,
    ) -> None:
        self.service = service
        self.catalog = catalog or default_catalog()
        self.diff_engine = diff_engine

    # -- request validation -------------------------------------------------

    def resolve(self, requests: list[ModifierRequest]) -> list[APKModifier]:
        """Validate *requests* before anything runs; raises ModificationError."""
        if not requests:
            raise ModificationError("No modifier requested", context="pipeline")
        seen: set[str] = set()
        modifiers: list[APKModifier] = []
        for req in requests:
            if req.modifier_id in seen:
                raise ModificationError(
                    f"Modifier {req.modifier_id!r} is requested more than once",
                    context="pipeline",
                )
            seen.add(req.modifier_id)
            m = self.catalog.get(req.modifier_id)
            unknown = sorted(set(req.parameters) - set(m.parameters))
            if unknown:
                raise ModificationError(
                    f"Modifier {m.id!r} does not accept parameter(s) {unknown}; accepted: "
                    f"{sorted(m.parameters) or 'none'}",
                    context="pipeline",
                )
            modifiers.append(m)
        return modifiers

    # -- entry point --------------------------------------------------------

    def run(
        self,
        apk: Path,
        requests: list[ModifierRequest],
        *,
        noop_baseline: NoopSemanticBaseline | None = None,
        dry_run: bool = False,
        allow_partial: bool = False,
        work_dir: Path | None = None,
        output_apk: Path | None = None,
        keep_workspace: bool = False,
    ) -> PipelineResult:
        """Plan (``dry_run``) or execute *requests* on *apk*. Never modifies *apk*.

        Args:
            noop_baseline: semantic no-op baseline; this APK's entry is the noise floor.
                ``None`` falls back to the global noise rules and is recorded as a
                failure (noise floor not established), except in a dry run.
            dry_run: stop after planning, validation and conflict detection.
            allow_partial: execute the ready modifiers even if others were skipped.
            work_dir: parent for the BuildService workspace (default: the service's).
            output_apk: copy the rebuilt APK here when the run has no failure.
            keep_workspace: keep the BuildService workspace (debugging/evidence).

        Raises:
            InputError: *apk* is not a file.
            ModificationError: invalid request (unknown or repeated modifier, unknown
                parameter). Raised before anything runs.
        """
        modifiers = self.resolve(requests)
        apk = Path(apk).expanduser().resolve()
        if not apk.is_file():
            raise InputError(f"APK not found: {apk}", context="pipeline")
        sha_before = _sha256(apk)
        result = PipelineResult(
            run_id=uuid.uuid4().hex[:12],
            dry_run=dry_run,
            allow_partial=allow_partial,
            apk=str(apk),
            original_sha256_before=sha_before,
            toolchain=self.service.toolchain.to_dict(),
            order=[m.id for m in modifiers],
            modifiers=[
                ModifierRun(
                    order=i, info=m.info(), parameters=dict(req.parameters), step=_step(i, m.id)
                )
                for i, (m, req) in enumerate(zip(modifiers, requests, strict=True))
            ],
        )
        try:
            self._run(apk, modifiers, result, noop_baseline, work_dir, output_apk)
        except _OriginalChanged:
            result.status = PipelineStatus.FAILED
            _not_attempted(result.modifiers, "the original APK changed; run stopped")
        finally:
            sha_after = _sha256(apk) if apk.is_file() else None
            result.original_sha256_after = sha_after
            result.original_preserved = sha_after == sha_before
            if not result.original_preserved:
                if ORIGINAL_CHANGED not in result.failures:
                    result.failures.append(ORIGINAL_CHANGED)
                result.status = PipelineStatus.FAILED
            if result.workspace is not None:  # set as soon as the workspace exists
                ws_root = Path(result.workspace)
                result.workspace_kept = keep_workspace
                if not keep_workspace:
                    shutil.rmtree(ws_root, ignore_errors=True)
                    if result.output_apk and Path(result.output_apk).is_relative_to(ws_root):
                        result.output_apk = None  # removed with the workspace; not exported
        if result.failures and result.status in (
            PipelineStatus.VERIFIED,
            PipelineStatus.UNVERIFIED,
            PipelineStatus.PARTIAL,
            PipelineStatus.DRY_RUN,
        ):
            result.status = PipelineStatus.FAILED
        return result

    # -- body ---------------------------------------------------------------

    def _check_original(self, apk: Path, result: PipelineResult, checkpoint: str) -> None:
        if _sha256(apk) != result.original_sha256_before:
            result.failures.append(ORIGINAL_CHANGED)
            result.failures.append(f"original APK SHA-256 mismatch detected after {checkpoint}")
            raise _OriginalChanged
        result.original_checkpoints.append(checkpoint)

    def _run(
        self,
        apk: Path,
        modifiers: list[APKModifier],
        result: PipelineResult,
        noop_baseline: NoopSemanticBaseline | None,
        work_dir: Path | None,
        output_apk: Path | None,
    ) -> None:
        fail = result.failures.append
        runs = result.modifiers

        if not zipfile.is_zipfile(apk):
            fail("invalid APK: not a ZIP archive")
            _not_attempted(runs, "invalid APK")
            return

        # 1. Baseline inspection of the original (read-only).
        insp = InspectionEngine().inspect(
            apk, enabled_inspectors={"manifest"}, keep_workspace=False
        )
        m = insp.manifest
        result.baseline = {
            "package": insp.metadata.package_name,
            "version_name": insp.metadata.version_name,
            "version_code": insp.metadata.version_code,
            "uses_permissions": sorted(p.name for p in m.permissions) if m else [],
            "receivers": {
                r.name: {"enabled": r.enabled, "exported": r.exported} for r in m.receivers
            }
            if m
            else {},
            "inspection_status": str(insp.status),
        }

        # 2. Noise floor (not needed for a dry run: nothing is built or compared).
        #    A v2 baseline is used only with this service's exact toolchain identity.
        toolchain = current_toolchain_identity(self.service)
        result.toolchain_identity = toolchain
        check = check_baseline(noop_baseline, result.original_sha256_before, toolchain)
        result.baseline_check = check
        if result.dry_run:
            result.noise_floor = {"source": None, "note": "dry run: no diff is classified"}
        else:
            sha = result.original_sha256_before
            entry = noop_baseline.entry_for(sha) if noop_baseline else None
            if not check.usable:
                fail(
                    f"No usable semantic no-op baseline for this APK ({check.status}: "
                    f"{'; '.join(check.reasons)}); the noise floor is not established."
                )
            allowances = noop_baseline.allowances(result.original_sha256_before) if (
                noop_baseline and check.usable) else None  # fmt: skip
            rules = (
                set(entry.fingerprint.rule_counts())
                if check.content_aware and entry is not None and entry.fingerprint
                else (allowances[0] if allowances else None)
            )
            result.noise_floor = {
                "source": "semantic no-op baseline" if check.usable else None,
                "baseline_status": str(check.status),
                "content_aware": check.content_aware,
                "allowed_noise_rules": sorted(rules) if rules is not None else None,
                "allowed_residue": sorted(allowances[1]) if allowances else None,
            }
            if check.status == BaselineStatus.LEGACY_PATH_RULES:
                result.warnings.append(
                    "legacy (schema 1) no-op baseline: noise is accepted by path rule without "
                    "comparing content; the result cannot be VERIFIED"
                )

        # 3. Workspace + decode (BuildService).
        ws, prep = self.service.prepare_workspace(work_dir=work_dir)
        result.stages.append(_summary(prep))
        if ws is None or not prep.passed:
            fail(f"prepare: {prep.failure_cause}")
            _not_attempted(runs, "workspace preparation failed")
            return
        result.workspace = str(ws.root)
        dec = self.service.decode(apk, ws)
        result.stages.append(_summary(dec))
        if not dec.passed:
            fail(f"decode: {dec.failure_category}: {dec.failure_cause}")
            _not_attempted(runs, "decode failed")
            return
        project = ProjectContext(
            ws.decoded_dir,
            original_apk=apk,
            original_sha256=result.original_sha256_before,
            baseline=result.baseline,
        )
        decoded_package = project.package()
        if result.baseline["package"] != decoded_package:
            fail(
                f"decoded package {decoded_package} != inspected package "
                f"{result.baseline['package']}"
            )
            _not_attempted(runs, "decoded package does not match the inspected APK")
            return

        # 4. Plan every modifier against the unmodified project. Planning never writes.
        pristine = _snapshot(project.decoded_dir)
        planning_failed = False
        for mod, run in zip(modifiers, runs, strict=True):
            if not self._plan(mod, run, project):
                planning_failed = True
        if _snapshot(project.decoded_dir) != pristine:
            fail("planning modified the decoded project")
            planning_failed = True
        self._check_original(apk, result, "planning")
        if planning_failed:
            _not_attempted(runs, "planning failed")
            return

        ready = [r for r in runs if r.plan is not None and r.plan.ready]
        skipped = [r for r in runs if r.step.status == StepStatus.SKIPPED]

        # 5. Conflicts between ready plans.
        result.conflicts = detect_conflicts([r.plan for r in ready if r.plan is not None])
        if result.conflicts:
            result.status = PipelineStatus.REFUSED
            subjects = ", ".join(sorted({c.subject for c in result.conflicts}))
            result.warnings.append(f"{len(result.conflicts)} conflict(s) between plans")
            _not_attempted(runs, f"conflicting plans ({subjects})")
            return
        if not ready:
            result.status = PipelineStatus.SKIPPED
            result.warnings.append("No change was executed: every modifier was skipped.")
            return
        if skipped and not result.allow_partial:
            result.status = PipelineStatus.REFUSED
            names = ", ".join(r.info.id for r in skipped)
            result.warnings.append(
                f"{names} skipped (preconditions not met) and partial execution is not allowed"
            )
            _not_attempted(runs, f"{names} skipped and partial execution is not allowed")
            return

        # 6. Dry run ends here.
        if result.dry_run:
            for r in ready:
                r.step.status = StepStatus.DRY_RUN
                r.step.message = "Would apply: " + "; ".join(r.plan.changes if r.plan else [])
            result.status = PipelineStatus.PARTIAL if skipped else PipelineStatus.DRY_RUN
            return

        # 7. Apply, in order, with a source check after each modifier.
        if not self._apply_all(apk, modifiers, ready, project, result):
            result.status = PipelineStatus.FAILED
            return

        # 8. build -> align -> sign -> verify (BuildService).
        if not self._build(ws, result):
            self._check_original(apk, result, "build pipeline")
            _not_attempted(runs, "build pipeline failed")
            return
        self._check_original(apk, result, "build pipeline")

        # 9. Re-analyse, compare with the combined plan, then per-modifier verification.
        diff = (self.diff_engine or DiffEngine()).diff(apk, ws.signed_apk)
        expected = [e for r in ready if r.plan is not None for e in r.plan.expected_changes]
        planned, unmapped = archive_entries_for(
            sorted({fc.path for r in ready if r.plan is not None for fc in r.plan.file_changes})
        )
        if unmapped:
            result.warnings.append(
                "planned change(s) to project files with no known archive mapping: "
                + ", ".join(unmapped)
            )
        verdict = classify(
            diff,
            expected,
            noop_baseline,
            check,
            planned_entries=planned,
            expected_signer=result.signer_sha256,
            sha256=result.original_sha256_before,
        )
        result.verdict = verdict
        result.failures.extend(f"semantic: {f}" for f in verdict.failures)
        evidence = VerificationEvidence(project, ws.signed_apk, diff, verdict)
        for mod, run in zip(modifiers, runs, strict=True):
            if run.step.executed:
                self._verify(mod, run, evidence, verdict, result)
        self._check_original(apk, result, "diff")

        # 10. Verification matrix (Phase E6) over the rebuilt APK.
        security = build_security_diff(diff, verdict)
        # A test double that does not produce real APKs supplies its own check.
        checker = getattr(self.service, "structural_check", None) or structural_check
        matrix = build_matrix(
            structural=checker(ws.signed_apk),
            signature=signature_check(result.verification),
            baseline=check,
            diff=diff,
            verdict=verdict,
            security=security,
            expected=expected,
            modification=_modification_row(runs),
        )
        result.verification_matrix = matrix
        result.report = build_report(
            diff=diff,
            verdict=verdict,
            security=security,
            matrix=matrix,
            baseline=check,
            toolchain=toolchain,
            expected=expected,
            requested=[f"{r.info.id}: {c}" for r in ready if r.plan for c in r.plan.changes],
            original=apk,
            modified=ws.signed_apk,
        )
        if matrix.overall == OverallStatus.FAILED and not result.failures:
            result.failures.append(f"verification: {matrix.overall_reason}")

        if not result.failures:
            if output_apk is not None:
                self._export(apk, ws.signed_apk, Path(output_apk), result)
            if not result.failures:
                result.status = self._final_status(runs, skipped)
                if (
                    result.status == PipelineStatus.VERIFIED
                    and matrix.overall != OverallStatus.VERIFIED
                ):
                    result.status = PipelineStatus.UNVERIFIED
                    result.warnings.append(
                        f"verification matrix is {matrix.overall} ({matrix.overall_reason}); "
                        "the run is reported not verified"
                    )

    # -- planning -----------------------------------------------------------

    def _plan(self, mod: APKModifier, run: ModifierRun, project: ProjectContext) -> bool:
        """Inspect + plan one modifier; False if planning itself failed."""
        step = run.step
        try:
            run.findings = mod.inspect(project)
            plan = mod.plan(project, run.findings, dict(run.parameters))
        except Exception as exc:
            step.status = StepStatus.FAILED
            step.message = f"Planning exception: {type(exc).__name__}: {exc}"
            step.details["exception_type"] = type(exc).__name__
            return False
        run.plan = plan
        problems = _validate_plan(plan, mod, project)
        if problems:
            step.status = StepStatus.FAILED
            step.message = "Invalid plan: " + "; ".join(problems)
            return False
        if not plan.ready:
            step.status = StepStatus.SKIPPED
            code = f" ({plan.refusal_code})" if plan.refusal_code else ""
            step.message = f"Preconditions not met{code}: " + "; ".join(plan.problems)
            step.details["readiness"] = str(plan.readiness)
            if plan.refusal_code:
                step.details["refusal_code"] = plan.refusal_code
        return True

    # -- apply + rollback ---------------------------------------------------

    def _apply_all(
        self,
        apk: Path,
        modifiers: list[APKModifier],
        ready: list[ModifierRun],
        project: ProjectContext,
        result: PipelineResult,
    ) -> bool:
        by_id = {m.id: m for m in modifiers}
        applied: list[_Applied] = []
        initial = _snapshot(project.decoded_dir)
        for run in ready:
            mod = by_id[run.info.id]
            ok, record = self._apply_one(mod, run, project)
            if record is not None:
                applied.append(record)
            if ok:
                self._check_original(apk, result, f"apply {mod.id}")
                continue
            result.failures.append(f"apply: {mod.id}: {run.step.message}")
            self._rollback(applied, project, initial, result)
            _not_attempted(result.modifiers, f"execution stopped at {mod.id}")
            self._check_original(apk, result, f"apply {mod.id}")
            return False
        return True

    def _apply_one(
        self, mod: APKModifier, run: ModifierRun, project: ProjectContext
    ) -> tuple[bool, _Applied | None]:
        """Re-plan, apply and source-check one modifier. Returns (ok, rollback record)."""
        step = run.step
        planned = run.plan
        assert planned is not None
        # Re-plan against the current project: earlier modifiers must not have changed
        # what this one intends to do.
        try:
            fresh = mod.plan(project, mod.inspect(project), dict(run.parameters))
        except Exception as exc:
            step.status = StepStatus.FAILED
            step.message = f"Re-planning exception: {type(exc).__name__}: {exc}"
            return False, None
        if fresh.comparable() != planned.comparable():
            step.status = StepStatus.FAILED
            step.message = (
                "Plan changed after earlier modifications were applied; the interaction "
                "was not detectable at planning time."
            )
            return False, None
        run.plan = fresh

        before = _snapshot(project.decoded_dir)
        backup: dict[str, bytes | None] = {}
        for fc in fresh.file_changes:
            p = project.path(fc.path)
            backup[fc.path] = p.read_bytes() if p.is_file() and not p.is_symlink() else None
        manifest_before = backup.get(MANIFEST)
        record = _Applied(run, before, backup)

        try:
            outcome = mod.apply(fresh, project)
        except Exception as exc:
            step.status = StepStatus.FAILED
            step.message = f"Apply exception: {type(exc).__name__}: {exc}"
            step.details["exception_type"] = type(exc).__name__
            return False, record
        run.apply = outcome
        check = _source_check(fresh, project, before, manifest_before)
        run.source_check = check
        step.files_created, step.files_modified, step.files_deleted = (
            check.added,
            check.modified,
            check.removed,
        )
        if not outcome.applied:
            step.status = StepStatus.FAILED
            step.message = "Apply failed: " + ("; ".join(outcome.errors) or outcome.message)
            return False, record
        if not check.passed:
            step.status = StepStatus.FAILED
            step.message = "Source check failed: " + "; ".join(check.problems)
            return False, record
        step.status = StepStatus.SUCCESS
        step.message = outcome.message or "; ".join(fresh.changes) or "applied"
        return True, record

    def _rollback(
        self,
        applied: list[_Applied],
        project: ProjectContext,
        initial: dict[str, str],
        result: PipelineResult,
    ) -> None:
        """Undo applied modifiers in reverse order and confirm the project is restored."""
        errors: list[str] = []
        for rec in reversed(applied):
            now = _snapshot(project.decoded_dir)
            rec_errors: list[str] = []
            for rel, data in rec.backup.items():
                p = project.path(rel)
                try:
                    if data is None:
                        if p.is_symlink() or p.is_file():
                            p.unlink()
                    else:
                        p.parent.mkdir(parents=True, exist_ok=True)
                        if p.is_symlink():
                            p.unlink()
                        p.write_bytes(data)
                except OSError as exc:
                    rec_errors.append(f"{rel}: {exc}")
            for rel in sorted(now.keys() - rec.before.keys() - rec.backup.keys()):
                try:  # unplanned additions can be removed
                    project.path(rel).unlink()
                except (OSError, ModificationError) as exc:
                    rec_errors.append(f"{rel}: {exc}")
            for rel in rec.backup:
                _prune_empty_parents(project.path(rel).parent, project.decoded_dir)
            restored = _snapshot(project.decoded_dir) == rec.before
            if not restored:
                rec_errors.append(f"{rec.run.info.id}: project not restored to its prior state")
            # rolled_back only for a step that had changed something and was undone.
            if restored and now != rec.before:
                rec.run.step.rolled_back = True
            errors.extend(rec_errors)
        restored_all = _snapshot(project.decoded_dir) == initial
        result.rollback = {
            "attempted": True,
            "restored": restored_all and not errors,
            "modifiers": [r.run.info.id for r in reversed(applied) if r.run.step.rolled_back],
            "errors": errors,
            "scope": "decoded project in the BuildService workspace",
        }
        if errors or not restored_all:
            result.failures.append("rollback: " + ("; ".join(errors) or "project not restored"))

    # -- build --------------------------------------------------------------

    def _build(self, ws: BuildWorkspace, result: PipelineResult) -> bool:
        fail = result.failures.append
        svc = self.service
        result.build_passed = False
        built = svc.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws)
        result.stages.append(_summary(built))
        if not built.passed:
            fail(f"build: {built.failure_category}: {built.failure_cause}")
            return False
        aligned = svc.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws)
        result.stages.append(_summary(aligned))
        if not aligned.passed:
            fail(f"align: {aligned.failure_category}: {aligned.failure_cause}")
            return False
        signed = svc.sign(ws.aligned_apk, ws.signed_apk, workspace=ws)
        result.stages.append(_summary(signed))
        if not signed.passed:
            fail(f"sign: {signed.failure_category}: {signed.failure_cause}")
            return False
        result.build_passed = True
        result.signer_sha256 = signed.certificate_sha256
        result.signing_mode = str(svc.signing.mode) if svc.signing else None
        verified = svc.verify(
            ws.signed_apk, expected_certificate_sha256=signed.certificate_sha256, workspace=ws
        )
        result.stages.append(_summary(verified))
        v = verified.verification
        if v is not None:
            result.verification = {
                k: val for k, val in v.to_dict().items() if k not in ("apksigner_output",)
            }
        result.apk_verified = verified.passed
        if not verified.passed:
            fail(f"verify: {verified.failure_category}: {verified.failure_cause}")
            return False
        result.output_sha256 = _sha256(ws.signed_apk)
        result.output_apk = str(ws.signed_apk)
        return True

    # -- verification -------------------------------------------------------

    @staticmethod
    def _verify(
        mod: APKModifier,
        run: ModifierRun,
        evidence: VerificationEvidence,
        verdict: ExpectationVerdict,
        result: PipelineResult,
    ) -> None:
        plan = run.plan
        assert plan is not None
        run.expected_observed = [e for e in plan.expected_changes if e in verdict.expected_observed]
        run.expected_missing = [e for e in plan.expected_changes if e in verdict.expected_missing]
        step = run.step
        if mod.has_verification():
            try:
                run.verification = mod.verify(plan, evidence)
            except Exception as exc:
                run.verification = VerificationOutcome(
                    passed=False, message=f"Verify exception: {type(exc).__name__}: {exc}"
                )
                step.details["exception_type"] = type(exc).__name__
            step.verified = run.verification.passed
        problems: list[str] = []
        if run.verification is not None and not run.verification.passed:
            problems.append(run.verification.message)
        if run.expected_missing:
            problems.append(
                "expected change(s) not observed: "
                + ", ".join(f"{e.category} {e.kind} {e.identifier}" for e in run.expected_missing)
            )
            step.verified = False
        if problems:
            step.verified = False
            step.status = StepStatus.VERIFICATION_FAILED
            step.message = f"{step.message} | verification failed: {'; '.join(problems)}"
            result.failures.append(f"modification verification: {mod.id}: {'; '.join(problems)}")
        elif step.verified is None:
            result.warnings.append(
                f"{mod.id} has no verification; its modification is reported as not verified"
            )

    # -- output -------------------------------------------------------------

    @staticmethod
    def _export(apk: Path, built: Path, dest: Path, result: PipelineResult) -> None:
        dest = dest.expanduser().resolve()
        if dest == apk:
            result.failures.append("output: refusing to overwrite the original APK")
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(built, dest)
        result.output_apk = str(dest)

    @staticmethod
    def _final_status(runs: list[ModifierRun], skipped: list[ModifierRun]) -> PipelineStatus:
        if skipped:
            return PipelineStatus.PARTIAL
        if any(r.step.executed and r.step.verified is None for r in runs):
            return PipelineStatus.UNVERIFIED
        return PipelineStatus.VERIFIED


def _modification_row(runs: list[ModifierRun]) -> VerificationCheck:
    executed = [r for r in runs if r.step.executed]
    states = {r.info.id: r.verification_state for r in runs}
    ev = [f"{k}: {v}" for k, v in states.items()]
    if not executed:
        return VerificationCheck(name="modification", status=CheckStatus.UNDETERMINED,
                                 summary="no modifier executed", evidence=ev)  # fmt: skip
    if any(r.step.verified is False for r in executed):
        status, summary = CheckStatus.FAILED, "a modifier's verification failed"
    elif any(r.step.verified is None for r in executed):
        status, summary = CheckStatus.UNDETERMINED, "a modifier has no verification"
    else:
        status, summary = CheckStatus.PASSED, f"{len(executed)} modifier(s) verified"
    return VerificationCheck(name="modification", status=status, summary=summary, evidence=ev)


def measure_noise_floor(
    service: BuildService,
    apk: Path,
    *,
    work_dir: Path,
    diff_engine: DiffEngine | None = None,
) -> NoopSemanticBaseline:
    """Measure *apk*'s rebuild noise with one unmodified BuildService round trip.

    Returns a one-entry semantic no-op baseline for :meth:`ModificationPipeline.run`.
    Only an ``EQUIVALENT`` or ``EQUIVALENT_WITH_RESIDUE`` entry establishes a noise
    floor; any other result makes the modification run fail truthfully.
    """
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline, run_semantic_noop

    entry = run_semantic_noop(
        service, Path(apk), entry_id=Path(apk).name, work_dir=work_dir, diff_engine=diff_engine
    )
    identity = current_toolchain_identity(service)
    return NoopSemanticBaseline(
        name="Measured semantic no-op baseline (single APK)",
        toolchain={"versions": identity.model_dump() if identity else None},
        toolchain_identity=identity,
        entries=[entry],
    )


def _prune_empty_parents(directory: Path, root: Path) -> None:
    while directory != root and directory.is_relative_to(root):
        try:
            directory.rmdir()  # only succeeds when empty
        except OSError:
            return
        directory = directory.parent


def _source_check(
    plan: ModifierPlan,
    project: ProjectContext,
    before: dict[str, str],
    manifest_before: bytes | None,
) -> SourceCheck:
    """Compare what changed in the decoded project with what the plan declared."""
    after = _snapshot(project.decoded_dir)
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    modified = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
    actual: dict[str, FileAction] = {
        **dict.fromkeys(added, FileAction.ADD),
        **dict.fromkeys(removed, FileAction.REMOVE),
        **dict.fromkeys(modified, FileAction.MODIFY),
    }
    planned = {fc.path: fc.action for fc in plan.file_changes}
    unplanned = sorted(p for p, a in actual.items() if planned.get(p) != a)
    missing = sorted(p for p, a in planned.items() if actual.get(p) != a)
    check = SourceCheck(
        passed=False,
        added=added,
        modified=modified,
        removed=removed,
        unplanned=unplanned,
        missing=missing,
    )
    if unplanned:
        check.problems.append(f"unplanned file change(s): {', '.join(unplanned)}")
    if missing:
        check.problems.append(f"planned file change(s) not made: {', '.join(missing)}")
    links = sorted(p for p, h in after.items() if h == _SYMLINK and before.get(p) != _SYMLINK)
    if links:
        check.problems.append(f"symlink(s) created: {', '.join(links)}")

    if MANIFEST in modified or plan.manifest_edits:
        try:
            edits = manifest_edits(
                (manifest_before or b"").decode("utf-8"), project.manifest_text()
            )
        except Exception as exc:  # malformed XML written by the modifier
            check.manifest_matches_plan = False
            check.problems.append(f"manifest cannot be compared: {type(exc).__name__}: {exc}")
        else:
            check.manifest_edits = edits
            check.manifest_matches_plan = same_edits(edits, plan.manifest_edits)
            if not check.manifest_matches_plan:
                check.problems.append("manifest edits differ from the planned edits")
    check.passed = not check.problems
    return check
