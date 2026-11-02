"""Phase H.9 - sequential ModKit chains.

A chain runs ModKit operations in a fixed, user-declared order: each step is an ordinary,
fully isolated :meth:`ModKitManager.execute` (own workspace, staging, validation and
provenance) whose *validated* output becomes the next step's input. The framework adds no
trust: a step only ever sees an APK the previous step's independent validation accepted.

- The chain stops at the first step that does not succeed; nothing is published then.
- A ``NO_OP`` step (only allowed with ``allow_noop``) passes its input through unchanged.
- Intermediate APKs live in a chain directory under the workspace base, never in the
  output directory; only the final APK is published there (same no-overwrite rule).
  Step workspaces follow the normal retention rules and ``chain-result.json`` is always
  written there; intermediate APKs are deleted after a successful chain unless kept.
- With ``check_conflicts``, each changing step is diffed (input -> output) and
  repeated changes across steps are reported (H.10, :mod:`apkforge.modkit.conflicts`).
  Conflicts never change the chain's status.

Pipeline file (TOML, or JSON with the same shape)::

    [[steps]]
    modkit = "morphe"
    operation = "patch"
    timeout_seconds = 600          # optional
    allow_noop = false             # optional
    [steps.parameters]
    patches = "/path/patches.mpp"
    enable = "Clone app"
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import Field, ValidationError

from apkforge.core.models import AnalysisStatus
from apkforge.modkit.conflicts import ChainConflict, ConflictStatus, find_conflicts
from apkforge.modkit.executor import ModKitExecutor
from apkforge.modkit.models import (
    SCHEMA_VERSION,
    ArtifactRecord,
    ExecutionRequest,
    FailureCategory,
    ModKitExecutionResult,
    ModKitResultStatus,
    _Frozen,
)
from apkforge.modkit.workspace import new_execution_id, sha256_file

if TYPE_CHECKING:
    from apkforge.diff.engine import DiffEngine
    from apkforge.modkit.manager import ModKitManager

__all__ = [
    "ChainSpec",
    "ChainStep",
    "ModKitChainResult",
    "ModKitChainRunner",
    "load_chain_spec",
]

R = ModKitResultStatus
#: Hard cap: each step is a full isolated execution (and a full APK copy on disk).
MAX_CHAIN_STEPS = 32


class ChainStep(_Frozen):
    modkit: str
    operation: str
    parameters: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int | None = Field(default=None, ge=1, le=86_400)
    allow_noop: bool = False


class ChainSpec(_Frozen):
    steps: tuple[ChainStep, ...] = Field(min_length=1, max_length=MAX_CHAIN_STEPS)


def load_chain_spec(path: Path) -> ChainSpec:
    """Parse a pipeline file (``.json`` is JSON, anything else TOML).

    Raises ``ValueError`` with a readable message on any problem."""
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
        return ChainSpec.model_validate(data)
    except (OSError, UnicodeDecodeError, ValueError, ValidationError) as exc:
        # ValidationError/JSONDecodeError/TOMLDecodeError are all ValueErrors
        raise ValueError(f"invalid pipeline {path}: {exc}") from exc


class ModKitChainResult(_Frozen):
    schema_version: int = SCHEMA_VERSION
    chain_id: str
    #: SUCCESS / NO_OP (every step was a no-op), otherwise the failing step's status.
    status: ModKitResultStatus
    failure: FailureCategory | None = None
    reason: str = ""
    original: ArtifactRecord | None = None
    published: ArtifactRecord | None = None
    #: One result per step that was attempted, in order.
    steps: tuple[ModKitExecutionResult, ...] = ()
    #: Index of the step that stopped the chain, if any.
    failed_step: int | None = None
    original_unchanged: bool | None = None
    chain_dir: str | None = None
    intermediates_retained: bool = False
    #: H.10: reported only; never changes ``status``.
    conflict_status: ConflictStatus = ConflictStatus.NOT_CHECKED
    conflicts: tuple[ChainConflict, ...] = ()
    #: Steps whose diff was not COMPLETE (their conflicts may be missing).
    conflict_gaps: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status in (R.SUCCESS, R.NO_OP)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent, sort_keys=False)


class ModKitChainRunner:
    def __init__(self, manager: ModKitManager, *, diff_engine: DiffEngine | None = None) -> None:
        self.manager = manager
        self._engine = diff_engine

    def _conflicts(self, results: list[ModKitExecutionResult]) -> dict[str, Any]:
        from apkforge.diff.expectations import observe

        if self._engine is None:
            from apkforge.diff.engine import DiffEngine

            self._engine = DiffEngine()
        changes, gaps = [], []
        for i, res in enumerate(results):
            if res.published is None or res.original is None:
                continue  # NO_OP step: changed nothing
            diff = self._engine.diff(Path(res.original.path), Path(res.published.path))
            if diff.status != AnalysisStatus.COMPLETE:
                why = "; ".join([*diff.errors, *diff.warnings][:2])
                gaps.append(f"step {i}: diff {diff.status}" + (f" ({why})" if why else ""))
            changes.append((i, observe(diff)))
        conflicts = find_conflicts(changes)
        if gaps:
            status = ConflictStatus.INCOMPLETE
        elif any(not c.container for c in conflicts):
            status = ConflictStatus.CONFLICTS
        else:
            status = ConflictStatus.CONTAINER_ONLY if conflicts else ConflictStatus.NONE
        return {"conflict_status": status, "conflicts": tuple(conflicts),
                "conflict_gaps": tuple(gaps)}  # fmt: skip

    def run(
        self,
        spec: ChainSpec,
        input_apk: Path,
        output_dir: Path,
        *,
        output_name: str | None = None,
        workspace_base: Path | None = None,
        keep_workspace: bool = False,
        check_conflicts: bool = False,
    ) -> ModKitChainResult:
        chain_id = new_execution_id().replace("mk-", "chain-", 1)
        original = input_apk.resolve()

        def fail(reason: str, failure: FailureCategory = FailureCategory.INVALID_REQUEST,
                 status: ModKitResultStatus = R.INVALID_INPUT) -> ModKitChainResult:  # fmt: skip
            return ModKitChainResult(chain_id=chain_id, status=status, failure=failure,
                                     reason=reason)  # fmt: skip

        # Pre-flight every step before running any, so a typo in step 3 doesn't cost
        # two full third-party executions first.
        for i, step in enumerate(spec.steps):
            adapter = self.manager.get(step.modkit)
            if adapter is None:
                info = self.manager.info(step.modkit)
                why = info.availability.reason if info else f"unknown ModKit {step.modkit!r}"
                return fail(f"step {i} ({step.modkit}): {why}", FailureCategory.NOT_AVAILABLE,
                            R.NOT_AVAILABLE)  # fmt: skip
            if step.operation not in {o.id for o in adapter.operations()}:
                return fail(f"step {i} ({step.modkit}): unknown operation {step.operation!r}")
        if not original.is_file():
            return fail(f"input {original} is not a regular file", FailureCategory.INVALID_INPUT)
        name = output_name or f"{original.stem}.chain.apk"
        destination = output_dir.resolve() / name
        if destination.exists() or destination.is_symlink():
            return fail(f"refusing to overwrite existing {destination}")
        if destination == original:
            return fail("the output would replace the input")

        orig_sha = sha256_file(original)
        orig_rec = ArtifactRecord(role="original", path=str(original), sha256=orig_sha,
                                  size=original.stat().st_size)  # fmt: skip
        base = workspace_base or self.manager.executor.settings.base_directory / "modkits"
        chain_dir = base / chain_id
        chain_dir.mkdir(parents=True, exist_ok=False)

        current = original
        results: list[ModKitExecutionResult] = []
        status, failure, reason, failed_step = R.NO_OP, None, "every step was a no-op", None
        for i, step in enumerate(spec.steps):
            request = ExecutionRequest(
                input_apk=current,
                output_dir=chain_dir,
                operation=step.operation,
                parameters=step.parameters,
                timeout_seconds=step.timeout_seconds,
                expect_change=not step.allow_noop,
                workspace_base=chain_dir / "workspaces",
                keep_workspace=keep_workspace,
                output_name=f"step-{i}.apk",
            )
            res = self.manager.execute(step.modkit, request)
            results.append(res)
            if not res.succeeded:
                status, failure, failed_step = res.status, res.failure, i
                reason = f"step {i} ({step.modkit}/{step.operation}) {res.status}: {res.reason}"
                break
            if res.published is not None:
                current = Path(res.published.path)
                status, reason = R.SUCCESS, f"{len(spec.steps)} step(s) completed"

        published = None
        if status is R.SUCCESS:
            try:
                published = ModKitExecutor._publish(current, sha256_file(current), destination)
            except OSError as exc:
                status, failure = R.OUTPUT_INVALID, FailureCategory.PUBLISH_FAILED
                reason = f"publishing the final output failed: {exc}"
        unchanged = sha256_file(original) == orig_sha
        if not unchanged:
            status, failure = R.EXECUTION_FAILED, FailureCategory.ORIGINAL_MUTATED
            reason = "the original APK changed during the chain"
        # Needs the intermediates, so before they are deleted.
        conflict_fields = self._conflicts(results) if check_conflicts and published else {}
        # Intermediate APKs are only evidence for a failed chain or an explicit keep.
        retained = keep_workspace or status not in (R.SUCCESS, R.NO_OP)
        if not retained:
            for step_apk in chain_dir.glob("step-*.apk"):
                step_apk.unlink(missing_ok=True)
        result = ModKitChainResult(
            chain_id=chain_id,
            status=status,
            failure=failure,
            reason=reason,
            original=orig_rec,
            published=published,
            steps=tuple(results),
            failed_step=failed_step,
            original_unchanged=unchanged,
            chain_dir=str(chain_dir),
            intermediates_retained=retained,
            **conflict_fields,
        )
        (chain_dir / "chain-result.json").write_text(result.to_json() + "\n", encoding="utf-8")
        return result
