"""Status semantics of the legacy ModificationFramework (known-limitations §17).

A skipped step must never be reported as a successful modification.  These tests
drive ``ModificationFramework.execute`` with a scripted modifier whose behaviour is
selected by the change target, so every status path is deterministic and no APK is
rebuilt.  ``test_disable_missing_component_is_not_success`` reproduces §17 with the
real ``ComponentModifier``.
"""

from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest
from rich.console import Console

from apkforge.modification.framework import ModificationFramework
from apkforge.modification.models import (
    ChangeStatus,
    ChangeType,
    ModificationPlan,
    PlannedChange,
    PlanStatus,
)
from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationResult,
    ModificationStepResult,
    StepStatus,
)
from apkforge.modification.modifiers.registry import ModifierRegistry

# Change types routed to the scripted modifier; one per step so a plan can mix them.
_TYPES = [
    ChangeType.REMOVE_PERMISSION,
    ChangeType.MODIFY_PERMISSION,
    ChangeType.REMOVE_RESOURCE,
    ChangeType.REMOVE_ASSET,
]


class ScriptedModifier:
    """Behaves according to ``change.target``.

    ok           apply writes a marker file; verify passes
    skip         apply finds nothing to change (SKIPPED)
    fail         apply returns FAILED
    raise        apply raises RuntimeError
    verify_fail  apply writes a marker file; verify returns FAILED
    verify_raise apply writes a marker file; verify raises
    tamper       apply appends to the ORIGINAL APK (must be caught)
    """

    modifier_id = "ScriptedModifier"
    name = "Scripted"
    description = "Test double"
    supported_change_types: ClassVar[list[str]] = [t.value for t in _TYPES]

    def __init__(self) -> None:
        self.verify_calls: list[str] = []
        self.rollback_calls: list[str] = []

    def _step(self, change: PlannedChange, status: StepStatus, msg: str) -> ModificationStepResult:
        return ModificationStepResult(
            change_id=change.id, modifier_id=self.modifier_id, status=status, message=msg
        )

    def preflight(
        self, change: PlannedChange, context: ModificationExecutionContext
    ) -> ModificationStepResult:
        return self._step(change, StepStatus.SUCCESS, "preflight ok")

    def apply(
        self, change: PlannedChange, context: ModificationExecutionContext
    ) -> ModificationStepResult:
        behaviour = change.target
        if behaviour == "skip":
            return self._step(change, StepStatus.SKIPPED, "No changes applied: not found")
        if behaviour == "fail":
            return self._step(change, StepStatus.FAILED, "could not write")
        if behaviour == "raise":
            raise RuntimeError("modifier exploded")
        if behaviour == "tamper":
            with open(context.original_apk_path, "ab") as fh:
                fh.write(b"tampered")
        if context.dry_run:
            return self._step(change, StepStatus.DRY_RUN, "would apply")
        (context.workspace_dir / f"{change.id}.marker").write_text(behaviour)
        return self._step(change, StepStatus.SUCCESS, f"applied {change.id}")

    def verify(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        self.verify_calls.append(change.id)
        if change.target == "verify_raise":
            raise ValueError("verifier exploded")
        marker = context.workspace_dir / f"{change.id}.marker"
        ok = change.target != "verify_fail" and marker.is_file()
        return self._step(
            change,
            StepStatus.SUCCESS if ok else StepStatus.FAILED,
            "marker present" if ok else "working copy does not reflect the change",
        )

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        self.rollback_calls.append(change.id)
        (context.workspace_dir / f"{change.id}.marker").unlink(missing_ok=True)
        return self._step(change, StepStatus.ROLLED_BACK, "rolled back")


class UnverifiedModifier(ScriptedModifier):
    """Same as ScriptedModifier but without a verify() method."""

    modifier_id = "UnverifiedModifier"

    verify = None  # type: ignore[assignment]


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    return path


def _plan(apk: Path, *targets: str) -> ModificationPlan:
    return ModificationPlan(
        plan_id="PLAN-STATUS",
        source_apk=str(apk),
        source_sha256=ModificationFramework._compute_sha256(apk),
        created_at="2026-10-03T00:00:00Z",
        status=PlanStatus.APPROVED,
        changes=[
            PlannedChange(
                id=f"C{i + 1}",
                change_type=_TYPES[i],
                target=target,
                status=ChangeStatus.ACCEPTED,
            )
            for i, target in enumerate(targets)
        ],
    )


def _run(
    apk: Path,
    tmp_path: Path,
    *targets: str,
    modifier: ScriptedModifier | None = None,
    dry_run: bool = False,
) -> tuple[ModificationResult, ScriptedModifier]:
    modifier = modifier or ScriptedModifier()
    registry = ModifierRegistry()
    registry.register(modifier)
    framework = ModificationFramework(registry=registry, workspace_base=tmp_path / "ws")
    result = framework.execute(_plan(apk, *targets), apk, dry_run=dry_run)
    return result, modifier


# ---------------------------------------------------------------------------
# Single-step paths
# ---------------------------------------------------------------------------


def test_executed_and_verified_step_is_success(apk: Path, tmp_path: Path) -> None:
    result, mod = _run(apk, tmp_path, "ok")
    (step,) = result.steps
    assert step.status == StepStatus.SUCCESS
    assert step.executed and step.verified is True
    assert mod.verify_calls == ["C1"]
    assert result.status == StepStatus.SUCCESS
    assert (result.planned_steps, result.executed_steps, result.verified_steps) == (1, 1, 1)
    assert result.all_succeeded


def test_skipped_step_is_not_success(apk: Path, tmp_path: Path) -> None:
    """The §17 defect: one skipped step used to aggregate to overall SUCCESS."""
    result, mod = _run(apk, tmp_path, "skip")
    (step,) = result.steps
    assert step.status == StepStatus.SKIPPED
    assert not step.executed and step.verified is None
    assert mod.verify_calls == []
    assert result.status == StepStatus.SKIPPED
    assert result.status != StepStatus.SUCCESS
    assert result.executed_steps == 0 and result.skipped_steps == 1
    assert not result.all_succeeded
    assert any("skipped" in w for w in result.warnings)
    # Nothing was executed, so there is no output to keep.
    assert result.working_copy_path is None
    assert list((tmp_path / "ws").iterdir()) == []


def test_failed_step_is_failure(apk: Path, tmp_path: Path) -> None:
    result, _ = _run(apk, tmp_path, "fail")
    assert result.steps[0].status == StepStatus.FAILED
    assert not result.steps[0].executed
    assert result.status == StepStatus.FAILED
    assert result.failed_steps == 1 and result.executed_steps == 0


def test_verification_failure_is_failure(apk: Path, tmp_path: Path) -> None:
    result, mod = _run(apk, tmp_path, "verify_fail")
    (step,) = result.steps
    assert step.status == StepStatus.VERIFICATION_FAILED
    assert step.executed and step.verified is False
    assert "verification failed" in step.message
    assert result.status == StepStatus.FAILED
    assert (result.failed_steps, result.verification_failed_steps) == (1, 1)
    # The executed-but-unverified change is undone.
    assert mod.rollback_calls == ["C1"] and step.rolled_back


def test_verifier_exception_is_verification_failure(apk: Path, tmp_path: Path) -> None:
    result, _ = _run(apk, tmp_path, "verify_raise")
    (step,) = result.steps
    assert step.status == StepStatus.VERIFICATION_FAILED
    assert "ValueError: verifier exploded" in step.message
    assert result.status == StepStatus.FAILED


def test_exception_during_apply_is_recorded_as_failure(apk: Path, tmp_path: Path) -> None:
    original = apk.read_bytes()
    result, _ = _run(apk, tmp_path, "raise")
    (step,) = result.steps
    assert step.status == StepStatus.FAILED
    assert step.status != StepStatus.SKIPPED
    assert "RuntimeError: modifier exploded" in step.message
    assert step.details["exception_type"] == "RuntimeError"
    assert result.status == StepStatus.FAILED
    assert any("C1" in e for e in result.errors)
    assert apk.read_bytes() == original


def test_executed_but_unverifiable_step(apk: Path, tmp_path: Path) -> None:
    """A modifier without verify(): executed and reported, but never claimed verified."""
    result, _ = _run(apk, tmp_path, "ok", modifier=UnverifiedModifier())
    (step,) = result.steps
    assert step.status == StepStatus.SUCCESS and step.verified is None
    assert result.status == StepStatus.SUCCESS
    assert (result.executed_steps, result.verified_steps) == (1, 0)


def test_modified_original_apk_is_detected(apk: Path, tmp_path: Path) -> None:
    result, _ = _run(apk, tmp_path, "tamper")
    assert result.status == StepStatus.FAILED
    assert any("Original APK was modified" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Multi-step aggregation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("targets", "expected"),
    [
        (("ok", "ok"), "success"),
        (("ok", "skip"), "partial"),
        (("skip", "ok"), "partial"),
        (("ok", "fail"), "failed"),
        (("skip", "skip"), "skipped"),
        (("ok", "verify_fail"), "failed"),
        (("skip", "fail"), "failed"),
        (("ok", "raise"), "failed"),
    ],
)
def test_aggregate_status(
    apk: Path, tmp_path: Path, targets: tuple[str, ...], expected: str
) -> None:
    # Statuses are given as their string values (StepStatus is a StrEnum).
    result, _ = _run(apk, tmp_path, *targets)
    assert result.status == expected
    assert result.status == result.aggregate_status()
    assert result.all_succeeded is (expected == StepStatus.SUCCESS)


def test_partial_counts_and_keeps_output(apk: Path, tmp_path: Path) -> None:
    result, _ = _run(apk, tmp_path, "ok", "skip")
    assert (result.planned_steps, result.executed_steps, result.skipped_steps) == (2, 1, 1)
    assert result.successful_steps == 1
    assert any("1 of 2 change(s) were skipped" in w for w in result.warnings)
    # The executed change is real output: the working copy is kept.
    assert result.working_copy_path is not None
    assert (Path(result.working_copy_path).parent / "C1.marker").is_file()


def test_failure_rolls_back_earlier_steps_and_marks_rest_not_attempted(
    apk: Path, tmp_path: Path
) -> None:
    result, mod = _run(apk, tmp_path, "ok", "fail", "ok")
    assert [s.status for s in result.steps] == [
        StepStatus.SUCCESS,
        StepStatus.FAILED,
        StepStatus.PENDING,
    ]
    assert result.steps[0].rolled_back and mod.rollback_calls == ["C1"]
    assert "Not attempted" in result.steps[2].message
    assert result.status == StepStatus.FAILED
    assert (result.planned_steps, result.not_attempted_steps, result.rolled_back_steps) == (
        3,
        1,
        1,
    )


def test_dry_run_aggregation(apk: Path, tmp_path: Path) -> None:
    result, mod = _run(apk, tmp_path, "ok", dry_run=True)
    assert result.status == StepStatus.DRY_RUN
    assert result.steps[0].verified is None and mod.verify_calls == []
    partial, _ = _run(apk, tmp_path, "ok", "skip", dry_run=True)
    assert partial.status == StepStatus.PARTIAL


def test_no_accepted_changes_is_skipped_not_success(apk: Path, tmp_path: Path) -> None:
    plan = _plan(apk, "ok")
    plan.changes[0].status = ChangeStatus.PROPOSED
    result = ModificationFramework(workspace_base=tmp_path / "ws").execute(plan, apk)
    assert result.status == StepStatus.SKIPPED
    assert result.steps == [] and not result.all_succeeded


# ---------------------------------------------------------------------------
# Result model, reporting and exit codes
# ---------------------------------------------------------------------------


def test_all_succeeded_is_false_for_empty_and_skipped() -> None:
    assert ModificationResult(plan_id="P").all_succeeded is False
    skipped = ModificationResult(
        plan_id="P",
        steps=[ModificationStepResult(change_id="C", modifier_id="M", status=StepStatus.SKIPPED)],
    )
    assert skipped.all_succeeded is False
    assert skipped.aggregate_status() == StepStatus.SKIPPED


def test_result_round_trips_through_json(apk: Path, tmp_path: Path) -> None:
    result, _ = _run(apk, tmp_path, "ok", "verify_fail")
    again = ModificationResult.model_validate_json(result.model_dump_json())
    assert again.status == StepStatus.FAILED
    assert [s.verified for s in again.steps] == [True, False]
    assert [s.rolled_back for s in again.steps] == [True, True]


def test_report_shows_skipped_not_success(
    apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkforge.cli import main as cli

    out = io.StringIO()
    monkeypatch.setattr(cli, "_console", Console(file=out, width=200, color_system=None))
    result, _ = _run(apk, tmp_path, "ok", "skip")
    cli._render_modification_result(result)
    text = out.getvalue()
    assert "Status: PARTIAL" in text
    assert "Executed: 1 (verified: 1)" in text
    assert "Skipped (not executed): 1" in text
    assert "[SKIPPED] C2" in text
    assert "[SUCCESS] C1 (ScriptedModifier) verified" in text


@pytest.mark.parametrize(
    ("status", "code"),
    [
        ("success", 0),
        ("dry_run", 0),
        ("skipped", 3),
        ("partial", 3),
        ("failed", 1),
        ("verification_failed", 1),
        ("pending", 1),
    ],
)
def test_cli_exit_code(status: str, code: int) -> None:
    from apkforge.cli.main import _modification_exit_code

    assert _modification_exit_code(StepStatus(status)) == code


# ---------------------------------------------------------------------------
# Real modifier: the §17 reproduction
# ---------------------------------------------------------------------------


def test_disable_missing_component_is_not_success(apk: Path, tmp_path: Path) -> None:
    """Approved plan to disable a component that does not exist: nothing changes,
    so the run must not report SUCCESS (it used to)."""
    ws = tmp_path / "decoded"
    ws.mkdir()
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example">\n  <application>\n'
        '    <receiver android:name="com.example.Present" android:enabled="true" />\n'
        "  </application>\n</manifest>\n"
    )
    (ws / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    shutil.copy2(apk, ws / apk.name)
    plan = _plan(apk)
    plan.changes.append(
        PlannedChange(
            id="C1",
            change_type=ChangeType.DISABLE_COMPONENT,
            target="com.example.Missing",
            status=ChangeStatus.ACCEPTED,
        )
    )
    result = ModificationFramework().execute(plan, apk, workspace_dir=ws)
    assert result.steps[0].status == StepStatus.SKIPPED
    assert result.status == StepStatus.SKIPPED
    assert (ws / "AndroidManifest.xml").read_text(encoding="utf-8") == manifest
