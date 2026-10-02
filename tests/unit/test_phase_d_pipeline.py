"""Phase D pipeline: status semantics, ordering, conflicts, rollback, safety, build and diff.

A simulated BuildService (real ZIP output, no tools) and DiffEngine; the real-toolchain
runs are in tests/integration/test_phase_d_pipeline.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from apkforge.core.exceptions import InputError, ModificationError
from apkforge.diff.models import ChangeType, FileEntryDiff
from apkforge.modification.builtin import BootReceiverModifier, MarkerAssetModifier
from apkforge.modification.builtin.marker_asset import MARKER_CONTENT
from apkforge.modification.catalog import (
    DuplicateModifierError,
    ModifierCatalog,
    UnknownModifierError,
)
from apkforge.modification.contract import PlanTarget, TargetAccess
from apkforge.modification.modifiers.base import StepStatus
from apkforge.modification.pipeline import (
    ORIGINAL_CHANGED,
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
    PipelineStatus,
)
from tests.fixtures import create_synthetic_apk
from tests.unit.phase_d_support import (
    FakeDiff,
    Scripted,
    Unverified,
    ZipService,
    baseline_for,
    diff_adding,
    scripted_path,
    sha,
)
from tests.unit.test_c5_boot_receiver import PKG


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk", package_name=PKG)


def _run(
    apk: Path,
    tmp_path: Path,
    modifiers: list[Any],
    *,
    service: ZipService | None = None,
    diff: Any = None,
    ids: list[str] | None = None,
    **kw: Any,
) -> tuple[PipelineResult, ZipService]:
    svc = service or ZipService()
    kw.setdefault("noop_baseline", baseline_for(apk))
    executed = [m.id for m in modifiers]
    pipeline = ModificationPipeline(
        svc,  # type: ignore[arg-type]
        ModifierCatalog(modifiers),
        diff_engine=FakeDiff(diff or diff_adding(*(scripted_path(i) for i in executed))),  # type: ignore[arg-type]
    )
    reqs = [ModifierRequest(modifier_id=i) for i in (ids or executed)]
    return pipeline.run(apk, reqs, work_dir=tmp_path / "work", **kw), svc


def _statuses(res: PipelineResult) -> list[StepStatus]:
    return [r.step.status for r in res.modifiers]


def _workspaces(tmp_path: Path) -> list[Path]:
    work = tmp_path / "work"
    return sorted(work.iterdir()) if work.exists() else []


BUILD = ["prepare", "decode", "build", "align", "sign", "verify"]


# ---------------------------------------------------------------------------
# Registration and request validation
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_and_list_sorted(self) -> None:
        cat = ModifierCatalog([Scripted("b"), Scripted("a")])
        assert cat.ids() == ["a", "b"]
        assert [i.id for i in cat.list()] == ["a", "b"]
        assert "a" in cat and "c" not in cat

    def test_duplicate_id_rejected(self) -> None:
        cat = ModifierCatalog([Scripted("a")])
        with pytest.raises(DuplicateModifierError):
            cat.register(Scripted("a"))

    def test_unknown_modifier(self) -> None:
        with pytest.raises(UnknownModifierError, match="nope"):
            ModifierCatalog([Scripted("a")]).get("nope")

    def test_default_catalog(self) -> None:
        from apkforge.modification.catalog import default_catalog

        infos = {i.id: i for i in default_catalog().list()}
        assert set(infos) == {"c5.disable_boot_receiver", "test.marker_asset"}
        assert infos["test.marker_asset"].test_only
        assert all(i.verification_available for i in infos.values())

    def test_verification_availability_derived(self) -> None:
        assert Scripted("a").info().verification_available is True
        assert Unverified("a").info().verification_available is False

    @pytest.mark.parametrize(
        ("reqs", "match"),
        [
            ([], "No modifier"),
            ([ModifierRequest(modifier_id="x")], "Unknown modifier"),
            ([ModifierRequest(modifier_id="a")] * 2, "more than once"),
            ([ModifierRequest(modifier_id="a", parameters={"bogus": "1"})], "bogus"),
        ],
    )
    def test_invalid_requests_raise_before_anything_runs(
        self, apk: Path, tmp_path: Path, reqs: list[ModifierRequest], match: str
    ) -> None:
        svc = ZipService()
        pipeline = ModificationPipeline(svc, ModifierCatalog([Scripted("a")]))  # type: ignore[arg-type]
        with pytest.raises(ModificationError, match=match):
            pipeline.run(apk, reqs, work_dir=tmp_path / "work")
        assert svc.calls == []

    def test_missing_apk(self, tmp_path: Path) -> None:
        pipeline = ModificationPipeline(ZipService(), ModifierCatalog([Scripted("a")]))  # type: ignore[arg-type]
        with pytest.raises(InputError):
            pipeline.run(tmp_path / "missing.apk", [ModifierRequest(modifier_id="a")])

    def test_invalid_apk_is_structured_failure(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.apk"
        bad.write_bytes(b"not a zip")
        res, svc = _run(bad, tmp_path, [Scripted("a")])
        assert res.status == PipelineStatus.FAILED
        assert "invalid APK: not a ZIP archive" in res.failures
        assert svc.calls == [] and _statuses(res) == [StepStatus.PENDING]
        assert res.original_preserved


# ---------------------------------------------------------------------------
# Planning, preconditions, dry run
# ---------------------------------------------------------------------------


class TestPlanning:
    def test_dry_run_plans_without_applying_or_building(self, apk: Path, tmp_path: Path) -> None:
        before = sha(apk)
        m = Scripted("a")
        res, svc = _run(apk, tmp_path, [m], dry_run=True)
        assert res.status == PipelineStatus.DRY_RUN
        assert svc.calls == ["prepare", "decode"]
        assert "apply" not in m.calls
        assert _statuses(res) == [StepStatus.DRY_RUN]
        plan = res.modifiers[0].plan
        assert plan is not None and plan.ready and plan.expected_changes
        assert res.output_apk is None and res.verdict is None
        assert sha(apk) == before and res.original_preserved
        assert res.noise_floor["source"] is None and not res.failures
        assert _workspaces(tmp_path) == []

    def test_failed_precondition_is_skipped_with_reason(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a", "skip")])
        assert res.status == PipelineStatus.SKIPPED
        assert "build" not in svc.calls
        (run,) = res.modifiers
        assert run.step.status == StepStatus.SKIPPED and not run.step.executed
        assert "target_missing" in run.step.message
        (pre,) = [p for p in run.plan.preconditions if not p.satisfied]  # type: ignore[union-attr]
        assert (pre.name, pre.expected, pre.actual, pre.reason) == (
            "scripted_condition",
            "condition present",
            "absent",
            "simulated missing target",
        )
        assert res.counts()["skipped"] == 1 and res.counts()["executed"] == 0

    def test_planning_exception_fails(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a", "plan_raise"), Scripted("b")])
        assert res.status == PipelineStatus.FAILED
        assert _statuses(res) == [StepStatus.FAILED, StepStatus.PENDING]
        assert "RuntimeError" in res.modifiers[0].step.message
        assert "Not attempted: planning failed" in res.modifiers[1].step.message
        assert "build" not in svc.calls

    def test_planning_must_not_write(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "plan_writes")])
        assert res.status == PipelineStatus.FAILED
        assert "planning modified the decoded project" in res.failures

    def test_planning_leaves_original_unchanged(self, apk: Path, tmp_path: Path) -> None:
        before = sha(apk)
        res, _ = _run(apk, tmp_path, [Scripted("a"), Scripted("b")], dry_run=True)
        assert sha(apk) == before == res.original_sha256_after
        assert res.original_checkpoints == ["planning"]


# ---------------------------------------------------------------------------
# Execution and status semantics
# ---------------------------------------------------------------------------


class TestExecution:
    def test_single_success_is_verified(self, apk: Path, tmp_path: Path) -> None:
        out = tmp_path / "out" / "mod.apk"
        m = Scripted("a")
        res, svc = _run(apk, tmp_path, [m], output_apk=out)
        assert res.status == PipelineStatus.VERIFIED, res.failures
        assert svc.calls == BUILD
        (run,) = res.modifiers
        assert run.step.status == StepStatus.SUCCESS and run.step.verified is True
        assert run.verification_state == "verified"
        assert run.step.files_created == [scripted_path("a")]
        assert run.source_check is not None and run.source_check.passed
        assert run.expected_observed and not run.expected_missing
        assert res.build_passed and res.apk_verified and res.modification_verified
        assert res.output_apk == str(out.resolve()) and out.is_file()
        assert res.original_checkpoints == ["planning", "apply a", "build pipeline", "diff"]
        assert _workspaces(tmp_path) == []

    def test_apply_failure(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a", "apply_fail")])
        assert res.status == PipelineStatus.FAILED
        assert "build" not in svc.calls and res.build_passed is None
        assert res.modifiers[0].step.status == StepStatus.FAILED
        assert any(f.startswith("apply: a:") for f in res.failures)

    def test_apply_exception_is_failed_step(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "apply_raise")])
        step = res.modifiers[0].step
        assert res.status == PipelineStatus.FAILED
        assert step.status == StepStatus.FAILED and step.details["exception_type"] == "RuntimeError"

    def test_verification_failure(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "verify_fail")])
        run = res.modifiers[0]
        assert res.status == PipelineStatus.FAILED
        assert run.step.status == StepStatus.VERIFICATION_FAILED and run.step.verified is False
        assert run.step.executed and res.apk_verified is True  # APK fine, modification not
        assert any(f.startswith("modification verification: a:") for f in res.failures)
        assert res.output_apk is None

    def test_verify_exception_is_verification_failure(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "verify_raise")])
        run = res.modifiers[0]
        assert run.step.status == StepStatus.VERIFICATION_FAILED
        assert run.verification is not None and "RuntimeError" in run.verification.message

    def test_modifier_without_verification_is_not_verified(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Unverified("a")])
        run = res.modifiers[0]
        assert res.status == PipelineStatus.UNVERIFIED
        assert run.step.status == StepStatus.SUCCESS and run.step.verified is None
        assert run.verification_state == "not_verified" and run.verification is None
        assert run.expected_observed  # the diff still saw it; that is not modifier verification
        assert not res.modification_verified
        assert res.counts()["not_verified"] == 1 and res.counts()["verified"] == 0
        assert any("not verified" in w for w in res.warnings)

    def test_missing_expected_change_fails_that_modifier(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(
            apk, tmp_path, [Scripted("a"), Scripted("b")], diff=diff_adding(scripted_path("a"))
        )
        assert res.status == PipelineStatus.FAILED
        a, b = res.modifiers
        assert a.step.verified is True
        assert b.step.status == StepStatus.VERIFICATION_FAILED and b.expected_missing
        assert any("expected change not observed" in f for f in res.failures)


# ---------------------------------------------------------------------------
# Multiple modifiers: aggregation, ordering, partial execution
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_two_successes(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a"), Scripted("b")])
        assert res.status == PipelineStatus.VERIFIED
        assert svc.calls.count("build") == 1  # one build for the combined change
        assert res.counts()["verified"] == 2

    def test_success_plus_skipped_refused_by_default(self, apk: Path, tmp_path: Path) -> None:
        a = Scripted("a")
        res, svc = _run(apk, tmp_path, [a, Scripted("b", "skip")])
        assert res.status == PipelineStatus.REFUSED
        assert _statuses(res) == [StepStatus.PENDING, StepStatus.SKIPPED]
        assert "partial execution is not allowed" in res.modifiers[0].step.message
        assert "apply" not in a.calls and "build" not in svc.calls

    def test_success_plus_skipped_partial_when_allowed(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(
            apk,
            tmp_path,
            [Scripted("a"), Scripted("b", "skip")],
            allow_partial=True,
            diff=diff_adding(scripted_path("a")),
        )
        assert res.status == PipelineStatus.PARTIAL
        assert _statuses(res) == [StepStatus.SUCCESS, StepStatus.SKIPPED]
        assert res.modifiers[0].step.verified is True and "build" in svc.calls
        assert res.execution().aggregate_status() == StepStatus.PARTIAL

    def test_dry_run_partial(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(
            apk, tmp_path, [Scripted("a"), Scripted("b", "skip")], allow_partial=True, dry_run=True
        )
        assert res.status == PipelineStatus.PARTIAL
        assert _statuses(res) == [StepStatus.DRY_RUN, StepStatus.SKIPPED]

    def test_skipped_plus_skipped(self, apk: Path, tmp_path: Path) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a", "skip"), Scripted("b", "skip")])
        assert res.status == PipelineStatus.SKIPPED
        assert _statuses(res) == [StepStatus.SKIPPED, StepStatus.SKIPPED]
        assert "build" not in svc.calls

    def test_success_then_failure_rolls_back_and_stops(self, apk: Path, tmp_path: Path) -> None:
        c = Scripted("c")
        res, svc = _run(
            apk,
            tmp_path,
            [Scripted("a"), Scripted("b", "apply_fail"), c],
            keep_workspace=True,
        )
        assert res.status == PipelineStatus.FAILED
        assert _statuses(res) == [StepStatus.SUCCESS, StepStatus.FAILED, StepStatus.PENDING]
        a, _, c_run = res.modifiers
        assert a.step.rolled_back and a.step.verified is None
        assert c_run.step.message == "Not attempted: execution stopped at b"
        assert "apply" not in c.calls and "build" not in svc.calls
        assert res.rollback is not None and res.rollback["restored"] is True
        assert res.rollback["modifiers"] == ["a"]
        decoded = Path(res.workspace or "") / "decoded"
        assert not (decoded / scripted_path("a")).exists()
        counts = res.counts()
        assert (counts["executed"], counts["failed"], counts["not_attempted"]) == (1, 1, 1)
        assert counts["rolled_back"] == 1
        assert res.execution().aggregate_status() == StepStatus.FAILED

    def test_failing_step_with_partial_writes_is_rolled_back(
        self, apk: Path, tmp_path: Path
    ) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "partial_raise")], keep_workspace=True)
        run = res.modifiers[0]
        assert run.step.status == StepStatus.FAILED and run.step.rolled_back
        assert not (Path(res.workspace or "") / "decoded" / scripted_path("a")).exists()

    def test_unplanned_change_fails_source_check_and_is_undone(
        self, apk: Path, tmp_path: Path
    ) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "unplanned")], keep_workspace=True)
        run = res.modifiers[0]
        assert run.step.status == StepStatus.FAILED
        assert run.source_check is not None and run.source_check.unplanned == [
            "assets/scripted/extra.txt"
        ]
        assert run.step.rolled_back and res.rollback and res.rollback["restored"]
        assert not (Path(res.workspace or "") / "decoded" / "assets" / "scripted").exists()

    def test_unrestorable_change_reports_rollback_failure(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a", "modify_unplanned")])
        run = res.modifiers[0]
        assert run.step.status == StepStatus.FAILED
        assert run.step.rolled_back is False  # not claimed: the manifest was not restored
        assert res.rollback is not None and res.rollback["restored"] is False
        assert any(f.startswith("rollback:") for f in res.failures)

    def test_dependent_plan_change_detected_at_apply(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a"), Scripted("b", f"replan:{scripted_path('a')}")])
        assert res.status == PipelineStatus.FAILED
        assert _statuses(res) == [StepStatus.SUCCESS, StepStatus.FAILED]
        assert "Plan changed" in res.modifiers[1].step.message
        assert res.modifiers[0].step.rolled_back


class TestOrdering:
    def test_request_order_is_execution_order(self, apk: Path, tmp_path: Path) -> None:
        mods = [Scripted("b"), Scripted("a"), Scripted("c")]
        res, _ = _run(apk, tmp_path, mods, ids=["c", "a", "b"])
        assert res.order == ["c", "a", "b"]
        assert [r.info.id for r in res.modifiers] == ["c", "a", "b"]
        assert [r.order for r in res.modifiers] == [0, 1, 2]

    def test_order_is_deterministic(self, apk: Path, tmp_path: Path) -> None:
        orders = []
        for i in range(3):
            mods = [Scripted("b"), Scripted("a")]
            res, _ = _run(apk, tmp_path / str(i), mods, ids=["b", "a"])
            orders.append(([r.info.id for r in res.modifiers], [c.subject for c in res.conflicts]))
        assert orders == [orders[0]] * 3 and orders[0][0] == ["b", "a"]


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------


class TestConflicts:
    def test_same_file_conflict_refused_before_execution(self, apk: Path, tmp_path: Path) -> None:
        a, b = Scripted("a", path="assets/x.txt"), Scripted("b", path="assets/x.txt")
        res, svc = _run(apk, tmp_path, [a, b])
        assert res.status == PipelineStatus.REFUSED
        kinds = {c.kind for c in res.conflicts}
        assert {"file", "target", "expected_change"} <= kinds
        assert all(c.modifiers == ["a", "b"] for c in res.conflicts)
        assert "apply" not in a.calls + b.calls and "build" not in svc.calls
        assert _statuses(res) == [StepStatus.PENDING, StepStatus.PENDING]
        assert "conflicting plans" in res.modifiers[0].step.message

    def test_component_modify_vs_remove_conflict(self, apk: Path, tmp_path: Path) -> None:
        rx = "com.example.app.conf.BootReceiver"
        a = Scripted(
            "a", target=PlanTarget(kind="component", identifier=rx, access=TargetAccess.MODIFY)
        )
        b = Scripted(
            "b", target=PlanTarget(kind="component", identifier=rx, access=TargetAccess.REMOVE)
        )
        res, _ = _run(apk, tmp_path, [a, b], dry_run=True)
        assert res.status == PipelineStatus.REFUSED
        (c,) = res.conflicts
        assert (c.kind, c.subject) == ("target", f"component:{rx}")

    def test_read_vs_write_conflict(self, apk: Path, tmp_path: Path) -> None:
        a = Scripted(
            "a", target=PlanTarget(kind="resource", identifier="string/x", access=TargetAccess.READ)
        )
        b = Scripted(
            "b",
            target=PlanTarget(kind="resource", identifier="string/x", access=TargetAccess.MODIFY),
        )
        res, _ = _run(apk, tmp_path, [a, b], dry_run=True)
        assert [c.kind for c in res.conflicts] == ["target"]

    def test_two_readers_do_not_conflict(self, apk: Path, tmp_path: Path) -> None:
        t = PlanTarget(kind="resource", identifier="string/x", access=TargetAccess.READ)
        res, _ = _run(
            apk, tmp_path, [Scripted("a", target=t), Scripted("b", target=t)], dry_run=True
        )
        assert res.status == PipelineStatus.DRY_RUN and not res.conflicts

    def test_c5_and_marker_do_not_conflict(self, apk: Path, tmp_path: Path) -> None:
        mods = [BootReceiverModifier(), MarkerAssetModifier()]
        res, _ = _run(apk, tmp_path, mods, dry_run=True)
        assert res.status == PipelineStatus.DRY_RUN and not res.conflicts


# ---------------------------------------------------------------------------
# Safety, BuildService, diff
# ---------------------------------------------------------------------------


class TestSafety:
    def test_original_changed_during_apply_stops_run(self, apk: Path, tmp_path: Path) -> None:
        b = Scripted("b")
        res, svc = _run(apk, tmp_path, [Scripted("a", "tamper"), b])
        assert res.status == PipelineStatus.FAILED and not res.original_preserved
        assert ORIGINAL_CHANGED in res.failures
        assert any("after apply a" in f for f in res.failures)
        assert "apply" not in b.calls and "build" not in svc.calls
        assert res.modifiers[1].step.status == StepStatus.PENDING

    def test_original_changed_during_build(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a")], service=ZipService(tamper=apk))
        assert res.status == PipelineStatus.FAILED and ORIGINAL_CHANGED in res.failures
        assert res.verdict is None

    def test_output_must_not_be_the_original(self, apk: Path, tmp_path: Path) -> None:
        before = sha(apk)
        res, _ = _run(apk, tmp_path, [Scripted("a")], output_apk=apk)
        assert res.status == PipelineStatus.FAILED
        assert "output: refusing to overwrite the original APK" in res.failures
        assert sha(apk) == before

    def test_exception_in_service_propagates_and_cleans_up(self, apk: Path, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="simulated crash"):
            _run(apk, tmp_path, [Scripted("a")], service=ZipService(raise_in="build"))
        assert _workspaces(tmp_path) == []


class TestBuildIntegration:
    @pytest.mark.parametrize("stage", ["build", "verify"])
    def test_stage_failure_propagates(self, apk: Path, tmp_path: Path, stage: str) -> None:
        res, svc = _run(apk, tmp_path, [Scripted("a")], service=ZipService(fail=stage))
        assert res.status == PipelineStatus.FAILED
        assert any(f.startswith(f"{stage}:") for f in res.failures)
        assert res.verdict is None and res.output_apk is None
        run = res.modifiers[0]
        assert run.step.status == StepStatus.SUCCESS  # applied to the source...
        assert run.step.verified is None  # ...but never verified
        if stage == "build":
            assert res.build_passed is False and res.apk_verified is None
            assert "align" not in svc.calls
        else:
            assert res.build_passed is True and res.apk_verified is False

    def test_missing_noise_floor_fails(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Scripted("a")], noop_baseline=None)
        assert res.status == PipelineStatus.FAILED
        assert "noise floor is not established" in res.failures[0]
        assert res.modifiers[0].step.verified is True  # modification itself was fine


class TestDiff:
    def test_unexpected_change_is_not_success(self, apk: Path, tmp_path: Path) -> None:
        extra = FileEntryDiff(
            path="assets/other.txt", change_type=ChangeType.ADDED, category="asset", size_after=3
        )
        res, _ = _run(
            apk, tmp_path, [Scripted("a")], diff=diff_adding(scripted_path("a"), extra=[extra])
        )
        assert res.status == PipelineStatus.FAILED
        assert res.verdict is not None and not res.verdict.passed
        assert res.verdict.counts["unexpected"] == 1
        assert "semantic: 1 unexpected change(s)" in res.failures
        assert res.output_apk is None

    def test_undeclared_change_is_unexpected(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [Unverified("a", "no_expectation")])
        assert res.status == PipelineStatus.FAILED
        assert res.verdict is not None and res.verdict.counts["unexpected"] == 1


class TestBuiltinModifiers:
    def test_marker_asset_end_to_end(self, apk: Path, tmp_path: Path) -> None:
        path = "assets/apkforge-test/marker.txt"
        entry = FileEntryDiff(
            path=path,
            change_type=ChangeType.ADDED,
            category="asset",
            size_after=len(MARKER_CONTENT),
        )
        res, _ = _run(apk, tmp_path, [MarkerAssetModifier()], diff=diff_adding(extra=[entry]))
        assert res.status == PipelineStatus.VERIFIED, res.failures
        run = res.modifiers[0]
        assert run.verification is not None
        assert [c.name for c in run.verification.checks] == ["marker_present", "marker_content"]

    def test_marker_invalid_name_skipped(self, apk: Path, tmp_path: Path) -> None:
        pipeline = ModificationPipeline(
            ZipService(),  # type: ignore[arg-type]
            ModifierCatalog([MarkerAssetModifier()]),
        )
        res = pipeline.run(
            apk,
            [ModifierRequest(modifier_id="test.marker_asset", parameters={"name": "../x"})],
            work_dir=tmp_path / "work",
            dry_run=True,
        )
        assert res.status == PipelineStatus.SKIPPED
        assert res.modifiers[0].plan is not None
        assert res.modifiers[0].plan.refusal_code == "invalid_parameter"

    def test_boot_receiver_plan_mapping(self, apk: Path, tmp_path: Path) -> None:
        res, _ = _run(apk, tmp_path, [BootReceiverModifier()], dry_run=True)
        plan = res.modifiers[0].plan
        assert plan is not None and plan.ready
        assert [(t.kind, str(t.access)) for t in plan.targets] == [
            ("permission", "remove"),
            ("component", "modify"),
        ]
        assert all(p.expected and p.actual for p in plan.preconditions)
        assert [f.path for f in plan.file_changes] == ["AndroidManifest.xml"]
        assert len(plan.manifest_edits) == 2 and len(plan.expected_changes) == 2
