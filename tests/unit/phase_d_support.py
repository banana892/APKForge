"""Test doubles for the Phase D pipeline: a BuildService that produces real ZIPs and a
modifier whose behaviour is chosen per instance."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.diff.expectations import ExpectedChange
from apkforge.diff.models import ChangeType, DiffResult, FileDiff, FileEntryDiff
from apkforge.modification.contract import (
    APKModifier,
    ApplyOutcome,
    FileAction,
    ModifierPlan,
    PlannedFileChange,
    PlanTarget,
    Precondition,
    ProjectContext,
    TargetAccess,
    VerificationEvidence,
    VerificationOutcome,
)
from tests.unit.test_c5_boot_receiver import manifest
from tests.unit.test_c5_controlled import FakeDiff, FakeService
from tests.unit.test_c5_expectations import _diff, _rebuild_noise_files, noise_baseline

if TYPE_CHECKING:
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.builders.workspace import BuildWorkspace

__all__ = [
    "FakeDiff",
    "Scripted",
    "Unverified",
    "ZipService",
    "baseline_for",
    "diff_adding",
    "scripted_path",
    "sha",
]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def baseline_for(apk: Path) -> NoopSemanticBaseline:
    return noise_baseline(sha(apk))


class ZipService(FakeService):
    """FakeService whose decode writes an Apktool-like project and whose build zips it."""

    def __init__(self, decoded_manifest: str | None = None, **kw: Any) -> None:
        super().__init__(decoded_manifest or manifest(), **kw)
        self.toolchain_valid = True

    def check_toolchain(self, *, refresh: bool = False) -> Any:
        check = super().check_toolchain(refresh=refresh)
        check.valid = self.toolchain_valid
        return check

    def decode(self, apk: Path, ws: BuildWorkspace, **kw: Any) -> Any:
        sr = super().decode(apk, ws, **kw)
        (ws.decoded_dir / "apktool.yml").write_text("version: simulated\n")
        return sr

    def build(self, project: Path, out: Path, **kw: Any) -> Any:
        sr = super().build(project, out, **kw)
        if sr.passed:
            with zipfile.ZipFile(out, "w") as z:
                for p in sorted(Path(project).rglob("*")):
                    if p.is_file():
                        z.write(p, p.relative_to(project).as_posix())
        return sr


def scripted_path(modifier_id: str, suffix: str = "") -> str:
    return f"assets/scripted/{modifier_id}{suffix}.txt"


def diff_adding(*paths: str, extra: list[FileEntryDiff] | None = None) -> DiffResult:
    """Rebuild noise plus one ``file added`` per scripted path (content = id line)."""
    entries = _rebuild_noise_files()
    for p in paths:
        size = len(_content(Path(p).stem))
        entries.append(
            FileEntryDiff(path=p, change_type=ChangeType.ADDED, category="asset", size_after=size)
        )
    return _diff(files=FileDiff(entries=[*entries, *(extra or [])]))


def _content(modifier_id: str) -> bytes:
    return f"{modifier_id}\n".encode()


class Scripted(APKModifier):
    """Adds ``assets/scripted/<id>.txt``; *behaviour* selects how it misbehaves.

    ok, skip, plan_raise, plan_writes, apply_fail, apply_raise, partial_raise, unplanned,
    modify_unplanned, tamper, verify_fail, verify_raise, replan:<path>, no_expectation
    """

    id: ClassVar[str] = "scripted"
    name: ClassVar[str] = "Scripted"
    description: ClassVar[str] = "Test double"
    parameters: ClassVar[dict[str, str]] = {"note": "free text"}

    def __init__(
        self,
        modifier_id: str,
        behaviour: str = "ok",
        *,
        target: PlanTarget | None = None,
        path: str | None = None,
    ) -> None:
        self.id = modifier_id  # type: ignore[misc]
        self.behaviour = behaviour
        self.target = target
        self.fixed_path = path
        self.calls: list[str] = []

    def _path(self, project: ProjectContext) -> str:
        if self.fixed_path:
            return self.fixed_path
        if self.behaviour.startswith("replan:"):
            other = self.behaviour.split(":", 1)[1]
            return scripted_path(self.id, "-after" if project.path(other).exists() else "")
        return scripted_path(self.id)

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        self.calls.append("inspect")
        return {"marker": project.path(self._path(project)).exists()}

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        self.calls.append("plan")
        if self.behaviour == "plan_raise":
            raise RuntimeError("simulated planning crash")
        if self.behaviour == "plan_writes":
            project.path("assets/planning-leak.txt").parent.mkdir(parents=True, exist_ok=True)
            project.path("assets/planning-leak.txt").write_text("x")
        plan = self.new_plan(project, parameters)
        path = self._path(project)
        if self.behaviour == "skip":
            plan.require(
                "scripted_condition",
                False,
                expected="condition present",
                actual="absent",
                reason="simulated missing target",
            )
            plan.refusal_code = "target_missing"
            return plan
        plan.require("marker_absent", not findings["marker"], expected="absent", actual="absent")
        plan.targets = [
            self.target or PlanTarget(kind="file", identifier=path, access=TargetAccess.ADD)
        ]
        plan.changes = [f"add {path}"]
        plan.file_changes = [PlannedFileChange(path=path, action=FileAction.ADD)]
        if self.behaviour != "no_expectation":
            plan.expected_changes = [
                ExpectedChange(
                    category="file",
                    kind="added",
                    identifier=path,
                    detail={"file_category": "asset", "size": len(_content(self.id))},
                )
            ]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        self.calls.append("apply")
        b = self.behaviour
        if b == "apply_fail":
            return ApplyOutcome(applied=False, errors=["simulated apply failure"])
        if b == "apply_raise":
            raise RuntimeError("simulated apply crash")
        target = project.path(plan.file_changes[0].path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_content(self.id))
        if b == "partial_raise":
            raise RuntimeError("simulated crash after writing")
        if b == "unplanned":
            project.path("assets/scripted/extra.txt").write_text("unplanned")
        if b == "modify_unplanned":
            project.manifest_path.write_text(project.manifest_text() + "<!-- edited -->\n")
        if b == "tamper":
            with project.original_apk.open("ab") as f:
                f.write(b"tampered")
        return ApplyOutcome(applied=True, message=f"added {plan.file_changes[0].path}")

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        self.calls.append("verify")
        if self.behaviour == "verify_raise":
            raise RuntimeError("simulated verify crash")
        path = plan.file_changes[0].path
        with zipfile.ZipFile(evidence.output_apk) as z:
            present = path in z.namelist()
        ok = present and self.behaviour != "verify_fail"
        return VerificationOutcome.from_checks(
            [Precondition(name="present", satisfied=ok, expected="present", actual=str(present))]
        )


class Unverified(Scripted):
    """Same as Scripted, without a verification implementation."""

    verify = APKModifier.verify  # type: ignore[assignment]
