"""H-TRANS-001 executor: a Phase D modifier bound to one validated H.2 plan.

The modifier is constructed by the H.3 executor *after* the plan passed every integrity
and eligibility check, and is never registered in the default modifier catalog, so it
cannot be requested through ``apkforge modify`` (which would bypass H.2).

Within the :class:`~apkforge.modification.pipeline.ModificationPipeline` contract it:

- ``plan``: re-checks the plan's target against the decoded workspace (defined exactly
  once, in the planned file, census matching the analysed APK) and declares the single
  file removal plus every semantic change Phase E is expected to observe;
- ``apply``: removes exactly that smali file and validates, before anything is built,
  that exactly the target class disappeared and nothing else changed;
- ``verify``: checks the rebuilt APK's DEX diff (one class removed, nothing else).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.diff.expectations import ExpectedChange
from apkforge.diff.strings import _SAMPLE_LIMIT
from apkforge.modification.contract import (
    APKModifier,
    ApplyOutcome,
    FileAction,
    PlannedFileChange,
    PlanTarget,
    Precondition,
    TargetAccess,
    VerificationOutcome,
)
from apkforge.modification.models import ModificationRisk
from apkforge.transformation.application import ApplicationReason, MutationRecord
from apkforge.transformation.dexstate import ClassCensus, pool_tokens, take_census

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.modification.contract import ModifierPlan, ProjectContext, VerificationEvidence
    from apkforge.transformation.models import TransformationPlan

__all__ = ["H3_MODIFIER_ID", "RemoveIsolatedClassModifier"]

H3_MODIFIER_ID = "h3.remove_isolated_class"
_R = ApplicationReason


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RemoveIsolatedClassModifier(APKModifier):
    """Removes the one class named by a validated ``H-TRANS-001`` plan."""

    id: ClassVar[str] = H3_MODIFIER_ID
    name: ClassVar[str] = "Remove isolated class (H-TRANS-001, H.3)"
    description: ClassVar[str] = (
        "Removes exactly the class definition named by a validated, ELIGIBLE H.2 plan."
    )
    risk: ClassVar[ModificationRisk] = ModificationRisk.HIGH

    def __init__(
        self,
        plan: TransformationPlan,
        *,
        defined_classes: int,
        string_pool: set[str],
        api_removed: set[str],
    ) -> None:
        """
        Args:
            plan: the validated H.2 plan.
            defined_classes: class count of the H.1 analysis the plan was checked against.
            string_pool: the original APK's DEX string pool as Phase E enumerates it.
            api_removed: framework API references used only by the target class.
        """
        change = plan.planned_changes[0]
        self.target = plan.target.class_name
        self.target_file = change.artifact or ""
        self.target_dex = change.details.get("dex", "classes.dex")
        self.transformation_id = plan.transformation_id
        self.defined_classes = defined_classes
        self.string_pool = string_pool
        self.api_removed = api_removed
        self.mutation: MutationRecord | None = None

    # -- plan -------------------------------------------------------------------

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        census = take_census(project.decoded_dir)
        return {
            "classes": census.count,
            "unparsed_files": census.unparsed,
            "target_files": census.classes.get(self.target, []),
        }

    def _refuse(self, plan: ModifierPlan, code: ApplicationReason) -> ModifierPlan:
        plan.refusal_code = code.value
        return plan

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        census = take_census(project.decoded_dir)
        files = census.classes.get(self.target, [])
        if not plan.require(
            "decoded_project_readable",
            not census.unparsed,
            expected="every smali file has a .class directive",
            actual=f"{len(census.unparsed)} unreadable",
            reason=f"smali file(s) without a readable .class directive: {census.unparsed[:5]}",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)
        if not plan.require(
            "target_exists",
            bool(files),
            expected=f"{self.target} defined",
            actual="not defined",
            reason=f"{self.target} is not defined in the decoded workspace",
        ):
            return self._refuse(plan, _R.TARGET_NOT_FOUND)
        if not plan.require(
            "target_unambiguous",
            len(files) == 1,
            expected="exactly one definition",
            actual=f"{len(files)} definitions ({', '.join(files)})",
        ):
            return self._refuse(plan, _R.TARGET_AMBIGUOUS)
        if not plan.require(
            "target_identity",
            files[0] == self.target_file and census.dex_of[files[0]] == self.target_dex,
            expected=f"{self.target_file} ({self.target_dex})",
            actual=f"{files[0]} ({census.dex_of[files[0]]})",
            reason="the target is not defined where the plan recorded it",
        ):
            return self._refuse(plan, _R.TARGET_STATE_MISMATCH)
        if not plan.require(
            "workspace_matches_analysis",
            census.count == self.defined_classes,
            expected=f"{self.defined_classes} class definitions (H.1 analysis)",
            actual=f"{census.count}",
            reason="the decoded workspace does not correspond to the analysed APK",
        ):
            return self._refuse(plan, _R.TARGET_STATE_MISMATCH)
        if not plan.require(
            "dex_file_kept",
            census.classes_in(self.target_dex) > 1,
            expected=f"{self.target_dex} keeps at least one class",
            actual=f"{census.classes_in(self.target_dex)} class(es) in {self.target_dex}",
            reason="removing the only class of a DEX file would remove the DEX file",
        ):
            return self._refuse(plan, _R.TRANSFORMATION_PRECONDITION_FAILED)

        strings = self._strings_removed(project.decoded_dir, census)
        if not plan.require(
            "string_changes_enumerable",
            len(strings) <= _SAMPLE_LIMIT,
            expected=f"at most {_SAMPLE_LIMIT} string-pool removals (Phase E enumeration)",
            actual=str(len(strings)),
            reason="Phase E cannot enumerate every string removal; the change could not "
            "be verified",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)

        target_path = project.path(self.target_file)
        plan.targets = [
            PlanTarget(kind="dex_class", identifier=self.target, access=TargetAccess.REMOVE)
        ]
        plan.changes = [f"remove class {self.target} ({self.target_file})"]
        plan.file_changes = [PlannedFileChange(path=self.target_file, action=FileAction.REMOVE)]
        plan.expected_changes = [
            ExpectedChange(
                category="dex_class",
                kind="removed",
                identifier=self.target,
                description=f"{self.target} is no longer defined (the planned change)",
            ),
            *(
                ExpectedChange(
                    category="dex_string",
                    kind="removed",
                    identifier=s,
                    description=f"string-pool entry used only by {self.target}",
                )
                for s in sorted(strings)
            ),
            *(
                ExpectedChange(
                    category="dex_api_reference",
                    kind="removed",
                    identifier=a,
                    description=f"framework API referenced only by {self.target}",
                )
                for a in sorted(self.api_removed)
            ),
        ]
        plan.verification = [
            f"{self.target} absent from the rebuilt DEX; no class added, modified or removed "
            "besides it; no DEX file added or removed"
        ]
        plan.details = {
            "transformation_id": self.transformation_id,
            "target_file": self.target_file,
            "target_dex": self.target_dex,
            "target_sha256": _sha256(target_path),
            "census_sha256": census.digest(),
            "classes": census.count,
        }
        return plan

    def _strings_removed(self, root: Path, census: ClassCensus) -> set[str]:
        """Pool strings the target contributes that no remaining class contributes."""
        target_tokens = pool_tokens((root / self.target_file).read_text(encoding="utf-8"))
        others: set[str] = set()
        for paths in census.classes.values():
            for rel in paths:
                if rel != self.target_file:
                    others |= pool_tokens((root / rel).read_text(encoding="utf-8"), generous=True)
        return (target_tokens & self.string_pool) - others

    # -- apply ------------------------------------------------------------------

    def _remove(self, path: Path) -> None:
        """The mutation itself (one hook, so a test can simulate a faulty mutation)."""
        path.unlink()

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        details = plan.details
        path = project.path(self.target_file)
        before = take_census(project.decoded_dir)
        if (
            before.classes.get(self.target) != [self.target_file]
            or before.digest() != details["census_sha256"]
            or _sha256(path) != details["target_sha256"]
        ):
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.TARGET_STATE_MISMATCH}: target state changed since planning"],
                details={"reason": _R.TARGET_STATE_MISMATCH.value},
            )
        pre_sha = _sha256(path)
        self._remove(path)
        after = take_census(project.decoded_dir)
        removed = sorted(set(before.classes) - set(after.classes))
        added = sorted(set(after.classes) - set(before.classes))
        changed_paths = sorted(
            n
            for n in set(before.classes) & set(after.classes)
            if before.classes[n] != after.classes[n]
        )
        record = MutationRecord(
            transformation_id=self.transformation_id,
            target=self.target,
            target_file=self.target_file,
            target_dex=self.target_dex,
            count=len(removed),
            pre_transform_sha256=pre_sha,
            post_transform_sha256=_sha256(path) if path.exists() else None,
            classes_before=before.count,
            classes_after=after.count,
            removed_classes=removed,
            added_classes=added,
            census_before_sha256=before.digest(),
            census_after_sha256=after.digest(),
        )
        self.mutation = record
        problems: list[str] = []
        if path.exists() or self.target in after.classes:
            problems.append(f"{self.target} is still defined after the mutation")
        if removed != [self.target]:
            problems.append(f"expected exactly [{self.target}] removed, observed {removed}")
        if added or changed_paths or after.unparsed != before.unparsed:
            problems.append(f"classes added/moved: {added + changed_paths}")
        if after.count != before.count - 1:
            problems.append(f"class count {before.count} -> {after.count} (expected -1)")
        if problems:
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.UNEXPECTED_MUTATION}: " + "; ".join(problems)],
                details={"reason": _R.UNEXPECTED_MUTATION.value, "mutation": record.model_dump()},
            )
        return ApplyOutcome(
            applied=True,
            message=f"removed class {self.target} ({self.target_file})",
            details={"mutation": record.model_dump()},
        )

    # -- verify -----------------------------------------------------------------

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        d = evidence.diff.dex
        checks = [
            Precondition(
                name="target_class_removed",
                satisfied=d.classes_removed == [self.target],
                expected=f"[{self.target}]",
                actual=str(d.classes_removed),
            ),
            Precondition(
                name="no_class_added",
                satisfied=not d.classes_added,
                expected="[]",
                actual=str(d.classes_added),
            ),
            Precondition(
                name="no_class_modified",
                satisfied=not d.classes_modified,
                expected="[]",
                actual=str([c.class_name for c in d.classes_modified]),
            ),
            Precondition(
                name="dex_files_unchanged",
                satisfied=not d.dex_files_added and not d.dex_files_removed,
                expected="no DEX file added or removed",
                actual=f"added {d.dex_files_added}, removed {d.dex_files_removed}",
            ),
        ]
        return VerificationOutcome.from_checks(checks)
