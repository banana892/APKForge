"""H-TRANS-001/-002/-003 executors: Phase D modifiers bound to one validated H.2 plan.

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

:class:`RemoveIsolatedMethodModifier` (H.5) and :class:`ReplaceCallSiteModifier` (H.6)
follow the same contract for one method declaration / one invocation.
"""

from __future__ import annotations

import hashlib
from collections import Counter
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
from apkforge.reference.models import ReferenceKind
from apkforge.reference.smali import parse_smali
from apkforge.transformation.application import ApplicationReason, MutationRecord
from apkforge.transformation.dexstate import (
    ClassCensus,
    MethodBlock,
    method_census,
    method_key,
    pool_tokens,
    replace_invocation,
    split_method_block,
    take_census,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.modification.contract import ModifierPlan, ProjectContext, VerificationEvidence
    from apkforge.reference.models import Evidence
    from apkforge.transformation.models import TransformationPlan

__all__ = [
    "H3_MODIFIER_ID",
    "H5_MODIFIER_ID",
    "H6_MODIFIER_ID",
    "RemoveIsolatedClassModifier",
    "RemoveIsolatedMethodModifier",
    "ReplaceCallSiteModifier",
    "call_site_expectations",
    "call_site_strings",
    "invocation_diff",
    "method_removal_expectations",
    "removal_expectations",
    "strings_removed",
    "strings_removed_for_method",
]

H3_MODIFIER_ID = "h3.remove_isolated_class"
H5_MODIFIER_ID = "h5.remove_isolated_method"
H6_MODIFIER_ID = "h6.replace_call_site"
_R = ApplicationReason


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strings_removed(
    root: Path, census: ClassCensus, target_file: str, string_pool: set[str]
) -> set[str]:
    """Pool strings the target file contributes that no remaining class contributes.

    Shared by the H.3 modifier (declaration before mutation) and the H.4 verifier
    (independent re-derivation from the original APK).
    """
    target_tokens = pool_tokens((root / target_file).read_text(encoding="utf-8"))
    others: set[str] = set()
    for paths in census.classes.values():
        for rel in paths:
            if rel != target_file:
                others |= pool_tokens((root / rel).read_text(encoding="utf-8"), generous=True)
    return (target_tokens & string_pool) - others


def removal_expectations(
    target: str, strings: set[str], api_removed: set[str]
) -> list[ExpectedChange]:
    """Every Phase E observation removing *target* must produce (and nothing else)."""
    return [
        ExpectedChange(
            category="dex_class",
            kind="removed",
            identifier=target,
            description=f"{target} is no longer defined (the planned change)",
        ),
        *(
            ExpectedChange(
                category="dex_string",
                kind="removed",
                identifier=s,
                description=f"string-pool entry used only by {target}",
            )
            for s in sorted(strings)
        ),
        *(
            ExpectedChange(
                category="dex_api_reference",
                kind="removed",
                identifier=a,
                description=f"framework API referenced only by {target}",
            )
            for a in sorted(api_removed)
        ),
    ]


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

        strings = strings_removed(project.decoded_dir, census, self.target_file, self.string_pool)
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
        plan.expected_changes = removal_expectations(self.target, strings, self.api_removed)
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


def strings_removed_for_method(
    root: Path, census: ClassCensus, target_file: str, block: MethodBlock, string_pool: set[str]
) -> set[str]:
    """Pool strings the target *method block* contributes that nothing that remains does.

    Mirrors :func:`strings_removed` at method granularity: the strings the block uses
    (literals, type descriptors, member names, prototype shorties) minus the strings
    every surviving class *and* every other method of the target class contributes
    (``block.without`` is the target file with the block removed). Shared with the H.4
    verifier, which re-derives it from the original APK.
    """
    target_tokens = pool_tokens(block.text)
    others = pool_tokens(block.without, generous=True)
    for paths in census.classes.values():
        for rel in paths:
            if rel != target_file:
                others |= pool_tokens((root / rel).read_text(encoding="utf-8"), generous=True)
    return (target_tokens & string_pool) - others


def method_removal_expectations(
    class_name: str, key: str, strings: set[str], api_removed: set[str]
) -> list[ExpectedChange]:
    """Every Phase E observation removing the method *key* from *class_name* must produce.

    The containing class is *modified* (one method removed, nothing added or changed), and
    the string-pool entries and framework API references used only by that method
    disappear. Nothing else may change."""
    return [
        ExpectedChange(
            category="dex_class",
            kind="modified",
            identifier=class_name,
            detail={"methods_modified": [], "methods_added": [], "methods_removed": [key]},
            description=f"{class_name} no longer declares {key} (the planned change)",
        ),
        *(
            ExpectedChange(
                category="dex_string",
                kind="removed",
                identifier=s,
                description=f"string-pool entry used only by {class_name}->{key}",
            )
            for s in sorted(strings)
        ),
        *(
            ExpectedChange(
                category="dex_api_reference",
                kind="removed",
                identifier=a,
                description=f"framework API referenced only by {class_name}->{key}",
            )
            for a in sorted(api_removed)
        ),
    ]


class RemoveIsolatedMethodModifier(APKModifier):
    """Removes the one method named by a validated ``H-TRANS-002`` plan (H.5).

    Like :class:`RemoveIsolatedClassModifier`, it is constructed by the executor only
    *after* the plan passed every integrity and eligibility check, and is never
    registered in the default catalog. The containing class is kept: exactly one
    ``.method`` block is removed from one smali file."""

    id: ClassVar[str] = H5_MODIFIER_ID
    name: ClassVar[str] = "Remove isolated method (H-TRANS-002, H.5)"
    description: ClassVar[str] = (
        "Removes exactly the method declaration named by a validated, ELIGIBLE H.2 plan."
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
        change = plan.planned_changes[0]
        assert plan.target.method_name is not None and plan.target.descriptor is not None
        self.target_class = plan.target.class_name
        self.method_name = plan.target.method_name
        self.descriptor = plan.target.descriptor
        self.signature = f"{self.method_name}{self.descriptor}"
        self.method_key = method_key(self.method_name, self.descriptor)
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
            "target_files": census.classes.get(self.target_class, []),
        }

    def _refuse(self, plan: ModifierPlan, code: ApplicationReason) -> ModifierPlan:
        plan.refusal_code = code.value
        return plan

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        census = take_census(project.decoded_dir)
        files = census.classes.get(self.target_class, [])
        if not plan.require(
            "decoded_project_readable",
            not census.unparsed,
            expected="every smali file has a .class directive",
            actual=f"{len(census.unparsed)} unreadable",
            reason=f"smali file(s) without a readable .class directive: {census.unparsed[:5]}",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)
        if not plan.require(
            "class_exists",
            bool(files),
            expected=f"{self.target_class} defined",
            actual="not defined",
            reason=f"{self.target_class} is not defined in the decoded workspace",
        ):
            return self._refuse(plan, _R.TARGET_NOT_FOUND)
        if not plan.require(
            "class_unambiguous",
            len(files) == 1,
            expected="exactly one definition",
            actual=f"{len(files)} definitions ({', '.join(files)})",
        ):
            return self._refuse(plan, _R.TARGET_AMBIGUOUS)
        if not plan.require(
            "class_identity",
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

        target_path = project.path(self.target_file)
        text = target_path.read_text(encoding="utf-8")
        sigs = method_census(text)
        occurrences = sigs.count(self.signature)
        if not plan.require(
            "method_exists",
            occurrences >= 1,
            expected=f"{self.signature} declared by {self.target_class}",
            actual="not declared",
            reason=f"{self.target_class} does not declare {self.signature}",
        ):
            return self._refuse(plan, _R.TARGET_NOT_FOUND)
        if not plan.require(
            "method_unambiguous",
            occurrences == 1,
            expected="exactly one declaration",
            actual=f"{occurrences} declarations",
            reason=f"{self.signature} is declared {occurrences} times in {self.target_file}",
        ):
            return self._refuse(plan, _R.TARGET_AMBIGUOUS)
        block = split_method_block(text, self.signature)
        if not plan.require(
            "method_block_delimited",
            block is not None,
            expected=".method ... .end method block located once",
            actual="not located",
            reason=f"the {self.signature} block could not be delimited in {self.target_file}",
        ):
            return self._refuse(plan, _R.TARGET_STATE_MISMATCH)
        assert block is not None
        if not plan.require(
            "class_kept",
            len(sigs) > 1,
            expected=f"{self.target_class} keeps at least one method",
            actual=f"{len(sigs)} method(s)",
            reason="removing the only method would still leave the class; refuse the degenerate "
            "case so the class is always retained with other declarations",
        ):
            return self._refuse(plan, _R.TRANSFORMATION_PRECONDITION_FAILED)

        strings = strings_removed_for_method(
            project.decoded_dir, census, self.target_file, block, self.string_pool
        )
        if not plan.require(
            "string_changes_enumerable",
            len(strings) <= _SAMPLE_LIMIT,
            expected=f"at most {_SAMPLE_LIMIT} string-pool removals (Phase E enumeration)",
            actual=str(len(strings)),
            reason="Phase E cannot enumerate every string removal; the change could not "
            "be verified",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)

        plan.targets = [
            PlanTarget(
                kind="dex_method",
                identifier=f"{self.target_class}->{self.method_key}",
                access=TargetAccess.MODIFY,
            )
        ]
        plan.changes = [f"remove method {self.target_class}->{self.signature} ({self.target_file})"]
        plan.file_changes = [PlannedFileChange(path=self.target_file, action=FileAction.MODIFY)]
        plan.expected_changes = method_removal_expectations(
            self.target_class, self.method_key, strings, self.api_removed
        )
        plan.verification = [
            f"{self.target_class} still defined; {self.method_key} absent from the rebuilt "
            "DEX; no other method of the class added, removed or modified; no other class or "
            "DEX file changed"
        ]
        plan.details = {
            "transformation_id": self.transformation_id,
            "target_file": self.target_file,
            "target_dex": self.target_dex,
            "signature": self.signature,
            "method_key": self.method_key,
            "block_sha256": hashlib.sha256(block.text.encode("utf-8")).hexdigest(),
            "target_sha256": _sha256(target_path),
            "census_sha256": census.digest(),
            "methods": len(sigs),
            "classes": census.count,
        }
        return plan

    # -- apply ------------------------------------------------------------------

    def _write(self, path: Path, text: str) -> None:
        """The mutation itself (one hook, so a test can simulate a faulty mutation)."""
        path.write_text(text, encoding="utf-8")

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        details = plan.details
        path = project.path(self.target_file)
        before = take_census(project.decoded_dir)
        text = path.read_text(encoding="utf-8")
        block = split_method_block(text, self.signature)
        before_sigs = method_census(text)
        if (
            before.classes.get(self.target_class) != [self.target_file]
            or before.digest() != details["census_sha256"]
            or _sha256(path) != details["target_sha256"]
            or block is None
            or hashlib.sha256(block.text.encode("utf-8")).hexdigest() != details["block_sha256"]
        ):
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.TARGET_STATE_MISMATCH}: target state changed since planning"],
                details={"reason": _R.TARGET_STATE_MISMATCH.value},
            )
        pre_sha = _sha256(path)
        self._write(path, block.without)
        after = take_census(project.decoded_dir)
        # a faulty mutation may remove the whole file (and thus the class): tolerate it so
        # it is reported as UNEXPECTED_MUTATION rather than crashing
        after_sigs = method_census(path.read_text(encoding="utf-8")) if path.exists() else []
        removed = sorted(_multiset_diff(before_sigs, after_sigs))
        added = sorted(_multiset_diff(after_sigs, before_sigs))
        class_removed = sorted(set(before.classes) - set(after.classes))
        class_added = sorted(set(after.classes) - set(before.classes))
        record = MutationRecord(
            transformation_id=self.transformation_id,
            operation="REMOVE_METHOD",
            target=f"{self.target_class}->{self.signature}",
            target_file=self.target_file,
            target_dex=self.target_dex,
            count=len(removed),
            pre_transform_sha256=pre_sha,
            post_transform_sha256=_sha256(path) if path.exists() else None,
            classes_before=before.count,
            classes_after=after.count,
            removed_classes=class_removed,
            added_classes=class_added,
            census_before_sha256=before.digest(),
            census_after_sha256=after.digest(),
            method_name=self.method_name,
            descriptor=self.descriptor,
            method_signature=self.signature,
            method_key=self.method_key,
            methods_before=len(before_sigs),
            methods_after=len(after_sigs),
            removed_methods=removed,
            added_methods=added,
        )
        self.mutation = record
        problems: list[str] = []
        if self.signature in after_sigs:
            problems.append(f"{self.signature} is still declared after the mutation")
        if removed != [self.signature]:
            problems.append(f"expected exactly [{self.signature}] removed, observed {removed}")
        if added or class_removed or class_added or after.count != before.count:
            problems.append(
                f"classes changed (removed {class_removed}, added {class_added}) or methods "
                f"added {added}"
            )
        if len(after_sigs) != len(before_sigs) - 1:
            problems.append(f"method count {len(before_sigs)} -> {len(after_sigs)} (expected -1)")
        if problems:
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.UNEXPECTED_MUTATION}: " + "; ".join(problems)],
                details={"reason": _R.UNEXPECTED_MUTATION.value, "mutation": record.model_dump()},
            )
        return ApplyOutcome(
            applied=True,
            message=f"removed method {self.target_class}->{self.signature} ({self.target_file})",
            details={"mutation": record.model_dump()},
        )

    # -- verify -----------------------------------------------------------------

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        d = evidence.diff.dex
        modified = {c.class_name: c for c in d.classes_modified}
        cd = modified.get(self.target_class)
        this_removed = cd.methods_removed if cd else []
        this_other = (cd.methods_added + [m.method_name for m in cd.methods_modified]) if cd else []
        other_classes_modified = sorted(n for n in modified if n != self.target_class)
        checks = [
            Precondition(
                name="target_class_kept",
                satisfied=self.target_class not in d.classes_removed,
                expected="class retained",
                actual="removed" if self.target_class in d.classes_removed else "retained",
            ),
            Precondition(
                name="target_method_removed",
                satisfied=this_removed == [self.method_key],
                expected=f"[{self.method_key}]",
                actual=str(this_removed),
            ),
            Precondition(
                name="no_other_method_changed",
                satisfied=not this_other,
                expected="[]",
                actual=str(this_other),
            ),
            Precondition(
                name="no_other_class_changed",
                satisfied=not d.classes_added
                and not d.classes_removed
                and not other_classes_modified,
                expected="no other class added/removed/modified",
                actual=f"added {d.classes_added}, removed {d.classes_removed}, "
                f"modified {other_classes_modified}",
            ),
            Precondition(
                name="dex_files_unchanged",
                satisfied=not d.dex_files_added and not d.dex_files_removed,
                expected="no DEX file added or removed",
                actual=f"added {d.dex_files_added}, removed {d.dex_files_removed}",
            ),
        ]
        return VerificationOutcome.from_checks(checks)


def _multiset_diff(a: list[str], b: list[str]) -> list[str]:
    """Elements of *a* with greater multiplicity than in *b* (as a flat list)."""
    diff = Counter(a) - Counter(b)
    return list(diff.elements())


# ---------------------------------------------------------------------------
# H.6: H-TRANS-003 controlled call-site replacement
# ---------------------------------------------------------------------------

_INVOCATIONS = (ReferenceKind.METHOD_REFERENCE, ReferenceKind.CONSTRUCTOR_REFERENCE)


def _invocation(e: Evidence, *, line: bool = True) -> str:
    regs = ", ".join(e.registers or ())
    res = f" -> {e.result_instruction} {e.result_register}" if e.result_register else ""
    where = f"{e.source_line}: " if line else ""
    return f"{where}{e.instruction} {{{regs}}} {e.target}{res}"


def _other_evidence(e: Evidence) -> str:
    """Line-independent identity of a non-invocation record (class/type mentions are
    deduplicated per method, so their first line may move when an earlier mention goes)."""
    if e.kind in (ReferenceKind.CLASS_REFERENCE, ReferenceKind.TYPE_REFERENCE):
        return f"{e.kind.value} {e.source_method} {e.context} {e.instruction} {e.target}"
    return f"{e.kind.value} {e.source_method} {e.source_line} {e.instruction} {e.target}"


def invocation_diff(
    before: str, after: str, path: str, caller_method: str, owners: set[str]
) -> tuple[list[str], list[str], list[str]]:
    """Compare two versions of one smali file with the H.1 parser.

    Returns (invocations removed, invocations added, other differences). Class / type
    mentions of the original and replacement owner classes (*owners*) inside the caller
    method are a consequence of the replaced reference and are not "other"; occurrence
    counts of deduplicated mentions are ignored (only presence is compared)."""
    pa, pb = parse_smali(before, path), parse_smali(after, path)
    inv_a = [_invocation(e) for e in pa.evidence if e.kind in _INVOCATIONS]
    inv_b = [_invocation(e) for e in pb.evidence if e.kind in _INVOCATIONS]
    removed = sorted(_multiset_diff(inv_a, inv_b))
    added = sorted(_multiset_diff(inv_b, inv_a))

    def others(res: Any) -> list[str]:  # noqa: ANN401 - SmaliFileResult
        return [
            _other_evidence(e)
            for e in res.evidence
            if e.kind not in _INVOCATIONS
            and not (
                e.kind in (ReferenceKind.CLASS_REFERENCE, ReferenceKind.TYPE_REFERENCE)
                and e.source_method == caller_method
                and e.target in owners
                and e.context == "member-owner"
            )
        ]

    oa, ob = others(pa), others(pb)
    other = [f"- {x}" for x in sorted(set(oa) - set(ob))]
    other += [f"+ {x}" for x in sorted(set(ob) - set(oa))]
    if pa.state != pb.state or pa.methods != pb.methods or pa.class_name != pb.class_name:
        other.append(f"declarations/state changed ({pa.state} -> {pb.state})")
    return removed, added, other


def call_site_strings(
    root: Path,
    census: ClassCensus,
    caller_file: str,
    before: str,
    after: str,
    string_pool: set[str],
) -> tuple[set[str], set[str]]:
    """(pool strings removed, pool strings added) by rewriting *caller_file* from *before*
    to *after*. Mirrors :func:`strings_removed`: a string disappears only when no other
    class (nor the rewritten file) still contributes it; a string appears when the
    rewritten file contributes one the original pool lacks. Shared with H.4."""
    tok_before, tok_after = pool_tokens(before), pool_tokens(after)
    others = pool_tokens(after, generous=True)
    for paths in census.classes.values():
        for rel in paths:
            if rel != caller_file:
                others |= pool_tokens((root / rel).read_text(encoding="utf-8"), generous=True)
    removed = ((tok_before - tok_after) & string_pool) - others
    added = (tok_after - tok_before) - string_pool
    return removed, added


def call_site_expectations(
    caller_class: str,
    caller_method_name: str,
    call_site: str,
    strings: tuple[set[str], set[str]],
    api: tuple[set[str], set[str]],
) -> list[ExpectedChange]:
    """Every Phase E observation replacing one call site must produce (nothing else): the
    caller class is *modified* with exactly one method body changed (no method added or
    removed), plus the string-pool / framework-API consequences of the swapped reference
    (none when both methods are declared in the APK and keep their other users)."""
    s_removed, s_added = strings
    a_removed, a_added = api
    out = [
        ExpectedChange(
            category="dex_class",
            kind="modified",
            identifier=caller_class,
            detail={
                "methods_modified": [caller_method_name],
                "methods_added": [],
                "methods_removed": [],
            },
            description=f"{caller_class}.{caller_method_name}: {call_site} (the planned change)",
        )
    ]
    for kind, items, what in (
        ("removed", s_removed, "string-pool entry used only by the replaced reference"),
        ("added", s_added, "string-pool entry introduced by the replacement reference"),
    ):
        out += [
            ExpectedChange(category="dex_string", kind=kind, identifier=x, description=what)
            for x in sorted(items)
        ]
    for kind, items, what in (
        ("removed", a_removed, "framework API reference used only by the replaced call"),
        ("added", a_added, "framework API reference introduced by the replacement call"),
    ):
        out += [
            ExpectedChange(category="dex_api_reference", kind=kind, identifier=x, description=what)
            for x in sorted(items)
        ]
    return out


def _tree_digests(root: Path, census: ClassCensus, skip: str) -> dict[str, str]:
    return {
        rel: _sha256(root / rel)
        for paths in census.classes.values()
        for rel in paths
        if rel != skip
    }


class ReplaceCallSiteModifier(APKModifier):
    """Replaces the one invocation named by a validated ``H-TRANS-003`` plan (H.6).

    Constructed by the executor only *after* the plan passed every integrity and
    eligibility check; never registered in the default catalog. The mutation rewrites the
    method reference of exactly one smali line; opcode, registers and the consuming
    ``move-result`` stay as they are. There is no other edit operation: this is not a
    smali patcher."""

    id: ClassVar[str] = H6_MODIFIER_ID
    name: ClassVar[str] = "Replace call site (H-TRANS-003, H.6)"
    description: ClassVar[str] = (
        "Replaces the method reference of exactly the invocation named by a validated, "
        "ELIGIBLE H.2 plan with the plan's replacement method."
    )
    risk: ClassVar[ModificationRisk] = ModificationRisk.HIGH

    def __init__(
        self,
        plan: TransformationPlan,
        *,
        defined_classes: int,
        string_pool: set[str],
        api: tuple[set[str], set[str]],
    ) -> None:
        change = plan.planned_changes[0]
        d = change.details
        self.call_site = plan.target.canonical
        self.caller_class = d["caller_class"]
        self.caller_method = d["caller_method"]
        self.caller_method_name = self.caller_method.partition("(")[0]
        self.source_line = int(d["source_line"])
        self.opcode = d["opcode"]
        self.registers = d["registers"]
        self.result = (d.get("result_instruction", ""), d.get("result_register", ""))
        self.original = d["original"]
        self.replacement = d["replacement"]
        self.occurrence = int(d["occurrence"])
        self.occurrences = int(d["occurrences_in_caller"])
        self.target_file = change.artifact or ""
        self.target_dex = d.get("dex", "classes.dex")
        self.transformation_id = plan.transformation_id
        self.defined_classes = defined_classes
        self.string_pool = string_pool
        self.api = api
        self.owners = {
            self.original[1:].partition(";")[0].replace("/", "."),
            self.replacement[1:].partition(";")[0].replace("/", "."),
        }
        self.mutation: MutationRecord | None = None

    @property
    def original_target(self) -> str:
        """The H.1 evidence ``target`` of the original invocation (``com.x.A.f(I)V``)."""
        return _evidence_target(self.original)

    @property
    def replacement_target(self) -> str:
        return _evidence_target(self.replacement)

    # -- plan -------------------------------------------------------------------

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        census = take_census(project.decoded_dir)
        return {
            "classes": census.count,
            "caller_files": census.classes.get(self.caller_class, []),
        }

    def _refuse(self, plan: ModifierPlan, code: ApplicationReason) -> ModifierPlan:
        plan.refusal_code = code.value
        return plan

    def _locate(self, text: str) -> tuple[Evidence | None, list[Evidence], str]:
        """(record at the planned line, the caller's invocations of the original, why not)."""
        parsed = parse_smali(text, self.target_file, self.target_dex)
        calls = [
            e
            for e in parsed.evidence
            if e.kind in _INVOCATIONS
            and e.source_method == self.caller_method
            and e.target == self.original_target
        ]
        at = [e for e in calls if e.source_line == self.source_line]
        if not at:
            return None, calls, f"no invocation of {self.original} at line {self.source_line}"
        e = at[0]
        problems = []
        if (e.instruction or "") != self.opcode:
            problems.append(f"opcode {e.instruction} != {self.opcode}")
        if ", ".join(e.registers or ()) != self.registers:
            problems.append(f"registers {e.registers} != {self.registers}")
        if (e.result_instruction or "", e.result_register or "") != self.result:
            problems.append(f"result {e.result_instruction} {e.result_register} != {self.result}")
        if len(calls) != self.occurrences or calls.index(e) + 1 != self.occurrence:
            problems.append(
                f"occurrence {calls.index(e) + 1}/{len(calls)} != planned "
                f"{self.occurrence}/{self.occurrences}"
            )
        return (None if problems else e), calls, "; ".join(problems)

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        census = take_census(project.decoded_dir)
        files = census.classes.get(self.caller_class, [])
        if not plan.require(
            "decoded_project_readable",
            not census.unparsed,
            expected="every smali file has a .class directive",
            actual=f"{len(census.unparsed)} unreadable",
            reason=f"smali file(s) without a readable .class directive: {census.unparsed[:5]}",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)
        if not plan.require(
            "caller_exists",
            bool(files),
            expected=f"{self.caller_class} defined",
            actual="not defined",
            reason=f"{self.caller_class} is not defined in the decoded workspace",
        ):
            return self._refuse(plan, _R.TARGET_NOT_FOUND)
        if not plan.require(
            "caller_unambiguous",
            len(files) == 1,
            expected="exactly one definition",
            actual=f"{len(files)} definitions ({', '.join(files)})",
        ):
            return self._refuse(plan, _R.TARGET_AMBIGUOUS)
        if not plan.require(
            "caller_identity",
            files[0] == self.target_file and census.dex_of[files[0]] == self.target_dex,
            expected=f"{self.target_file} ({self.target_dex})",
            actual=f"{files[0]} ({census.dex_of[files[0]]})",
            reason="the caller is not defined where the plan recorded it",
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

        path = project.path(self.target_file)
        text = path.read_text(encoding="utf-8")
        selected, calls, why = self._locate(text)
        if not plan.require(
            "call_site_exists",
            bool(calls),
            expected=f"{self.caller_method} invokes {self.original}",
            actual="no such invocation",
            reason=f"{self.caller_class}->{self.caller_method} no longer invokes {self.original}",
        ):
            return self._refuse(plan, _R.TARGET_NOT_FOUND)
        if not plan.require(
            "call_site_matches_plan",
            selected is not None,
            expected=f"{self.opcode} {{{self.registers}}} {self.original} at line "
            f"{self.source_line} (#{self.occurrence} of {self.occurrences})",
            actual=why,
            reason=f"the invocation does not match the plan: {why}",
        ):
            return self._refuse(plan, _R.TARGET_STATE_MISMATCH)
        new_text = replace_invocation(text, self.source_line, self.original, self.replacement)
        if not plan.require(
            "call_site_rewritable",
            new_text is not None,
            expected=f"line {self.source_line} ends with the method reference exactly once",
            actual="not rewritable",
            reason="the smali line does not have the single-reference invocation form",
        ):
            return self._refuse(plan, _R.TARGET_STATE_MISMATCH)
        assert new_text is not None
        strings = call_site_strings(
            project.decoded_dir, census, self.target_file, text, new_text, self.string_pool
        )
        if not plan.require(
            "string_changes_enumerable",
            len(strings[0]) + len(strings[1]) <= _SAMPLE_LIMIT,
            expected=f"at most {_SAMPLE_LIMIT} string-pool changes (Phase E enumeration)",
            actual=str(len(strings[0]) + len(strings[1])),
            reason="Phase E cannot enumerate every string change; the change could not be verified",
        ):
            return self._refuse(plan, _R.ANALYSIS_INCOMPLETE)

        plan.targets = [
            PlanTarget(
                kind="dex_call_site",
                identifier=f"{self.caller_class}->{self.caller_method}:{self.source_line}",
                access=TargetAccess.MODIFY,
            )
        ]
        plan.changes = [
            f"replace {self.original} with {self.replacement} in "
            f"{self.caller_class}->{self.caller_method} ({self.target_file}:{self.source_line})"
        ]
        plan.file_changes = [PlannedFileChange(path=self.target_file, action=FileAction.MODIFY)]
        plan.expected_changes = call_site_expectations(
            self.caller_class, self.caller_method_name, self.call_site, strings, self.api
        )
        plan.verification = [
            f"{self.caller_class}: only {self.caller_method_name} has a changed body; no method "
            "or class added, removed or otherwise modified; no DEX file added or removed"
        ]
        plan.details = {
            "transformation_id": self.transformation_id,
            "target_file": self.target_file,
            "target_dex": self.target_dex,
            "call_site": self.call_site,
            "target_sha256": _sha256(path),
            "census_sha256": census.digest(),
            "others_sha256": hashlib.sha256(
                repr(
                    sorted(_tree_digests(project.decoded_dir, census, self.target_file).items())
                ).encode()
            ).hexdigest(),
            "classes": census.count,
        }
        return plan

    # -- apply ------------------------------------------------------------------

    def _rewrite(self, text: str) -> str | None:
        """The edit itself: the one planned line (one hook, so a test can simulate a
        faulty mutation)."""
        return replace_invocation(text, self.source_line, self.original, self.replacement)

    def _write(self, path: Path, text: str) -> None:
        path.write_text(text, encoding="utf-8")

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        details = plan.details
        root = project.decoded_dir
        path = project.path(self.target_file)
        before = take_census(root)
        text = path.read_text(encoding="utf-8")
        others_before = _tree_digests(root, before, self.target_file)
        selected, _calls, _why = self._locate(text)
        if (
            before.classes.get(self.caller_class) != [self.target_file]
            or before.digest() != details["census_sha256"]
            or _sha256(path) != details["target_sha256"]
            or selected is None
        ):
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.TARGET_STATE_MISMATCH}: target state changed since planning"],
                details={"reason": _R.TARGET_STATE_MISMATCH.value},
            )
        new_text = self._rewrite(text)
        pre_sha = _sha256(path)
        if new_text is not None:
            self._write(path, new_text)
        after = take_census(root)
        after_text = path.read_text(encoding="utf-8") if path.exists() else ""
        lines_a, lines_b = text.splitlines(), after_text.splitlines()
        changed = [
            i + 1
            for i in range(max(len(lines_a), len(lines_b)))
            if (lines_a[i] if i < len(lines_a) else None)
            != (lines_b[i] if i < len(lines_b) else None)
        ]
        removed, added, other = invocation_diff(
            text, after_text, self.target_file, self.caller_method, self.owners
        )
        others_after = _tree_digests(root, after, self.target_file)
        other += [
            f"file {rel} changed"
            for rel in sorted(set(others_before) | set(others_after))
            if others_before.get(rel) != others_after.get(rel)
        ]
        class_removed = sorted(set(before.classes) - set(after.classes))
        class_added = sorted(set(after.classes) - set(before.classes))
        record = MutationRecord(
            transformation_id=self.transformation_id,
            operation="REPLACE_CALL_SITE",
            target=self.call_site,
            target_file=self.target_file,
            target_dex=self.target_dex,
            count=len(added),
            pre_transform_sha256=pre_sha,
            post_transform_sha256=_sha256(path) if path.exists() else None,
            classes_before=before.count,
            classes_after=after.count,
            removed_classes=class_removed,
            added_classes=class_added,
            census_before_sha256=before.digest(),
            census_after_sha256=after.digest(),
            method_signature=self.caller_method,
            changed_methods=[self.caller_method] if changed else [],
            call_site=self.call_site,
            source_line=self.source_line,
            original_instruction=lines_a[self.source_line - 1].strip(),
            replacement_instruction=(
                lines_b[self.source_line - 1].strip() if self.source_line <= len(lines_b) else None
            ),
            changed_lines=changed,
            removed_invocations=removed,
            added_invocations=added,
            other_changes=other,
        )
        self.mutation = record
        regs = self.registers
        res = f" -> {self.result[0]} {self.result[1]}" if self.result[1] else ""
        want_removed = [f"{self.source_line}: {self.opcode} {{{regs}}} {self.original_target}{res}"]
        want_added = [
            f"{self.source_line}: {self.opcode} {{{regs}}} {self.replacement_target}{res}"
        ]
        problems: list[str] = []
        if new_text is None:
            problems.append("the planned line could not be rewritten")
        if changed != [self.source_line]:
            problems.append(f"expected exactly line {self.source_line} changed, observed {changed}")
        if removed != want_removed or added != want_added:
            problems.append(
                f"expected exactly 1 call site changed ({want_removed} -> {want_added}), "
                f"observed removed {removed}, added {added}"
            )
        if other or class_removed or class_added or after.count != before.count:
            problems.append(
                f"other changes {other[:5]}; classes removed {class_removed}, added {class_added}"
            )
        if problems:
            return ApplyOutcome(
                applied=False,
                errors=[f"{_R.UNEXPECTED_MUTATION}: " + "; ".join(problems)],
                details={"reason": _R.UNEXPECTED_MUTATION.value, "mutation": record.model_dump()},
            )
        return ApplyOutcome(
            applied=True,
            message=f"replaced {self.original} with {self.replacement} at "
            f"{self.target_file}:{self.source_line}",
            details={"mutation": record.model_dump()},
        )

    # -- verify -----------------------------------------------------------------

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        d = evidence.diff.dex
        modified = {c.class_name: c for c in d.classes_modified}
        cd = modified.get(self.caller_class)
        changed = [m.method_name for m in cd.methods_modified] if cd else []
        decl = (
            (cd.methods_added + cd.methods_removed + cd.fields_added + cd.fields_removed)
            if cd
            else []
        )
        other_classes = sorted(n for n in modified if n != self.caller_class)
        checks = [
            Precondition(
                name="caller_method_body_changed",
                satisfied=changed == [self.caller_method_name],
                expected=f"[{self.caller_method_name}]",
                actual=str(changed),
            ),
            Precondition(
                name="no_declaration_changed",
                satisfied=not decl,
                expected="[]",
                actual=str(decl),
            ),
            Precondition(
                name="no_other_class_changed",
                satisfied=not d.classes_added and not d.classes_removed and not other_classes,
                expected="no other class added/removed/modified",
                actual=f"added {d.classes_added}, removed {d.classes_removed}, "
                f"modified {other_classes}",
            ),
            Precondition(
                name="dex_files_unchanged",
                satisfied=not d.dex_files_added and not d.dex_files_removed,
                expected="no DEX file added or removed",
                actual=f"added {d.dex_files_added}, removed {d.dex_files_removed}",
            ),
        ]
        return VerificationOutcome.from_checks(checks)


def _evidence_target(smali_ref: str) -> str:
    """``Lcom/x/A;->f(I)V`` -> ``com.x.A.f(I)V`` (the H.1 invocation record's target)."""
    owner, _, member = smali_ref.partition(";->")
    return f"{owner[1:].replace('/', '.')}.{member}"
