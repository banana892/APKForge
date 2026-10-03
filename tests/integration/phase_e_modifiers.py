"""Test-only modifiers for the Phase E verification scenarios (never in the default catalog).

- ``test.undeclared_meta_data``: adds a ``<meta-data>`` element to ``<application>``.
  The source edit is planned exactly, but no expected change is declared. Before Phase
  E no DiffEngine comparator looked at ``<meta-data>``, so the rebuilt manifest's byte
  change passed as ``manifest_reencoded`` noise; the full manifest tree comparison now
  reports it as an unexpected ``manifest_element`` change.
- ``test.declared_meta_data``: the same edit, declared as a specific expected change
  (element key, tag, subtree hash) derived from the planned decoded manifest.
- ``test.missing_expectation``: adds a fixed asset and declares, in addition, a change
  it never makes (a permission removal), so the requested change is not observed.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.diff.expectations import ExpectedChange
from apkforge.diff.manifest_tree import diff_manifest_trees, parse_manifest_xml
from apkforge.modification.contract import (
    MANIFEST,
    APKModifier,
    ApplyOutcome,
    FileAction,
    ModifierPlan,
    PlannedFileChange,
)
from apkforge.modification.edits import manifest_edits

if TYPE_CHECKING:
    from apkforge.modification.contract import ProjectContext

__all__ = [
    "DeclaredMetaDataModifier",
    "MissingExpectationModifier",
    "UndeclaredMetaDataModifier",
]

META_NAME = "apkforge.test.phase_e"
META_VALUE = "apkforge-phase-e-marker"
_APPLICATION_OPEN = re.compile(r"(<application\b[^>]*?)(/?)>", re.S)


def _with_meta_data(text: str) -> str:
    element = f'<meta-data android:name="{META_NAME}" android:value="{META_VALUE}"/>'
    m = _APPLICATION_OPEN.search(text)
    if m is None:
        raise ValueError("no <application> element")
    if m.group(2):  # self-closing <application/>
        return text[: m.start()] + f"{m.group(1)}>{element}</application>" + text[m.end() :]
    return text[: m.end()] + element + text[m.end() :]


class UndeclaredMetaDataModifier(APKModifier):
    id: ClassVar[str] = "test.undeclared_meta_data"
    name: ClassVar[str] = "Undeclared <meta-data> (test)"
    description: ClassVar[str] = "Adds a <meta-data> element without declaring it as expected."

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        before = project.manifest_text()
        after = _with_meta_data(before)
        plan.file_changes = [PlannedFileChange(path=MANIFEST, action=FileAction.MODIFY)]
        plan.manifest_edits = manifest_edits(before, after)
        plan.changes = [f"add <meta-data android:name={META_NAME}> to <application>"]
        plan.expected_changes = self.expectations(before, after)
        return plan

    def expectations(self, before: str, after: str) -> list[ExpectedChange]:
        return []

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        project.manifest_path.write_text(_with_meta_data(project.manifest_text()), encoding="utf-8")
        return ApplyOutcome(applied=True, message="added <meta-data>")


class DeclaredMetaDataModifier(UndeclaredMetaDataModifier):
    id: ClassVar[str] = "test.declared_meta_data"
    name: ClassVar[str] = "Declared <meta-data> (test)"
    description: ClassVar[str] = "Adds a <meta-data> element and declares exactly that change."

    def expectations(self, before: str, after: str) -> list[ExpectedChange]:
        changes = diff_manifest_trees(parse_manifest_xml(before), parse_manifest_xml(after))
        return [
            ExpectedChange(
                category="manifest_element",
                kind=c.kind,
                identifier=c.identifier,
                detail=c.detail(),
                description=f"<meta-data {META_NAME}> added to <application>",
            )
            for c in changes
        ]


class MissingExpectationModifier(APKModifier):
    id: ClassVar[str] = "test.missing_expectation"
    name: ClassVar[str] = "Missing expectation (test)"
    description: ClassVar[str] = "Declares a change it never makes."
    path = "assets/apkforge-test/missing-expectation.txt"
    content = b"apkforge phase e: missing expectation scenario\n"

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        plan.file_changes = [PlannedFileChange(path=self.path, action=FileAction.ADD)]
        plan.changes = [f"add {self.path}", "remove <uses-permission android.permission.INTERNET>"]
        plan.expected_changes = [
            ExpectedChange(
                category="file",
                kind="added",
                identifier=self.path,
                detail={"file_category": "asset", "size": len(self.content)},
                content_after=hashlib.sha256(self.content).hexdigest(),
            ),
            ExpectedChange(
                category="uses_permission",
                kind="removed",
                identifier="android.permission.INTERNET",
                description="declared but never applied",
            ),
        ]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        target = project.path(self.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.content)
        return ApplyOutcome(applied=True)
