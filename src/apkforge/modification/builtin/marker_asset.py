"""Test-only Phase D modifier: add one fixed text file under ``assets/``.

It exists to prove that the framework is not specific to C.5: a different kind of
change (a new file instead of manifest edits), its own preconditions, its own expected
change (``file added``), and its own verification that reads the rebuilt APK directly.

It has no security, privacy or sanitisation purpose. The application never reads the
file: nothing references it, and the content is plain text without URLs, hosts or code.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from typing import TYPE_CHECKING, Any, ClassVar

from apkforge.diff.expectations import ExpectedChange
from apkforge.modification.contract import (
    APKModifier,
    ApplyOutcome,
    FileAction,
    ModifierPlan,
    PlannedFileChange,
    PlanTarget,
    Precondition,
    TargetAccess,
    VerificationOutcome,
)
from apkforge.modification.models import ModificationRisk

if TYPE_CHECKING:
    from apkforge.modification.contract import ProjectContext, VerificationEvidence

__all__ = ["MARKER_CONTENT", "MARKER_DIR", "MarkerAssetModifier"]

MARKER_DIR = "assets/apkforge-test"
MARKER_CONTENT = (
    b"APKForge modification framework test marker.\n"
    b"Added by the test-only modifier test.marker_asset. Not read by the application.\n"
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class MarkerAssetModifier(APKModifier):
    id: ClassVar[str] = "test.marker_asset"
    name: ClassVar[str] = "Add marker asset (test only)"
    description: ClassVar[str] = (
        f"Add a fixed {len(MARKER_CONTENT)}-byte text file under {MARKER_DIR}/ to exercise "
        "the modification framework. No security or privacy purpose."
    )
    version: ClassVar[str] = "1"
    risk: ClassVar[ModificationRisk] = ModificationRisk.LOW
    supported_conditions: ClassVar[list[str]] = [
        "any Apktool-decodable APK whose decoded project does not already contain the marker"
    ]
    prerequisites: ClassVar[list[str]] = ["Apktool-decoded project (apktool.yml)"]
    parameters: ClassVar[dict[str, str]] = {
        "name": "Marker file name (default marker.txt; letters, digits, '.', '_', '-')",
    }
    test_only: ClassVar[bool] = True

    @staticmethod
    def _path(parameters: dict[str, str]) -> str:
        return f"{MARKER_DIR}/{parameters.get('name', 'marker.txt')}"

    def inspect(self, project: ProjectContext) -> dict[str, Any]:
        assets = project.decoded_dir / "assets"
        return {
            "apktool_yml": (project.decoded_dir / "apktool.yml").is_file(),
            "assets_dir": assets.is_dir() and not assets.is_symlink(),
            "marker_dir_entries": sorted(
                p.name for p in (project.decoded_dir / MARKER_DIR).glob("*")
            )
            if (project.decoded_dir / MARKER_DIR).is_dir()
            else [],
        }

    def plan(
        self, project: ProjectContext, findings: dict[str, Any], parameters: dict[str, str]
    ) -> ModifierPlan:
        plan = self.new_plan(project, parameters)
        name = parameters.get("name", "marker.txt")
        if not plan.require(
            "valid_name",
            bool(_NAME.fullmatch(name)),
            expected="a plain file name ([A-Za-z0-9._-], no path separators)",
            actual=repr(name),
        ):
            plan.refusal_code = "invalid_parameter"
            return plan
        path = self._path(parameters)
        plan.require(
            "apktool_project",
            bool(findings.get("apktool_yml")),
            expected="apktool.yml present",
            actual="present" if findings.get("apktool_yml") else "missing",
        )
        marker = project.path(path)
        exists = marker.exists() or marker.is_symlink()
        plan.require(
            "marker_absent",
            not exists,
            expected=f"{path} absent",
            actual="present" if exists else "absent",
            reason=f"{path} already exists; nothing to add",
        )
        if not plan.ready:
            plan.refusal_code = plan.refusal_code or "precondition_failed"
            return plan
        plan.targets = [PlanTarget(kind="file", identifier=path, access=TargetAccess.ADD)]
        plan.changes = [f"add {path} ({len(MARKER_CONTENT)} bytes, fixed text)"]
        plan.file_changes = [PlannedFileChange(path=path, action=FileAction.ADD)]
        plan.expected_changes = [
            ExpectedChange(
                category="file",
                kind="added",
                identifier=path,
                detail={"file_category": "asset", "size": len(MARKER_CONTENT)},
                content_after=hashlib.sha256(MARKER_CONTENT).hexdigest(),
                description=f"{path} added with exactly the marker bytes",
            )
        ]
        plan.verification = [f"the rebuilt APK contains {path} with exactly the marker bytes"]
        plan.limitations = ["Test-only change; demonstrates the framework, nothing else."]
        return plan

    def apply(self, plan: ModifierPlan, project: ProjectContext) -> ApplyOutcome:
        (fc,) = plan.file_changes
        target = project.path(fc.path)
        if target.exists() or target.is_symlink():
            return ApplyOutcome(applied=False, errors=[f"{fc.path} already exists"])
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as f:  # never follows or replaces an existing entry
            f.write(MARKER_CONTENT)
        return ApplyOutcome(applied=True, message=f"added {fc.path}")

    def verify(self, plan: ModifierPlan, evidence: VerificationEvidence) -> VerificationOutcome:
        (fc,) = plan.file_changes
        present, content_ok, actual = False, False, "missing"
        with zipfile.ZipFile(evidence.output_apk) as z:
            try:
                info = z.getinfo(fc.path)
            except KeyError:
                info = None
            if info is not None:
                present = True
                actual = f"{info.file_size} bytes"
                if info.file_size == len(MARKER_CONTENT):
                    content_ok = z.read(info) == MARKER_CONTENT
                    actual = "identical" if content_ok else "different bytes"
        return VerificationOutcome.from_checks(
            [
                Precondition(
                    name="marker_present",
                    satisfied=present,
                    expected=f"{fc.path} in the rebuilt APK",
                    actual="present" if present else "missing",
                ),
                Precondition(
                    name="marker_content",
                    satisfied=content_ok,
                    expected=f"{len(MARKER_CONTENT)} marker bytes",
                    actual=actual,
                ),
            ]
        )
