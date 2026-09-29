"""Modification planner converting static analysis into reviewable modification plans."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from apkforge.core.models import AnalysisStatus
from apkforge.modification.conflicts import ConflictDetector
from apkforge.modification.dependencies import DependencyAnalyzer
from apkforge.modification.models import (
    ChangeConflict,
    ChangeDependency,
    ModificationPlan,
    PlannedChange,
    PlanStatus,
)
from apkforge.modification.registry import ModificationRuleRegistry
from apkforge.modification.rules import ModificationContext

if TYPE_CHECKING:
    from apkforge.diff.models import DiffResult
    from apkforge.inspection.models import InspectionResult
    from apkforge.intake import AndroidPackage
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import SecurityResult

_log = logging.getLogger(__name__)


class ModificationPlanner:
    """Orchestrates proposal generation, impact assessment, dependencies, and conflicts."""

    PLANNER_VERSION = "0.1.0"

    def __init__(self, registry: ModificationRuleRegistry | None = None) -> None:
        self.registry = registry or ModificationRuleRegistry()

    def create_plan(
        self,
        apk_path: Path | str,
        inspection: InspectionResult | None = None,
        privacy: PrivacyResult | None = None,
        security: SecurityResult | None = None,
        diff: DiffResult | None = None,
        package: AndroidPackage | None = None,
    ) -> ModificationPlan:
        """Generate a structured, non-destructive ModificationPlan from analysis evidence."""
        p_path = Path(apk_path)
        sha256 = self._compute_sha256(p_path)

        warnings: list[str] = []
        limitations: list[str] = []
        analysis_refs: dict[str, str] = {}

        # 1. Evaluate analysis availability and record limitations
        if inspection:
            analysis_refs["inspection"] = inspection.status.value
            if inspection.status == AnalysisStatus.PARTIAL:
                warnings.append("Inspection status is PARTIAL; some artifacts were unparsed.")
                limitations.append(
                    "Inspection was partial; proposal generation may miss uninspected components."
                )
            elif inspection.status == AnalysisStatus.FAILED:
                warnings.append("Inspection status is FAILED.")
                limitations.append(
                    "Inspection failed; proposals requiring manifest or bytecode cannot run."
                )
            if not inspection.dex or not getattr(inspection.dex, "dex_files", []):
                limitations.append(
                    "DEX bytecode was not analyzed; API-based permission checks are degraded."
                )
        else:
            warnings.append("No InspectionResult provided.")
            limitations.append(
                "Inspection result was not provided; manifest and DEX proposals were skipped."
            )

        if privacy:
            analysis_refs["privacy"] = privacy.status.value
            if privacy.status == AnalysisStatus.PARTIAL:
                warnings.append("Privacy analysis status is PARTIAL.")
        else:
            limitations.append(
                "Privacy analysis was not provided; tracker and ad SDK proposals were not "
                "generated."
            )

        if security:
            analysis_refs["security"] = security.status.value
            if security.status == AnalysisStatus.PARTIAL:
                warnings.append("Security analysis status is PARTIAL.")
        else:
            limitations.append(
                "Security analysis was not provided; security finding mitigations were not "
                "generated."
            )

        if diff:
            analysis_refs["diff"] = "available"

        # 2. Build ModificationContext
        context = ModificationContext(
            apk_path=p_path,
            apk_sha256=sha256,
            package=package,
            inspection=inspection,
            privacy=privacy,
            security=security,
            diff=diff,
        )

        # 3. Execute modification rules
        raw_changes = self.registry.evaluate_all(context)

        # 4. Dependency discovery
        dependencies = DependencyAnalyzer.discover_dependencies(raw_changes)

        # 5. Conflict detection
        conflicts = ConflictDetector.detect_conflicts(raw_changes)

        # 6. Topological and logical ordering
        ordered_changes = DependencyAnalyzer.order_changes(raw_changes, dependencies)

        # 7. Normalize sequential IDs (CHANGE-001, CHANGE-002, ...)
        final_changes = self._normalize_change_ids(ordered_changes, dependencies, conflicts)

        # 8. Deterministic Plan ID
        hasher = hashlib.sha256()
        hasher.update(f"{sha256}:{len(final_changes)}:{self.PLANNER_VERSION}".encode())
        for c in final_changes:
            hasher.update(f":{c.id}:{c.change_type.value}:{c.target}".encode())
        plan_id = f"PLAN-{hasher.hexdigest()[:12].upper()}"

        status = PlanStatus.REVIEW_REQUIRED
        if conflicts:
            warnings.append(
                f"{len(conflicts)} conflict(s) detected between proposed changes; "
                "review and select mutually compatible modifications."
            )

        return ModificationPlan(
            plan_id=plan_id,
            source_apk=str(p_path),
            source_sha256=sha256,
            created_at=datetime.now(tz=UTC).isoformat(),
            planner_version=self.PLANNER_VERSION,
            analysis_references=analysis_refs,
            changes=final_changes,
            dependencies=dependencies,
            conflicts=conflicts,
            warnings=warnings,
            limitations=limitations,
            status=status,
        )

    def _normalize_change_ids(
        self,
        changes: list[PlannedChange],
        dependencies: list[ChangeDependency],
        conflicts: list[ChangeConflict],
    ) -> list[PlannedChange]:
        """Assign sequential identifiers (CHANGE-001, ...) and remap references."""
        id_map: dict[str, str] = {}
        for idx, c in enumerate(changes, start=1):
            new_id = f"CHANGE-{idx:03d}"
            id_map[c.id] = new_id

        # Remap IDs
        for c in changes:
            old_id = c.id
            c.id = id_map.get(old_id, old_id)
            c.dependencies = [id_map.get(d, d) for d in c.dependencies]
            c.conflicts = [id_map.get(cf, cf) for cf in c.conflicts]

        for d in dependencies:
            d.change_id = id_map.get(d.change_id, d.change_id)
            d.depends_on_id = id_map.get(d.depends_on_id, d.depends_on_id)

        for cf in conflicts:
            cf.change_id_a = id_map.get(cf.change_id_a, cf.change_id_a)
            cf.change_id_b = id_map.get(cf.change_id_b, cf.change_id_b)

        return changes

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        """Compute SHA-256 hash of APK file."""
        if not path.is_file():
            return "0" * 64
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().lower()
