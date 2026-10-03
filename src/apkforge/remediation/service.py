"""Programmatic Service layer for Phase G Controlled Remediation.

Provides:
- RemediationService.plan()
- RemediationService.apply()
- RemediationService.remediate()
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.remediation.execution import RemediationExecutor
from apkforge.remediation.planner import RemediationPlanner
from apkforge.remediation.report import (
    format_remediation_diff_report,
    format_remediation_plan_report,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.privacy.models import PrivacyFinding, PrivacyResult
    from apkforge.remediation.models import (
        RemediationExecutionResult,
        RemediationPlan,
    )

__all__ = ["RemediationService"]


class RemediationService:
    """High-level programmatic API for APKForge controlled privacy/security remediation."""

    @classmethod
    def plan(
        cls,
        apk_path: str | Path,
        finding_id: str,
        *,
        remediation_id: str | None = None,
        parameters: dict[str, str] | None = None,
        pre_analysis: PrivacyResult | None = None,
        finding_override: PrivacyFinding | None = None,
    ) -> RemediationPlan:
        """Construct a deterministic remediation plan for a finding."""
        planner = RemediationPlanner()
        return planner.plan(
            apk_path=apk_path,
            finding_id=finding_id,
            remediation_id=remediation_id,
            parameters=parameters,
            pre_analysis=pre_analysis,
            finding_override=finding_override,
        )

    @classmethod
    def apply(
        cls,
        plan: RemediationPlan,
        *,
        approved: bool = False,
        output_path: str | Path | None = None,
        work_dir: str | Path | None = None,
        pre_analysis: PrivacyResult | None = None,
    ) -> RemediationExecutionResult:
        """Apply an approved remediation plan and verify results."""
        executor = RemediationExecutor()
        return executor.execute(
            plan=plan,
            approved=approved,
            output_path=output_path,
            work_dir=work_dir,
            pre_analysis=pre_analysis,
        )

    @classmethod
    def remediate(
        cls,
        apk_path: str | Path,
        finding_id: str,
        *,
        approved: bool = False,
        remediation_id: str | None = None,
        parameters: dict[str, str] | None = None,
        output_path: str | Path | None = None,
        work_dir: str | Path | None = None,
        pre_analysis: PrivacyResult | None = None,
    ) -> RemediationExecutionResult:
        """Plan and execute (if approved) a remediation for a finding."""
        plan = cls.plan(
            apk_path=apk_path,
            finding_id=finding_id,
            remediation_id=remediation_id,
            parameters=parameters,
            pre_analysis=pre_analysis,
        )
        return cls.apply(
            plan=plan,
            approved=approved,
            output_path=output_path,
            work_dir=work_dir,
            pre_analysis=pre_analysis,
        )

    @classmethod
    def format_plan_report(cls, plan: RemediationPlan) -> str:
        return format_remediation_plan_report(plan)

    @classmethod
    def format_diff_report(cls, result: RemediationExecutionResult) -> str:
        return format_remediation_diff_report(result)
