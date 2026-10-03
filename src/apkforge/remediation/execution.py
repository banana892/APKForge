"""Remediation Executor for Phase G.

Executes an approved RemediationPlan by orchestrating the Phase D ModificationPipeline,
BuildService, Phase E VerificationMatrix, and post-remediation Phase F PrivacyAnalysis.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineStatus,
)
from apkforge.privacy.service import PrivacyAnalysisService
from apkforge.remediation.compare import compare_privacy_before_after
from apkforge.remediation.models import (
    FindingResolution,
    RemediationExecutionResult,
    RemediationPlan,
    RemediationState,
)
from apkforge.remediation.modifiers import remediation_modifier_catalog

if TYPE_CHECKING:
    from apkforge.builders import BuildService
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.privacy.models import PrivacyResult

__all__ = ["RemediationExecutor", "default_build_service"]


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def default_build_service(work_dir: Path | None = None) -> BuildService:
    """Creates a BuildService with discovered toolchain and dev keystore."""
    from apkforge.builders import BuildService, SigningConfig, ToolchainConfig
    from apkforge.builders.signing import ensure_dev_keystore

    toolchain = ToolchainConfig.discover()
    signing = SigningConfig.from_env()
    if signing is None and toolchain.keytool is not None:
        signing = ensure_dev_keystore(toolchain.keytool)
    return BuildService(toolchain, signing, work_dir=work_dir)


def default_noop_baseline() -> NoopSemanticBaseline | None:
    """Loads the Phase E noise baseline if available."""
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline

    base_file = Path("tests/corpus/results/phase-e-noise-baseline.json")
    if base_file.exists():
        return NoopSemanticBaseline.model_validate_json(base_file.read_text(encoding="utf-8"))
    return None


class RemediationExecutor:
    """Executes approved remediation plans with full verification and post-analysis."""

    def __init__(
        self,
        build_service: BuildService | None = None,
        noop_baseline: NoopSemanticBaseline | None = None,
    ) -> None:
        self.catalog = remediation_modifier_catalog()
        self.build_service = build_service
        self.noop_baseline = noop_baseline

    def execute(
        self,
        plan: RemediationPlan,
        *,
        approved: bool = False,
        output_path: str | Path | None = None,
        work_dir: str | Path | None = None,
        pre_analysis: PrivacyResult | None = None,
    ) -> RemediationExecutionResult:
        """Execute a remediation plan with explicit approval."""
        source_path = Path(plan.source_apk_path)
        sha_before = sha256_file(source_path)

        # 1. Approval Gate
        if not approved:
            return RemediationExecutionResult(
                plan=plan,
                state=RemediationState.APPROVAL_REQUIRED,
                approved=False,
                original_apk_sha256_before=sha_before,
                original_apk_sha256_after=sha_before,
                original_apk_preserved=True,
                errors=["Remediation requires explicit approval (--apply)."],
                warnings=["Run with --apply to apply planned changes to a rebuilt APK."],
            )

        # 2. Plan Readiness Gate
        if not plan.ready:
            return RemediationExecutionResult(
                plan=plan,
                state=plan.state,
                approved=approved,
                original_apk_sha256_before=sha_before,
                original_apk_sha256_after=sha_before,
                original_apk_preserved=True,
                errors=[f"Plan is not ready for execution (state={plan.state})."],
                warnings=list(plan.warnings),
                limitations=list(plan.limitations),
            )

        # 3. Destination output path
        if output_path is not None:
            out_file = Path(output_path).resolve()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            workspace_parent = out_file.parent
        else:
            temp_out_dir = (
                Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="apkforge-rem-"))
            )
            temp_out_dir.mkdir(parents=True, exist_ok=True)
            out_file = temp_out_dir / f"remediated-{source_path.stem}.apk"
            workspace_parent = temp_out_dir

        # 4. Phase D Pipeline execution
        service = self.build_service or default_build_service(
            Path(work_dir) if work_dir else workspace_parent
        )
        pipeline = ModificationPipeline(service=service, catalog=self.catalog)
        requests = [
            ModifierRequest(
                modifier_id=req["modifier_id"],
                parameters=req.get("parameters", {}),
            )
            for req in plan.modifier_requests
        ]

        baseline = self.noop_baseline or default_noop_baseline()

        pipeline_result = pipeline.run(
            source_path,
            requests,
            noop_baseline=baseline,
            output_apk=out_file,
            dry_run=False,
            work_dir=Path(work_dir) if work_dir else None,
        )

        sha_after = sha256_file(source_path)
        orig_preserved = sha_before == sha_after

        # Rollback check
        rollback_occurred = pipeline_result.rollback is not None
        rollback_success = (
            pipeline_result.rollback.get("success", False) if pipeline_result.rollback else None
        )

        # Build verification details
        verification_details: dict[str, Any] = {
            "pipeline_status": str(pipeline_result.status),
            "build_passed": pipeline_result.build_passed,
            "apk_verified": pipeline_result.apk_verified,
            "modification_verified": pipeline_result.modification_verified,
            "verification_matrix": (
                pipeline_result.verification_matrix.model_dump(mode="json")
                if pipeline_result.verification_matrix
                else None
            ),
        }

        # 5. Check if build and modification pipeline passed
        if (
            pipeline_result.status != PipelineStatus.VERIFIED
            or not out_file.exists()
            or not pipeline_result.modification_verified
        ):
            return RemediationExecutionResult(
                plan=plan,
                state=RemediationState.FAILED,
                approved=approved,
                output_apk_path=str(out_file) if out_file.exists() else None,
                output_apk_sha256=sha256_file(out_file) if out_file.exists() else None,
                original_apk_sha256_before=sha_before,
                original_apk_sha256_after=sha_after,
                original_apk_preserved=orig_preserved,
                pipeline_status=str(pipeline_result.status),
                build_passed=pipeline_result.build_passed,
                apk_verified=pipeline_result.apk_verified,
                verification_passed=False,
                verification_details=verification_details,
                errors=list(pipeline_result.failures) or ["Pipeline verification failed."],
                warnings=list(pipeline_result.warnings),
                rollback_occurred=rollback_occurred,
                rollback_success=rollback_success,
            )

        # 6. Post-Remediation Phase F Analysis
        pre_result = pre_analysis or PrivacyAnalysisService.analyze(source_path)
        post_result = PrivacyAnalysisService.analyze(out_file)

        # Pass parameters for specific resolution checks
        target_params: dict[str, str] = {}
        for req in plan.modifier_requests:
            target_params.update(req.get("parameters", {}))

        comparison = compare_privacy_before_after(
            before=pre_result,
            after=post_result,
            target_finding_id=plan.finding_id,
            remediation_id=plan.remediation_id,
            parameters=target_params,
        )

        # Classify final state based on target finding resolution
        target_res = comparison.target_finding.resolution
        if target_res == FindingResolution.REMEDIATED:
            final_state = RemediationState.VERIFIED
        elif target_res == FindingResolution.PARTIALLY_REMEDIATED:
            final_state = RemediationState.PARTIALLY_REMEDIATED
        elif target_res == FindingResolution.STILL_PRESENT:
            final_state = RemediationState.FAILED
        else:
            final_state = RemediationState.UNDETERMINED

        # If unexpected new privacy findings appeared, record warnings
        warnings = list(plan.warnings)
        if comparison.findings_introduced:
            intro_str = ", ".join(comparison.findings_introduced)
            warnings.append(f"New privacy findings observed post-remediation: {intro_str}")

        return RemediationExecutionResult(
            plan=plan,
            state=final_state,
            approved=approved,
            output_apk_path=str(out_file),
            output_apk_sha256=sha256_file(out_file),
            original_apk_sha256_before=sha_before,
            original_apk_sha256_after=sha_after,
            original_apk_preserved=orig_preserved,
            pipeline_status=str(pipeline_result.status),
            build_passed=pipeline_result.build_passed,
            apk_verified=pipeline_result.apk_verified,
            verification_passed=True,
            verification_details=verification_details,
            comparison=comparison,
            post_analysis=post_result,
            errors=[],
            warnings=warnings,
            limitations=list(comparison.limitations),
            rollback_occurred=rollback_occurred,
            rollback_success=rollback_success,
        )
