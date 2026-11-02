"""Unified analysis: Inspection -> Privacy -> Security, as one call.

Shared by ``apkforge analyze`` and the Phase 9 GUI so neither owns the orchestration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.inspection.engine import InspectionEngine
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.engine import SecurityEngine
from apkforge.security.models import FullAnalysisResult

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.core.config import APKForgeConfig
    from apkforge.inspection.models import InspectionResult
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import SecurityResult

__all__ = ["run_full_analysis"]


def run_full_analysis(
    apk: Path, cfg: APKForgeConfig, *, keep_workspace: bool = False
) -> tuple[FullAnalysisResult, InspectionResult, PrivacyResult, SecurityResult]:
    insp_res = InspectionEngine(cfg).inspect(apk, keep_workspace=keep_workspace)
    priv_res = PrivacyEngine(config=cfg).analyze(insp_res)
    sec_res = SecurityEngine(config=cfg).analyze(insp_res, privacy=priv_res)

    total_sdks = (
        priv_res.advertising.total_advertising_sdks
        + priv_res.analytics.total_analytics_sdks
        + priv_res.trackers.total_trackers
        + priv_res.telemetry.total_telemetry_sdks
    )
    full_result = FullAnalysisResult(
        status=sec_res.status,
        package_name=sec_res.package_name,
        version_name=sec_res.version_name,
        version_code=sec_res.version_code,
        inspection_status=insp_res.status,
        privacy_status=priv_res.status,
        security_status=sec_res.security_status,
        inspection_summary={
            "total_files": insp_res.inventory.total_file_count,
            "dex_files": insp_res.inventory.dex_count,
            "native_libraries": insp_res.inventory.native_library_count,
        },
        privacy_summary={
            "declared_permissions": len(priv_res.permissions.declared_permissions),
            "detected_sdks": total_sdks,
            "total_endpoints": priv_res.endpoints.total_endpoints,
        },
        security_summary=sec_res.summary,
        security_findings=sec_res.findings,
        warnings=sec_res.warnings,
        errors=sec_res.errors,
        limitations=sec_res.limitations,
    )
    return full_result, insp_res, priv_res, sec_res
