"""Programmatic API service for APKForge privacy and tracker analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.privacy.cross_check import compare_privacy_with_security
from apkforge.privacy.engine import PrivacyEngine

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.core.config import APKForgeConfig
    from apkforge.inspection.models import InspectionResult
    from apkforge.intake import AndroidPackage
    from apkforge.privacy.cross_check import PhaseBComparisonResult
    from apkforge.privacy.models import PrivacyReport, PrivacyResult
    from apkforge.security.models import SecurityResult


class PrivacyAnalysisService:
    """Dedicated programmatic service for privacy and tracker analysis.

    Provides high-level programmatic access to the privacy intelligence layer,
    returning structured findings with inspectable provenance.
    """

    def __init__(
        self,
        config: APKForgeConfig | None = None,
        custom_rules_dir: Path | None = None,
    ) -> None:
        self._config = config
        self._engine = PrivacyEngine(config=config, custom_rules_dir=custom_rules_dir)

    @classmethod
    def analyze(
        cls,
        apk_or_inspection: Path | str | InspectionResult,
        *,
        config: APKForgeConfig | None = None,
        package: AndroidPackage | None = None,
        keep_workspace: bool = False,
        custom_rules_dir: Path | None = None,
    ) -> PrivacyResult:
        """Convenience class method to analyze an APK or InspectionResult directly."""
        service = cls(config=config, custom_rules_dir=custom_rules_dir)
        return service.run_analysis(
            apk_or_inspection,
            package=package,
            keep_workspace=keep_workspace,
        )

    def run_analysis(
        self,
        apk_or_inspection: Path | str | InspectionResult,
        *,
        package: AndroidPackage | None = None,
        keep_workspace: bool = False,
    ) -> PrivacyResult:
        """Execute privacy analysis and return a structured PrivacyResult."""
        return self._engine.analyze(
            apk_or_inspection,
            package=package,
            keep_workspace=keep_workspace,
        )

    @staticmethod
    def generate_report(result: PrivacyResult) -> PrivacyReport:
        """Generate a structured, multi-section PrivacyReport from a PrivacyResult."""
        return result.to_report()

    @staticmethod
    def compare_with_security(
        privacy_result: PrivacyResult,
        security_result: SecurityResult,
    ) -> PhaseBComparisonResult:
        """Cross-check Phase F privacy findings against Phase B security findings."""
        return compare_privacy_with_security(privacy_result, security_result)
