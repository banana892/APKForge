"""Unit tests — Configuration system."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from apkforge.core.config import (
    AnalysisSettings,
    APKForgeConfig,
    ExtractionLimits,
    LogLevel,
    PluginSettings,
    ReportFormat,
    ReportSettings,
    WorkspaceSettings,
    load_default_config,
)


class TestExtractionLimits:
    @pytest.mark.unit()
    def test_defaults_are_sane(self) -> None:
        limits = ExtractionLimits()
        assert limits.max_total_size_bytes > 0
        assert limits.max_single_file_bytes > 0
        assert limits.max_file_count > 0
        assert limits.max_recursion_depth >= 0

    @pytest.mark.unit()
    def test_single_must_not_exceed_total(self) -> None:
        with pytest.raises(ValidationError):
            ExtractionLimits(
                max_total_size_bytes=1024,
                max_single_file_bytes=2048,  # exceeds total
            )

    @pytest.mark.unit()
    def test_negative_values_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ExtractionLimits(max_total_size_bytes=-1)  # pyright: ignore[reportArgumentType]

    @pytest.mark.unit()
    def test_recursion_depth_limit(self) -> None:
        with pytest.raises(ValidationError):
            ExtractionLimits(max_recursion_depth=100)  # pyright: ignore[reportArgumentType]  # exceeds maximum of 16


class TestAPKForgeConfig:
    @pytest.mark.unit()
    def test_default_config_loads(self) -> None:
        cfg = load_default_config()
        assert isinstance(cfg, APKForgeConfig)

    @pytest.mark.unit()
    def test_default_log_level_is_info(self) -> None:
        cfg = load_default_config()
        assert cfg.log_level == LogLevel.INFO

    @pytest.mark.unit()
    def test_extraction_limits_present(self) -> None:
        cfg = load_default_config()
        assert isinstance(cfg.extraction, ExtractionLimits)

    @pytest.mark.unit()
    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            APKForgeConfig(nonexistent_field="value")  # type: ignore[call-arg]

    @pytest.mark.unit()
    def test_log_level_values(self) -> None:
        for level in LogLevel:
            cfg = APKForgeConfig(log_level=level)
            assert cfg.log_level == level


class TestAnalysisSettings:
    @pytest.mark.unit()
    def test_defaults(self) -> None:
        s = AnalysisSettings()
        assert s.enabled_modules == []
        assert s.timeout_seconds > 0
        assert s.treat_warnings_as_errors is False

    @pytest.mark.unit()
    def test_negative_timeout_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AnalysisSettings(timeout_seconds=-1)  # pyright: ignore[reportArgumentType]


class TestReportSettings:
    @pytest.mark.unit()
    def test_default_format(self) -> None:
        s = ReportSettings()
        assert s.default_format == ReportFormat.TEXT

    @pytest.mark.unit()
    def test_output_directory_none_by_default(self) -> None:
        s = ReportSettings()
        assert s.output_directory is None


class TestWorkspaceSettings:
    @pytest.mark.unit()
    def test_base_directory_is_path(self) -> None:
        s = WorkspaceSettings()
        from pathlib import Path

        assert isinstance(s.base_directory, Path)

    @pytest.mark.unit()
    def test_tilde_expansion(self) -> None:
        s = WorkspaceSettings(base_directory="~/apkforge_test")  # type: ignore[arg-type]
        assert "~" not in str(s.base_directory)


class TestPluginSettings:
    @pytest.mark.unit()
    def test_empty_plugin_directories_by_default(self) -> None:
        s = PluginSettings()
        assert s.plugin_directories == []
        assert s.disabled_plugins == []
