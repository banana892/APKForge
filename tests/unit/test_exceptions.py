"""Unit tests — Exception hierarchy."""

from __future__ import annotations

import pytest

from apkforge.core.exceptions import (
    AnalysisError,
    APKForgeError,
    BuildError,
    ConfigurationError,
    ExtractionError,
    InputError,
    ModificationError,
    ParsingError,
    PluginError,
    PluginInitError,
    PluginNotFoundError,
    VerificationError,
    WorkspaceError,
)


class TestAPKForgeError:
    @pytest.mark.unit()
    def test_base_error_is_exception(self) -> None:
        err = APKForgeError("test")
        assert isinstance(err, Exception)

    @pytest.mark.unit()
    def test_message_preserved(self) -> None:
        err = APKForgeError("something went wrong")
        assert err.message == "something went wrong"
        assert str(err) == "something went wrong"

    @pytest.mark.unit()
    def test_context_appended_to_str(self) -> None:
        err = APKForgeError("test", context="my-module")
        assert "my-module" in str(err)

    @pytest.mark.unit()
    def test_context_optional(self) -> None:
        err = APKForgeError("test")
        assert err.context is None


class TestHierarchy:
    """All specific exceptions must be subclasses of APKForgeError."""

    @pytest.mark.unit()
    @pytest.mark.parametrize(
        "exc_cls",
        [
            InputError,
            ConfigurationError,
            AnalysisError,
            ExtractionError,
            ParsingError,
            PluginError,
            PluginNotFoundError,
            ModificationError,
            BuildError,
            VerificationError,
            WorkspaceError,
        ],
    )
    def test_is_subclass_of_apkforge_error(self, exc_cls: type) -> None:
        assert issubclass(exc_cls, APKForgeError)

    @pytest.mark.unit()
    def test_extraction_error_is_analysis_error(self) -> None:
        assert issubclass(ExtractionError, AnalysisError)

    @pytest.mark.unit()
    def test_parsing_error_is_analysis_error(self) -> None:
        assert issubclass(ParsingError, AnalysisError)

    @pytest.mark.unit()
    def test_plugin_not_found_is_plugin_error(self) -> None:
        assert issubclass(PluginNotFoundError, PluginError)

    @pytest.mark.unit()
    def test_plugin_init_error_is_plugin_error(self) -> None:
        assert issubclass(PluginInitError, PluginError)


class TestPluginNotFoundError:
    @pytest.mark.unit()
    def test_plugin_name_stored(self) -> None:
        err = PluginNotFoundError("analysis.dex")
        assert err.plugin_name == "analysis.dex"

    @pytest.mark.unit()
    def test_message_contains_plugin_name(self) -> None:
        err = PluginNotFoundError("analysis.dex")
        assert "analysis.dex" in str(err)


class TestPluginInitError:
    @pytest.mark.unit()
    def test_attributes(self) -> None:
        err = PluginInitError("my.plugin", "missing dependency")
        assert err.plugin_name == "my.plugin"
        assert err.reason == "missing dependency"
        assert "my.plugin" in str(err)


class TestExceptionCatchPatterns:
    """Verify that exception hierarchies allow sane catch patterns."""

    @pytest.mark.unit()
    def test_catch_analysis_catches_extraction(self) -> None:
        with pytest.raises(AnalysisError):
            raise ExtractionError("zip bomb detected")

    @pytest.mark.unit()
    def test_catch_apkforge_catches_all(self) -> None:
        errors = [
            InputError("bad input"),
            ConfigurationError("bad config"),
            AnalysisError("analysis failed"),
            ExtractionError("extraction failed"),
            ParsingError("parse failed"),
            PluginError("plugin error"),
            PluginNotFoundError("missing.plugin"),
            PluginInitError("bad.plugin", "init failed"),
            ModificationError("mod failed"),
            BuildError("build failed"),
            VerificationError("verify failed"),
            WorkspaceError("workspace failed"),
        ]
        for err in errors:
            with pytest.raises(APKForgeError):
                raise err

    @pytest.mark.unit()
    def test_failed_analysis_must_not_be_clean(self) -> None:
        """
        Security invariant: an AnalysisError must never be silently swallowed
        and turned into a 'clean' result.  This test documents the contract.
        """
        from apkforge.core.models import AnalysisStatus

        # Simulate the invariant: code catching AnalysisError must use FAILED
        try:
            raise AnalysisError("DEX parsing exploded")
        except AnalysisError:
            status = AnalysisStatus.FAILED  # correct
            assert status != AnalysisStatus.COMPLETE
