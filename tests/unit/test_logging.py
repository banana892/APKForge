"""Unit tests — Logging system."""

from __future__ import annotations

import logging

import pytest

from apkforge.core.logging import APKFORGE_LOGGER_NAME, get_logger, setup_logging


class TestSetupLogging:
    @pytest.mark.unit()
    def test_returns_logger(self) -> None:
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)

    @pytest.mark.unit()
    def test_logger_name(self) -> None:
        logger = setup_logging()
        assert logger.name == APKFORGE_LOGGER_NAME

    @pytest.mark.unit()
    def test_debug_level(self) -> None:
        logger = setup_logging(level="DEBUG")
        assert logger.level == logging.DEBUG

    @pytest.mark.unit()
    def test_error_level(self) -> None:
        logger = setup_logging(level="ERROR")
        assert logger.level == logging.ERROR

    @pytest.mark.unit()
    def test_idempotent(self) -> None:
        setup_logging(level="INFO")
        logger = setup_logging(level="INFO")
        # Should not accumulate handlers
        assert len(logger.handlers) == 1

    @pytest.mark.unit()
    def test_plain_handler(self) -> None:
        logger = setup_logging(rich=False)
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)


class TestGetLogger:
    @pytest.mark.unit()
    def test_child_logger_with_apkforge_prefix(self) -> None:
        logger = get_logger("apkforge.core.config")
        assert logger.name == "apkforge.core.config"

    @pytest.mark.unit()
    def test_child_logger_without_prefix_gets_prefixed(self) -> None:
        logger = get_logger("some.external.module")
        assert logger.name.startswith(APKFORGE_LOGGER_NAME)

    @pytest.mark.unit()
    def test_dunder_name_usage(self) -> None:
        # Typical usage pattern: get_logger(__name__)
        logger = get_logger(__name__)
        assert isinstance(logger, logging.Logger)
