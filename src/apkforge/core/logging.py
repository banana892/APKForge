"""APKForge logging system.

Provides a single function, :func:`setup_logging`, which configures the root
``apkforge`` logger for the current session.

Design principles
-----------------
- All APKForge loggers live under the ``apkforge`` namespace so that library
  users can control verbosity without affecting their own logging.
- Rich is used for console output to give operators a readable, coloured log
  stream during interactive use.
- Sensitive data must never be passed to loggers directly.  Log only
  descriptive messages and safe identifiers (e.g. SHA-256 hashes, not raw
  binary data, not extracted secrets).
- Analysis operations must be traceable: each major step should emit an INFO
  or DEBUG log so that failures can be located post-hoc from log files.

Usage::

    from apkforge.core.logging import setup_logging, get_logger
    setup_logging(level="DEBUG")

    log = get_logger(__name__)
    log.info("Starting analysis", extra={"apk": "com.example.app"})
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

__all__ = ["APKFORGE_LOGGER_NAME", "get_logger", "setup_logging"]

APKFORGE_LOGGER_NAME = "apkforge"

_console = Console(stderr=True)


def setup_logging(
    level: str | int = logging.INFO,
    *,
    rich: bool = True,
    propagate: bool = False,
) -> logging.Logger:
    """Configure the ``apkforge`` logger for this session.

    This function is idempotent: calling it multiple times with the same
    arguments is safe (handlers are replaced, not duplicated).

    Args:
        level: Log level name (e.g. ``"DEBUG"``, ``"INFO"``) or integer
            constant.  Defaults to ``INFO``.
        rich: Use Rich's coloured handler for console output.  Set to
            ``False`` to get plain text (useful in CI or when piping output).
        propagate: Whether the ``apkforge`` logger propagates to the root
            logger.  Defaults to ``False`` to avoid duplicate output when the
            caller has already configured logging.

    Returns:
        logging.Logger: The configured ``apkforge`` root logger.
    """
    logger = logging.getLogger(APKFORGE_LOGGER_NAME)

    # Remove any existing handlers to avoid duplication on re-initialisation.
    logger.handlers.clear()

    if isinstance(level, str):
        numeric_level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
    else:
        numeric_level = level

    logger.setLevel(numeric_level)
    logger.propagate = propagate

    if rich:
        handler: logging.Handler = RichHandler(
            console=_console,
            rich_tracebacks=True,
            tracebacks_show_locals=False,  # Never show locals: may contain APK data
            show_path=numeric_level <= logging.DEBUG,
            markup=True,
            log_time_format="[%X]",
        )
        fmt = "%(message)s"
    else:
        handler = logging.StreamHandler()
        fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"

    handler.setLevel(numeric_level)
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the ``apkforge`` namespace.

    Args:
        name: Typically ``__name__`` of the calling module.  If *name* already
            starts with ``apkforge``, it is used as-is; otherwise it is
            prefixed so that all APKForge loggers remain under the same
            namespace.

    Returns:
        logging.Logger: A configured child logger.

    Example::

        log = get_logger(__name__)
        log.debug("Loaded %d entries", count)
    """
    if name.startswith(APKFORGE_LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{APKFORGE_LOGGER_NAME}.{name}")
