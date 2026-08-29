"""Logging factory construction."""

from typing import TextIO

from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.shared.constants import LogLevel


def configure_logging(
    level: LogLevel = LogLevel.INFO,
    stream: TextIO | None = None,
) -> StandardLoggerFactory:
    """Create a logger factory without mutating global logging configuration.

    Args:
        level: Minimum log level applied to newly created loggers.
        stream: Optional text stream receiving JSON log records.

    Returns:
        Factory that creates isolated structured loggers.
    """
    return StandardLoggerFactory(level=level, stream=stream)
