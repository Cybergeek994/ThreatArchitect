"""Tests for logging configuration helpers."""

from io import StringIO

from threatmodeler.logging_config.configure import configure_logging
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.shared.constants import LogLevel


class TestConfigureLoggingPositive:
    """Verify configure_logging returns an isolated logger factory."""

    def test_configure_logging_returns_standard_logger_factory(self) -> None:
        stream = StringIO()
        factory = configure_logging(level=LogLevel.WARNING, stream=stream)

        assert isinstance(factory, StandardLoggerFactory)
        logger = factory.create("coverage.configure")
        logger.warning("configured", context={"enabled": True})

        assert '"level":"WARNING"' in stream.getvalue()
