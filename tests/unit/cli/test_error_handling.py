"""Tests for application errors, structured logging, and CLI safety."""

import json
from io import StringIO
from unittest.mock import Mock

import pytest
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.errors import (
    AgentProviderError,
    ArtifactStorageError,
    ConfigurationError,
    ConfluenceClientError,
    ThreatModelerError,
)
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.shared.constants import LogLevel
from typer.testing import CliRunner


@pytest.fixture
def error_handler() -> CliErrorHandler:
    """Build a CLI error handler with an isolated structured logger."""
    logger = StandardLoggerFactory(LogLevel.DEBUG, StringIO()).create("test.cli")
    return CliErrorHandler(logger)


@pytest.fixture
def unused_factories() -> list[Mock]:
    """Return standard mocks for CLI workflows outside the test scope."""
    return [Mock() for _ in range(4)]


class TestErrorHandlingPositive:
    """Verify supported inputs and successful behavior."""

    def test_logger_factory_emits_structured_json(self) -> None:
        stream = StringIO()
        logger = StandardLoggerFactory(LogLevel.INFO, stream).create("test.component")

        logger.error("artifact_save_failed", context={"artifact_id": "report-1"})

        payload = json.loads(stream.getvalue())
        assert payload["level"] == "ERROR"
        assert payload["logger"] == "test.component"
        assert payload["event"] == "artifact_save_failed"
        assert payload["context"] == {"artifact_id": "report-1"}

    def test_logger_emits_debug_warning_and_exception_events(self) -> None:
        stream = StringIO()
        logger = StandardLoggerFactory(LogLevel.DEBUG, stream).create("test.component")

        logger.debug("debug_event", context={"step": 1})
        logger.warning("warning_event", context={"step": 2})
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("exception_event", context={"step": 3})

        payloads = [json.loads(line) for line in stream.getvalue().splitlines()]
        assert payloads[0]["level"] == "DEBUG"
        assert payloads[1]["level"] == "WARNING"
        assert payloads[2]["level"] == "ERROR"
        assert "exception" in payloads[2]

    def test_logger_emits_info_events(self) -> None:
        stream = StringIO()
        logger = StandardLoggerFactory(LogLevel.INFO, stream).create("test.component")

        logger.info("info_event", context={"step": 1})

        payload = json.loads(stream.getvalue())
        assert payload["level"] == "INFO"
        assert payload["event"] == "info_event"

    def test_logger_omits_context_when_none(self) -> None:
        stream = StringIO()
        logger = StandardLoggerFactory(LogLevel.INFO, stream).create("test.component")

        logger.error("artifact_save_failed")

        payload = json.loads(stream.getvalue())
        assert "context" not in payload


class TestErrorHandlingErrors:
    """Verify dependency and application failures remain controlled."""

    @pytest.mark.parametrize(
        "error_type",
        [ConfigurationError, ConfluenceClientError, AgentProviderError],
    )

    def test_custom_errors_expose_structured_metadata(
        self,
        error_type: type[ThreatModelerError],
    ) -> None:
        error = error_type(
            "operation failed",
            error_code="TEST_001",
            retryable=True,
            context={"document_id": "42"},
        )

        assert str(error) == "operation failed"
        assert error.message == "operation failed"
        assert error.error_code == "TEST_001"
        assert error.retryable is True
        assert error.context == {"document_id": "42"}
        assert error.to_log_context()["error_type"] == error_type.__name__

    @pytest.mark.parametrize(
        "error",
        [
            ConfigurationError("invalid settings", error_code="CONFIG_INVALID"),
            ConfluenceClientError("page unavailable", retryable=True),
            ArtifactStorageError("cannot write artifact", context={"path": "output"}),
        ],
    )

    def test_expected_errors_produce_clean_cli_messages(
        self,
        error: ThreatModelerError,
        unused_factories: list[Mock],
        error_handler: CliErrorHandler,
    ) -> None:
        failing_ingestion_factory = Mock(side_effect=error)
        app = create_app(
            failing_ingestion_factory,
            unused_factories[0],
            unused_factories[1],
            unused_factories[2],
            unused_factories[3],
            error_handler,
        )

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", "failure.html", "--output", "out"],
        )

        assert result.exit_code == 1
        assert error.message in result.stderr
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        failing_ingestion_factory.assert_called_once_with("failure.html")
        for factory in unused_factories:
            factory.assert_not_called()

    def test_unexpected_error_is_hidden_without_debug_mode(
        self,
        unused_factories: list[Mock],
        error_handler: CliErrorHandler,
    ) -> None:
        app = create_app(
            Mock(side_effect=RuntimeError("sensitive implementation detail")),
            unused_factories[0],
            unused_factories[1],
            unused_factories[2],
            unused_factories[3],
            error_handler,
        )

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", "failure.html", "--output", "out"],
        )

        assert result.exit_code == 1
        assert "internal error occurred" in result.stderr
        assert "sensitive implementation detail" not in result.stderr
        assert "Traceback" not in result.stderr

    def test_debug_mode_shows_unexpected_error_details(
        self,
        unused_factories: list[Mock],
        error_handler: CliErrorHandler,
    ) -> None:
        app = create_app(
            Mock(side_effect=RuntimeError("diagnostic detail")),
            unused_factories[0],
            unused_factories[1],
            unused_factories[2],
            unused_factories[3],
            error_handler,
        )

        result = CliRunner().invoke(
            app,
            ["--debug", "ingest", "--input", "failure.html", "--output", "out"],
        )

        assert result.exit_code == 1
        assert "RuntimeError: diagnostic detail" in result.stderr
        assert "Traceback" not in result.stderr

    def test_debug_mode_shows_expected_error_context(
        self,
        unused_factories: list[Mock],
        error_handler: CliErrorHandler,
    ) -> None:
        error = ConfigurationError(
            "invalid settings",
            error_code="CONFIG_INVALID",
            context={"field": "agent_provider_name"},
        )
        app = create_app(
            Mock(side_effect=error),
            unused_factories[0],
            unused_factories[1],
            unused_factories[2],
            unused_factories[3],
            error_handler,
        )

        result = CliRunner().invoke(
            app,
            ["--debug", "ingest", "--input", "failure.html", "--output", "out"],
        )

        assert result.exit_code == 1
        assert "[CONFIG_INVALID]" in result.stderr
        assert '"field": "agent_provider_name"' in result.stderr

    def test_error_handler_assertion_when_exit_is_not_raised(
        self,
        error_handler: CliErrorHandler,
    ) -> None:
        error_handler._show_expected_error = Mock(return_value=None)  # type: ignore[method-assign]

        with pytest.raises(AssertionError, match="CLI error handling must terminate execution"):
            error_handler.execute(
                Mock(side_effect=ConfigurationError("invalid", error_code="CONFIG_INVALID")),
                debug=False,
            )
