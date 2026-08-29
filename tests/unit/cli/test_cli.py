"""CLI acceptance tests."""

from io import StringIO
from unittest.mock import Mock

import pytest
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.shared.constants import LogLevel
from typer.testing import CliRunner


@pytest.fixture
def error_handler() -> CliErrorHandler:
    """Build an isolated error handler for CLI tests."""
    logger = StandardLoggerFactory(LogLevel.INFO, StringIO()).create("test.cli")
    return CliErrorHandler(logger)


class TestCliPositive:
    """Verify supported inputs and successful behavior."""

    def test_help_command(self, error_handler: CliErrorHandler) -> None:
        factories = [Mock() for _ in range(5)]
        app = create_app(
            factories[0],
            factories[1],
            factories[2],
            factories[3],
            factories[4],
            error_handler,
        )
        result = CliRunner().invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "Agent-driven architecture threat modeling" in result.stdout
        assert "--fail-on-missing-information" in result.stdout
        for factory in factories:
            factory.assert_not_called()


class TestCliMainEntryPoint:
    """Verify the production CLI entry point."""

    def test_main_invokes_build_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        invoked = Mock()
        monkeypatch.setattr("threatmodeler.cli.main.build_app", Mock(return_value=invoked))

        from threatmodeler.cli.main import main

        main()

        invoked.assert_called_once()
