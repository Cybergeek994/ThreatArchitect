"""CLI boundary handling for expected and unexpected exceptions."""

import json
from collections.abc import Callable

import typer

from threatmodeler.errors.base import ThreatModelerError
from threatmodeler.ports.logger import StructuredLogger


class CliErrorHandler:
    """Translate application exceptions into safe CLI output and structured logs."""

    def __init__(self, logger: StructuredLogger) -> None:
        self._logger = logger

    def execute(self, operation: Callable[[], str], *, debug: bool) -> str:
        """Execute a CLI operation under the application error policy.

        Args:
            operation: Deferred CLI operation returning text for standard output.
            debug: Whether expected context and unexpected exception details may be shown.

        Returns:
            Text returned by a successful operation.

        Raises:
            typer.Exit: If the operation raises an expected or unexpected error.
        """
        try:
            return operation()
        except ThreatModelerError as error:
            self._logger.error("expected_application_error", context=error.to_log_context())
            self._show_expected_error(error, debug=debug)
        except Exception as error:
            log_context: dict[str, object] = {"error_type": type(error).__name__}
            if debug:
                log_context["message"] = str(error)
                self._logger.exception(
                    "unexpected_application_error",
                    context=log_context,
                )
            else:
                self._logger.error(
                    "unexpected_application_error",
                    context=log_context,
                )
            self._show_unexpected_error(error, debug=debug)
        raise AssertionError("CLI error handling must terminate execution")

    def _show_expected_error(self, error: ThreatModelerError, *, debug: bool) -> None:
        code = f" [{error.error_code}]" if error.error_code is not None else ""
        details = ""
        if debug and error.context is not None:
            details = f" context={json.dumps(error.context, default=str, sort_keys=True)}"
        typer.echo(f"error{code}: {error.message}{details}", err=True)
        raise typer.Exit(code=1)

    def _show_unexpected_error(self, error: Exception, *, debug: bool) -> None:
        if debug:
            message = f"unexpected error: {type(error).__name__}: {error}"
        else:
            message = "unexpected error: an internal error occurred; use --debug for details"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)
