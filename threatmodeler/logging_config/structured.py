"""Structured standard-library logging adapters."""

import json
import logging
from datetime import UTC, datetime
from typing import TextIO

from threatmodeler.ports.logger import StructuredLogger
from threatmodeler.shared.constants import LogLevel


class JsonLogFormatter(logging.Formatter):
    """Format log records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a log record and its structured context.

        Args:
            record: Standard-library log record to serialize.

        Returns:
            Compact JSON object terminated by the handler when emitted.
        """
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        context = getattr(record, "structured_context", None)
        if context:
            payload["context"] = context
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class StandardStructuredLogger:
    """Structured logger backed by an isolated standard-library logger."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def debug(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit a debug event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        self._logger.debug(event, extra=self._extra(context))

    def info(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an informational event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        self._logger.info(event, extra=self._extra(context))

    def warning(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit a warning event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        self._logger.warning(event, extra=self._extra(context))

    def error(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an error event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        self._logger.error(event, extra=self._extra(context))

    def exception(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an error event including the active exception.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        self._logger.exception(event, extra=self._extra(context))

    def _extra(self, context: dict[str, object] | None) -> dict[str, object]:
        return {"structured_context": dict(context) if context is not None else {}}


class StandardLoggerFactory:
    """Create independent JSON loggers without module-level logger instances."""

    def __init__(self, level: LogLevel, stream: TextIO | None = None) -> None:
        self._level = level
        self._stream = stream

    def create(self, name: str) -> StructuredLogger:
        """Create and configure a new isolated logger.

        Args:
            name: Component name included in every emitted record.

        Returns:
            Structured logger with an independent JSON handler.
        """
        logger = logging.Logger(name=name, level=self._level.value)
        handler = logging.StreamHandler(self._stream)
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False
        return StandardStructuredLogger(logger)
