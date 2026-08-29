"""Structured logging ports."""

from typing import Protocol


class StructuredLogger(Protocol):
    """Define structured application event logging without global logger state."""

    def debug(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit a debug event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        ...

    def info(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an informational event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        ...

    def warning(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit a warning event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        ...

    def error(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an error event.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        ...

    def exception(self, event: str, *, context: dict[str, object] | None = None) -> None:
        """Emit an error event including the active exception.

        Args:
            event: Stable event name or human-readable message.
            context: Optional structured values associated with the event.
        """
        ...


class LoggerFactory(Protocol):
    """Define creation of isolated structured loggers for named components."""

    def create(self, name: str) -> StructuredLogger:
        """Create and return a logger for a named application component.

        Args:
            name: Component name included in emitted records.

        Returns:
            Isolated structured logger.
        """
        ...
