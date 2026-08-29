"""Port for durable per-run artifact construction journals."""

from typing import Protocol

from threatmodeler.contracts.tool_calling import JournalEvent


class ConstructionJournal(Protocol):
    """Record construction events for later debugging and trust review."""

    def record(self, event: JournalEvent) -> None:
        """Persist one construction event.

        Args:
            event: Validated journal event to append.
        """
        ...

    def close(self) -> None:
        """Flush aggregate manifest and trust-summary artifacts."""
        ...
