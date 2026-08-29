"""Null-object journal used when a caller does not bind a real journal."""

from threatmodeler.contracts.tool_calling import JournalEvent


class DiscardingConstructionJournal:
    """Discard construction events while preserving the journal port."""

    def record(self, event: JournalEvent) -> None:
        """Ignore a construction event.

        Args:
            event: Journal event that would otherwise be persisted.
        """
        del event

    def close(self) -> None:
        """No-op close for the discarded journal."""
        return None
