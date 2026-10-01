"""Null-object factory used when construction journaling is disabled."""

from pathlib import Path

from threatmodeler.infrastructure.journal.null_construction_journal import NullConstructionJournal


class NullConstructionJournalFactory:
    """Create no-op journals while preserving the journal-factory port."""

    def open(self, journal_directory: Path) -> NullConstructionJournal:
        """Open a journal that discards every event.

        Args:
            journal_directory: Unused output directory retained for port compatibility.

        Returns:
            Null-object journal.
        """
        del journal_directory
        return NullConstructionJournal()
