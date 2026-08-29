"""Port for opening a construction journal beneath a caller-supplied directory."""

from pathlib import Path
from typing import Protocol

from threatmodeler.ports.construction_journal import ConstructionJournal


class ConstructionJournalFactory(Protocol):
    """Create a construction journal bound to one output journal directory."""

    def open(self, journal_directory: Path) -> ConstructionJournal:
        """Open a journal that writes beneath ``journal_directory``.

        Args:
            journal_directory: Directory for JSONL traces, manifest, and trust summary.

        Returns:
            Journal that records events for the current application run.
        """
        ...
