"""Port for collaborators that accept a per-run construction journal."""

from typing import Protocol, runtime_checkable

from threatmodeler.ports.construction_journal import ConstructionJournal


@runtime_checkable
class ConstructionJournalReceiver(Protocol):
    """Bind a per-run construction journal onto a generation collaborator."""

    def bind_journal(self, journal: ConstructionJournal | None) -> None:
        """Attach or clear the construction journal for the current run.

        Args:
            journal: Journal for the current run, or ``None`` to clear it.
        """
        ...
