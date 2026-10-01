"""No-op construction journal used when journaling is disabled."""

from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal


class NullConstructionJournal(DiscardingConstructionJournal):
    """Infrastructure alias for the domain null-object journal."""
