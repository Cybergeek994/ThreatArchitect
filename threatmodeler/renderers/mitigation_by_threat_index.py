"""Reverse index from threat ids to linked mitigations for report dossiers."""

from __future__ import annotations

from threatmodeler.contracts.artifacts.governance import Mitigation, MitigationPlan


class MitigationByThreatIndex:
    """O(1) lookup of mitigations linked to a threat id."""

    def __init__(self, plan: MitigationPlan) -> None:
        index: dict[str, tuple[Mitigation, ...]] = {}
        for mitigation in plan.mitigations:
            for threat_id in mitigation.threat_ids:
                existing = index.get(threat_id, ())
                index[threat_id] = (*existing, mitigation)
        self._index = index

    @classmethod
    def empty(cls) -> MitigationByThreatIndex:
        """Return an index with no mitigations."""
        instance = cls.__new__(cls)
        instance._index = {}
        return instance

    def for_threat(self, threat_id: str) -> tuple[Mitigation, ...]:
        """Return mitigations that list ``threat_id`` in ``threat_ids``."""
        return self._index.get(threat_id, ())
