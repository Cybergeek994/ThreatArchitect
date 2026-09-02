"""In-memory registry over a normalized ASVS control catalog snapshot."""

from __future__ import annotations

from threatmodeler.contracts.control_catalog import AsvsControlCatalogSnapshot, ControlRecord
from threatmodeler.errors import ConfigurationError


class AsvsControlRegistry:
    """Resolve and validate ASVS control identifiers from one snapshot."""

    def __init__(self, snapshot: AsvsControlCatalogSnapshot) -> None:
        if not snapshot.controls:
            raise ConfigurationError(
                "ASVS control registry requires at least one control",
                error_code="ASVS_REGISTRY_EMPTY",
                retryable=False,
                context={},
            )
        self._snapshot = snapshot
        self._by_id = {control.id: control for control in snapshot.controls}
        self._by_short_id = {control.short_id: control for control in snapshot.controls}

    @property
    def snapshot(self) -> AsvsControlCatalogSnapshot:
        """Return the underlying immutable snapshot."""
        return self._snapshot

    def contains(self, control_id: str) -> bool:
        """Return whether ``control_id`` matches a canonical id or short id."""
        return control_id in self._by_id or control_id in self._by_short_id

    def resolve_id(self, control_id: str) -> str | None:
        """Return the canonical id for ``control_id`` when recognized."""
        if control_id in self._by_id:
            return control_id
        record = self._by_short_id.get(control_id)
        return record.id if record is not None else None

    def get(self, control_id: str) -> ControlRecord | None:
        """Return a control record by canonical or short identifier."""
        record = self._by_id.get(control_id)
        if record is not None:
            return record
        return self._by_short_id.get(control_id)

    def all_controls(self) -> tuple[ControlRecord, ...]:
        """Return every catalogued control in snapshot order."""
        return self._snapshot.controls
