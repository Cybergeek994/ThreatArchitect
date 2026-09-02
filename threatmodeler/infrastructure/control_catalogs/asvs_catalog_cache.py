"""Disk cache for normalized ASVS catalog snapshots."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from threatmodeler.contracts.control_catalog import AsvsControlCatalogSnapshot
from threatmodeler.errors import ConfigurationError


class AsvsCatalogCache:
    """Persist and reload ASVS catalog snapshots from a local directory."""

    SNAPSHOT_FILENAME = "asvs-control-catalog.snapshot.json"

    def __init__(self, cache_dir: Path, *, ttl_hours: int = 168) -> None:
        self._cache_dir = cache_dir
        self._ttl = timedelta(hours=ttl_hours)

    @property
    def snapshot_path(self) -> Path:
        """Return the path to the cached snapshot file."""
        return self._cache_dir / self.SNAPSHOT_FILENAME

    def read_if_fresh(self) -> AsvsControlCatalogSnapshot | None:
        """Load a cached snapshot when present and within TTL."""
        path = self.snapshot_path
        if not path.is_file():
            return None
        snapshot = AsvsControlCatalogSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
        fetched_at = datetime.fromisoformat(snapshot.provenance.fetched_at)
        if datetime.now(tz=UTC) - fetched_at > self._ttl:
            return None
        return snapshot

    def write(self, snapshot: AsvsControlCatalogSnapshot) -> None:
        """Persist ``snapshot`` to the cache directory."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")

    def read_or_raise(self) -> AsvsControlCatalogSnapshot:
        """Load a cached snapshot or raise when missing."""
        if not self.snapshot_path.is_file():
            raise ConfigurationError(
                "ASVS catalog snapshot is missing from cache",
                error_code="ASVS_CACHE_MISS",
                retryable=False,
                context={"path": str(self.snapshot_path)},
            )
        return AsvsControlCatalogSnapshot.model_validate_json(
            self.snapshot_path.read_text(encoding="utf-8")
        )
