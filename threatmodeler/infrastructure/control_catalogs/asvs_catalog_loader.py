"""Load OWASP ASVS flat exports and normalized catalog snapshots."""

from __future__ import annotations

import json
from importlib import resources

from threatmodeler.config.settings import Settings
from threatmodeler.contracts.control_catalog import AsvsControlCatalogSnapshot, AsvsFlatDocument
from threatmodeler.domain.control_catalogs.asvs_flat_parser import parse_flat_document
from threatmodeler.infrastructure.control_catalogs.asvs_catalog_cache import AsvsCatalogCache
from threatmodeler.ports.control_catalog_loader import ControlCatalogLoader
from threatmodeler.shared.constants import AsvsCatalogFetchUrl, AsvsFrameworkVersion, PackagedDataFile


class PackagedAsvsCatalogLoader(ControlCatalogLoader):
    """Load the packaged ASVS flat JSON export."""

    def __init__(
        self,
        *,
        framework_version: str = AsvsFrameworkVersion.V5_0_0,
    ) -> None:
        self._framework_version = framework_version

    def load(self) -> AsvsControlCatalogSnapshot:
        """Return the normalized snapshot from the packaged flat export."""
        return self.load_snapshot()

    def load_flat_document(self) -> AsvsFlatDocument:
        """Read and validate the packaged flat ASVS export."""
        payload = resources.files(PackagedDataFile.PACKAGE).joinpath(
            PackagedDataFile.OWASP_ASVS_FLAT
        )
        raw = json.loads(payload.read_text(encoding="utf-8"))
        return AsvsFlatDocument.model_validate(raw)

    def load_snapshot(self) -> AsvsControlCatalogSnapshot:
        """Parse the packaged flat export into a normalized snapshot."""
        document = self.load_flat_document()
        return parse_flat_document(
            document,
            framework_version=self._framework_version,
            source_uri=f"package://{PackagedDataFile.PACKAGE}/{PackagedDataFile.OWASP_ASVS_FLAT}",
        )


class AsvsCatalogLoaderFacade(ControlCatalogLoader):
    """Load ASVS snapshots from cache or packaged flat data."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._packaged = PackagedAsvsCatalogLoader(
            framework_version=settings.control_framework_version,
        )
        self._cache = AsvsCatalogCache(
            settings.asvs_catalog_cache_dir.expanduser(),
            ttl_hours=settings.asvs_catalog_ttl_hours,
        )

    def load(self) -> AsvsControlCatalogSnapshot:
        """Return a cached snapshot or rebuild it from the packaged flat export."""
        cached = self._cache.read_if_fresh()
        if cached is not None:
            return cached
        snapshot = self._packaged.load_snapshot()
        self._cache.write(snapshot)
        return snapshot

    @property
    def default_fetch_url(self) -> str:
        """Return the configured remote ASVS flat export URL."""
        return self._settings.asvs_catalog_fetch_url or AsvsCatalogFetchUrl.V5_0_0_FLAT
