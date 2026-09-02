"""Factory for ASVS control registries."""

from __future__ import annotations

from threatmodeler.config.settings import Settings
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.infrastructure.control_catalogs.asvs_catalog_loader import (
    AsvsCatalogLoaderFacade,
    PackagedAsvsCatalogLoader,
)
from threatmodeler.ports.control_catalog_loader import ControlCatalogLoader


class AsvsControlRegistryFactory:
    """Create ``AsvsControlRegistry`` instances from catalog loaders."""

    def __init__(self, loader: ControlCatalogLoader) -> None:
        self._loader = loader

    @classmethod
    def packaged(cls) -> AsvsControlRegistryFactory:
        """Return a factory backed by the packaged ASVS flat export."""
        return cls(PackagedAsvsCatalogLoader())

    @classmethod
    def from_settings(cls, settings: Settings) -> AsvsControlRegistryFactory:
        """Return a factory backed by settings-driven cache and packaged fallback."""
        return cls(AsvsCatalogLoaderFacade(settings))

    def create(self) -> AsvsControlRegistry:
        """Load and wrap the current ASVS catalog snapshot."""
        return AsvsControlRegistry(self._loader.load())
