"""Port for loading OWASP ASVS catalog snapshots."""

from typing import Protocol

from threatmodeler.contracts.control_catalog import AsvsControlCatalogSnapshot


class ControlCatalogLoader(Protocol):
    """Load a normalized ASVS catalog snapshot."""

    def load(self) -> AsvsControlCatalogSnapshot:
        """Return the current ASVS catalog snapshot."""
        ...
