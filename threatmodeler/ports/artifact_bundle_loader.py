"""Artifact bundle loading port."""

from pathlib import Path
from typing import Protocol

from threatmodeler.contracts.artifacts import ArtifactBundle


class ArtifactBundleLoader(Protocol):
    """Define loading of validated artifact bundles from delivery-specific sources."""

    def load(self, path: Path) -> ArtifactBundle:
        """Load and return one validated artifact bundle.

        Args:
            path: Delivery-specific location of the serialized bundle.

        Returns:
            Validated artifact bundle.

        Raises:
            ArtifactValidationError: If the source cannot produce a valid bundle.
        """
        ...
