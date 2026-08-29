"""Rendered artifact repository port."""

from pathlib import Path
from typing import Protocol

from threatmodeler.contracts.integration import RenderedArtifact, SavedArtifact


class ArtifactRepository(Protocol):
    """Define persistence of rendered artifacts and their save metadata."""

    def save(self, artifact: RenderedArtifact, output_dir: Path) -> SavedArtifact:
        """Save an artifact and return metadata for the persisted output.

        Args:
            artifact: Rendered content and canonical filename metadata.
            output_dir: Root location beneath which the artifact is stored.

        Returns:
            Path, size, and digest metadata for the saved artifact.

        Raises:
            ArtifactStorageError: If the artifact cannot be persisted safely.
        """
        ...
