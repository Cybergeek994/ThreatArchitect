"""Factory port for artifact rendering and persistence adapters."""

from typing import Protocol

from threatmodeler.config.settings import Settings
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository


class ArtifactOutputDependencyFactory(Protocol):
    """Define construction of artifact renderer and repository adapters."""

    def create_artifact_renderer(self, settings: Settings) -> ArtifactRenderer:
        """Create the configured artifact renderer."""
        ...

    def create_artifact_repository(self, settings: Settings) -> ArtifactRepository:
        """Create the configured artifact repository."""
        ...
