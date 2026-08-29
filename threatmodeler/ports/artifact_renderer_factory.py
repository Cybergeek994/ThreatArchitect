"""Artifact renderer factory port."""

from typing import Protocol

from threatmodeler.ports.artifact_renderer import ArtifactRenderer


class ArtifactRendererFactory(Protocol):
    """Define creation of renderer strategies for named output artifacts."""

    def create(self, artifact_name: str) -> ArtifactRenderer:
        """Create and return a renderer for one output name.

        Args:
            artifact_name: Stable filename stem assigned to rendered output.

        Returns:
            Renderer strategy configured for the artifact name.
        """
        ...
