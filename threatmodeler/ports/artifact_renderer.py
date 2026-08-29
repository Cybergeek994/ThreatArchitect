"""Threat-model artifact renderer port."""

from typing import Protocol

from pydantic import BaseModel

from threatmodeler.contracts.integration import RenderedArtifact


class ArtifactRenderer(Protocol):
    """Define the strategy boundary for rendering validated Pydantic artifacts."""

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render a validated model into a persistable artifact.

        Args:
            artifact: Validated Pydantic model accepted by the renderer strategy.

        Returns:
            In-memory content and output metadata ready for persistence.

        Raises:
            ArtifactRenderingError: If the artifact type or serialization is unsupported.
        """
        ...
