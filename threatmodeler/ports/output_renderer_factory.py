"""Output renderer selection port."""

from typing import Protocol

from threatmodeler.ports.artifact_renderer import ArtifactRenderer


class OutputRendererFactory(Protocol):
    """Define renderer selection by output format and artifact kind."""

    def create(self, format_name: str, artifact_kind: str) -> ArtifactRenderer:
        """Create and return the requested deterministic renderer strategy.

        Args:
            format_name: Requested deterministic output format.
            artifact_kind: Validated artifact kind to render.

        Returns:
            Renderer compatible with the format and artifact combination.

        Raises:
            ArtifactRenderingError: If no renderer supports the combination.
        """
        ...
