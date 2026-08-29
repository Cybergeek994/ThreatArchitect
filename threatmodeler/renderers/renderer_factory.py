"""Factory selecting deterministic output renderer strategies."""

from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.renderers.renderer_registry import (
    DEFAULT_RENDERER_ENTRIES,
    RendererRegistryEntry,
    resolve_renderer_entry,
)


class RendererFactory:
    """Select deterministic renderer strategies by format and artifact kind."""

    def __init__(
        self,
        entries: tuple[RendererRegistryEntry, ...] = DEFAULT_RENDERER_ENTRIES,
    ) -> None:
        self._entries = entries

    def create(self, format_name: str, artifact_kind: str) -> ArtifactRenderer:
        """Create a renderer for a supported format and artifact combination.

        Args:
            format_name: Requested output format.
            artifact_kind: Artifact kind compatible with the requested format.

        Returns:
            Stateless renderer strategy for the requested output.

        Raises:
            ArtifactRenderingError: If the format and artifact combination is unsupported.
        """
        entry = resolve_renderer_entry(format_name, artifact_kind, self._entries)
        if entry is None:
            raise ArtifactRenderingError(
                "Unsupported renderer format and artifact combination",
                error_code="RENDERER_NOT_SUPPORTED",
                retryable=False,
                context={"format": format_name, "artifact_kind": artifact_kind},
            )
        return entry.factory()
