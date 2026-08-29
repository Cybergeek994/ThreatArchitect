"""Factory for named JSON artifact renderers."""

from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer


class JsonArtifactRendererFactory:
    """Create independent JSON renderer strategies."""

    def create(self, artifact_name: str) -> JsonArtifactRenderer:
        """Create a renderer for one stable output filename.

        Args:
            artifact_name: Filename stem assigned to the rendered JSON artifact.

        Returns:
            Independent JSON renderer configured with the supplied name.
        """
        return JsonArtifactRenderer(artifact_name)
