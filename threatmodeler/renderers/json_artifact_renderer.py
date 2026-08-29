"""Generic Pydantic JSON artifact renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors.application import ArtifactRenderingError


class JsonArtifactRenderer:
    """Render any validated Pydantic model as a formatted JSON artifact."""

    def __init__(self, artifact_name: str) -> None:
        self._artifact_name = artifact_name

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Serialize an artifact and normalize rendering failures.

        Args:
            artifact: Validated Pydantic model to serialize.

        Returns:
            UTF-8 JSON artifact with the configured output name.

        Raises:
            ArtifactRenderingError: If Pydantic serialization fails.
        """
        try:
            return RenderedArtifact(
                name=self._artifact_name,
                content=artifact.model_dump_json(indent=2),
                media_type="application/json",
                file_extension=".json",
            )
        except Exception as error:
            raise ArtifactRenderingError(
                "Unable to render the Pydantic artifact as JSON",
                error_code="ARTIFACT_JSON_RENDER_FAILED",
                retryable=False,
                context={"artifact_name": self._artifact_name},
            ) from error
