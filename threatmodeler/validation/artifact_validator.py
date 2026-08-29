"""Pydantic revalidation for generated artifacts."""

from pydantic import ValidationError

from threatmodeler.contracts.artifacts import ArtifactModel
from threatmodeler.errors import ArtifactValidationError


class PydanticArtifactValidator:
    """Revalidate generated artifact payloads at application boundaries."""

    def validate(self, artifact: ArtifactModel) -> None:
        """Validate a serialized artifact using its concrete Pydantic model.

        Args:
            artifact: Generated artifact to serialize and revalidate.

        Raises:
            ArtifactValidationError: If serialization no longer satisfies the model schema.
        """
        try:
            type(artifact).model_validate(artifact.model_dump(mode="json"))
        except ValidationError as error:
            raise ArtifactValidationError(
                "Generated artifact failed Pydantic validation",
                error_code="GENERATED_ARTIFACT_INVALID",
                retryable=False,
                context={
                    "artifact_id": artifact.artifact_id,
                    "artifact_type": type(artifact).__name__,
                    "validation_errors": error.errors(
                        include_url=False,
                        include_input=False,
                    ),
                },
            ) from error
