"""Local artifact bundle JSON loader."""

from pathlib import Path

from pydantic import ValidationError

from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.errors import ArtifactValidationError


class LocalArtifactBundleLoader:
    """Load and validate an artifact bundle from local JSON storage."""

    def load(self, path: Path) -> ArtifactBundle:
        """Read a bundle and normalize I/O and validation failures.

        Args:
            path: Path to the artifact-bundle JSON document.

        Returns:
            Validated artifact bundle.

        Raises:
            ArtifactValidationError: If the file cannot be read or violates the schema.
        """
        try:
            return ArtifactBundle.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValidationError) as error:
            context: dict[str, object] = {"path": str(path)}
            if isinstance(error, ValidationError):
                context["validation_errors"] = error.errors(
                    include_url=False,
                    include_input=False,
                )
            raise ArtifactValidationError(
                "Unable to load ArtifactBundle JSON",
                error_code="ARTIFACT_BUNDLE_LOAD_FAILED",
                retryable=False,
                context=context,
            ) from error
