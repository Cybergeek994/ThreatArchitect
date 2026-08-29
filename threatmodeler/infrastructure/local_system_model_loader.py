"""Local canonical system model JSON loader."""

from pathlib import Path

from pydantic import ValidationError

from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors.application import AgentSchemaValidationError


class LocalSystemModelLoader:
    """Load and validate canonical system models from local JSON storage."""

    def load(self, path: Path) -> CanonicalSystemModel:
        """Read a system model and normalize I/O and validation failures.

        Args:
            path: Path to the canonical system-model JSON artifact.

        Returns:
            Validated canonical system model.

        Raises:
            AgentSchemaValidationError: If the file cannot be read or violates the schema.
        """
        try:
            return CanonicalSystemModel.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValidationError) as error:
            context: dict[str, object] = {"path": str(path)}
            if isinstance(error, ValidationError):
                context["validation_errors"] = error.errors(
                    include_url=False,
                    include_input=False,
                )
            raise AgentSchemaValidationError(
                "Unable to load CanonicalSystemModel JSON",
                error_code="SYSTEM_MODEL_LOAD_FAILED",
                retryable=False,
                context=context,
            ) from error
