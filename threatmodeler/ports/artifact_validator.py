"""Generated artifact validation port."""

from typing import Protocol

from threatmodeler.contracts.artifacts import ArtifactModel


class ArtifactValidator(Protocol):
    """Define boundary validation for generated artifacts before downstream use."""

    def validate(self, artifact: ArtifactModel) -> None:
        """Accept a valid artifact or raise an expected application error.

        Args:
            artifact: Generated artifact requiring boundary validation.

        Raises:
            ArtifactValidationError: If the artifact violates its concrete schema.
        """
        ...
