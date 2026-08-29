"""Canonical system model business-validation port."""

from typing import Protocol

from threatmodeler.contracts.system_model import CanonicalSystemModel


class SchemaValidator(Protocol):
    """Define business validation for a schema-valid canonical model."""

    def validate(self, model: CanonicalSystemModel) -> CanonicalSystemModel:
        """Return the model when valid or raise an expected validation error.

        Args:
            model: Schema-valid canonical model requiring business validation.

        Returns:
            Original model after all business rules succeed.

        Raises:
            AgentSchemaValidationError: If one or more business rules fail.
        """
        ...


class SystemModelValidationRule(Protocol):
    """Define one composable canonical-system-model business rule."""

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Return human-readable violations for the supplied model.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Empty list on success or human-readable business-rule violations.
        """
        ...
