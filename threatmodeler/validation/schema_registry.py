"""Constructor-injected Pydantic output-schema registry."""

from collections.abc import Mapping

from pydantic import BaseModel

from threatmodeler.errors.application import AgentSchemaValidationError


class PydanticOutputSchemaRegistry:
    """Resolve constructor-injected Pydantic models without a global schema map."""

    def __init__(self, schemas: Mapping[str, type[BaseModel]]) -> None:
        self._schemas = dict(schemas)

    def get(self, schema_name: str) -> type[BaseModel]:
        """Resolve a registered schema by stable name.

        Args:
            schema_name: Stable output-schema name from an agent request.

        Returns:
            Concrete Pydantic model type registered for the name.

        Raises:
            AgentSchemaValidationError: If no model is registered for the name.
        """
        try:
            return self._schemas[schema_name]
        except KeyError as error:
            raise AgentSchemaValidationError(
                "Requested agent output schema is not registered",
                error_code="AGENT_SCHEMA_NOT_REGISTERED",
                retryable=False,
                context={"expected_schema_name": schema_name},
            ) from error
