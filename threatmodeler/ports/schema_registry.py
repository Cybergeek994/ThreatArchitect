"""Requested output-schema registry port."""

from typing import Protocol

from pydantic import BaseModel


class OutputSchemaRegistry(Protocol):
    """Define resolution of configured Pydantic output schemas by stable name."""

    def get(self, schema_name: str) -> type[BaseModel]:
        """Resolve and return the model type registered under a schema name.

        Args:
            schema_name: Stable schema identifier from an agent request.

        Returns:
            Registered Pydantic model type.

        Raises:
            AgentSchemaValidationError: If the schema name is unknown.
        """
        ...
