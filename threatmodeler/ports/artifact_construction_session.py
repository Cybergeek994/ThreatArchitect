"""Port for incremental, host-owned artifact construction state."""

from typing import Protocol

from pydantic import BaseModel, JsonValue

from threatmodeler.contracts.tool_calling import ToolApplicationResult, ToolDefinition


class ArtifactConstructionSession(Protocol):
    """Accumulate validated artifact pieces and assemble the final payload."""

    def tool_definitions(self) -> list[ToolDefinition]:
        """Return the provider-neutral tool catalog for this session.

        Returns:
            Tool definitions derived from the target output model.
        """
        ...

    def tool_parameter_model(self, name: str) -> type[BaseModel]:
        """Return the Pydantic parameter model for one construction tool.

        Args:
            name: Tool name from the catalog.

        Returns:
            Pydantic model used to validate that tool's arguments.
        """
        ...

    def apply(self, name: str, arguments: dict[str, JsonValue]) -> ToolApplicationResult:
        """Validate one tool invocation and, when accepted, merge it into builder state.

        Args:
            name: Tool name invoked by the provider.
            arguments: JSON-compatible tool arguments.

        Returns:
            Acceptance result, including finish status when the terminal tool succeeds.
        """
        ...

    def assemble(self) -> dict[str, JsonValue]:
        """Return the assembled payload after a successful finish tool.

        Returns:
            JSON-compatible object matching the target output model.
        """
        ...

    def is_complete(self) -> bool:
        """Return whether the terminal finish tool has been accepted.

        Returns:
            True when assembled output is available.
        """
        ...
