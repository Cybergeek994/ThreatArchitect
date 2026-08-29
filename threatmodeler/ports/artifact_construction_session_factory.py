"""Port for creating host-owned artifact construction sessions."""

from collections.abc import Callable, Mapping
from typing import Protocol

from pydantic import BaseModel, JsonValue

from threatmodeler.ports.artifact_construction_session import ArtifactConstructionSession

FinishValidator = Callable[[dict[str, JsonValue]], list[str]]
ItemValidator = Callable[
    [str, dict[str, JsonValue], Mapping[str, list[dict[str, JsonValue]]]],
    list[str],
]


class ArtifactConstructionSessionFactory(Protocol):
    """Create a construction session for one Pydantic output model."""

    def create(
        self,
        output_model: type[BaseModel],
        *,
        source_text: str = "",
        finish_validator: FinishValidator | None = None,
        item_validator: ItemValidator | None = None,
    ) -> ArtifactConstructionSession:
        """Create a session whose tools are derived from ``output_model``.

        Args:
            output_model: Pydantic model the agent must assemble.
            source_text: Corpus used for deterministic evidence grounding.
            finish_validator: Optional extra checks applied inside the finish tool.
            item_validator: Optional per-item checks applied before each add_* call.

        Returns:
            Host-owned construction session for one generation attempt.
        """
        ...
