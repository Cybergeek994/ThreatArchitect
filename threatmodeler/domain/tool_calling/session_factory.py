"""Factory for schema-derived artifact construction sessions."""

from pydantic import BaseModel

from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.ports.artifact_construction_session_factory import (
    FinishValidator,
    ItemValidator,
)


class PydanticArtifactSessionFactory:
    """Create builder sessions by introspecting a Pydantic output model.

    This factory keeps session construction independent of provider adapters, matching
    the injected-factory style used for agent clients and renderers.
    """

    def create(
        self,
        output_model: type[BaseModel],
        *,
        source_text: str = "",
        finish_validator: FinishValidator | None = None,
        item_validator: ItemValidator | None = None,
    ) -> ArtifactBuilderSession:
        """Create a session whose tools are derived from ``output_model``.

        Args:
            output_model: Pydantic model the agent must assemble.
            source_text: Corpus used for deterministic evidence grounding.
            finish_validator: Optional extra checks applied inside the finish tool.
            item_validator: Optional per-item checks applied before each add_* call.

        Returns:
            Host-owned construction session for one generation attempt.
        """
        return ArtifactBuilderSession(
            ArtifactToolSet.from_model(output_model),
            source_text=source_text,
            finish_validator=finish_validator,
            item_validator=item_validator,
        )
