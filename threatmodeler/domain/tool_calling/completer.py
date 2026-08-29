"""Retrying schema-bound completion through the tool-calling strategy."""

from pydantic import BaseModel

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.domain.tool_calling.session_factory import PydanticArtifactSessionFactory
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.ports.artifact_construction_session_factory import (
    ArtifactConstructionSessionFactory,
    FinishValidator,
    ItemValidator,
)
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider


class SchemaBoundToolCallingCompleter:
    """Apply retry policy around tool-calling artifact construction.

    The completer depends only on the tool-calling strategy and a session factory. It never
    falls back to one-shot JSON completion; schema repair remains a separate AgentProvider
    concern on the existing gateway.
    """

    def __init__(
        self,
        tool_calling_provider: ToolCallingProvider,
        session_factory: ArtifactConstructionSessionFactory | None = None,
        max_attempts: int = 1,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        self._tool_calling_provider = tool_calling_provider
        self._session_factory = session_factory or PydanticArtifactSessionFactory()
        self._max_attempts = max_attempts

    def complete(
        self,
        request: AgentRequest,
        output_model: type[BaseModel],
        journal: ConstructionJournal,
        *,
        source_text: str = "",
        finish_validator: FinishValidator | None = None,
        item_validator: ItemValidator | None = None,
    ) -> AgentResponse:
        """Assemble one schema-bound artifact through construction tools.

        Args:
            request: Provider-neutral agent request.
            output_model: Expected Pydantic output model.
            journal: Construction journal for the current run.
            source_text: Corpus used for deterministic evidence grounding.
            finish_validator: Optional extra checks applied inside the finish tool.
            item_validator: Optional per-item checks applied before each add_* call.

        Returns:
            Provider response whose payload is the assembled artifact.

        Raises:
            AgentProviderError: If the provider fails after retries.
        """
        last_error: AgentProviderError | None = None
        for _attempt in range(self._max_attempts):
            session = self._session_factory.create(
                output_model,
                source_text=source_text,
                finish_validator=finish_validator,
                item_validator=item_validator,
            )
            try:
                return self._tool_calling_provider.complete_with_tools(request, session, journal)
            except AgentProviderError as error:
                last_error = error
                if error.retryable is not True:
                    raise
        assert last_error is not None
        raise last_error
