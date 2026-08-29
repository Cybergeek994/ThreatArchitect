"""Port for provider-neutral tool-calling artifact construction."""

from typing import Protocol

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.ports.artifact_construction_session import ArtifactConstructionSession
from threatmodeler.ports.construction_journal import ConstructionJournal


class ToolCallingProvider(Protocol):
    """Complete an agent request by driving host-defined construction tools."""

    def complete_with_tools(
        self,
        request: AgentRequest,
        session: ArtifactConstructionSession,
        journal: ConstructionJournal,
    ) -> AgentResponse:
        """Run a tool-calling loop until the session finishes or the turn budget is exhausted.

        Args:
            request: Provider-neutral completion request.
            session: Host-owned construction state and tool catalog.
            journal: Durable trace of accepted and rejected tool calls.

        Returns:
            Provider response whose payload is the assembled artifact.

        Raises:
            AgentProviderError: If the provider fails or the turn budget is exceeded.
        """
        ...
