"""Agent-provider strategy boundary."""

from typing import Protocol

from threatmodeler.contracts.integration import AgentRequest, AgentResponse


class AgentProvider(Protocol):
    """Define the strategy boundary for provider-neutral agent completions."""

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Complete a request and return a provider-neutral response.

        Args:
            request: Validated request independent of any provider SDK.

        Returns:
            Normalized provider response.

        Raises:
            AgentProviderError: If the selected provider cannot complete the request.
        """
        ...
