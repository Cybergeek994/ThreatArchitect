"""Low-level agent client creation ports."""

from typing import Protocol

from threatmodeler.config.settings import Settings
from threatmodeler.contracts.integration import AgentRequest, AgentResponse


class AgentClient(Protocol):
    """Define the low-level provider client hidden behind agent strategies."""

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Execute a provider request and return its normalized response.

        Args:
            request: Provider-neutral request to execute.

        Returns:
            Provider-neutral response produced by the low-level client.
        """
        ...


class AgentClientFactory(Protocol):
    """Define construction of provider SDK clients from immutable settings."""

    def create_openai_client(self, settings: Settings) -> AgentClient:
        """Create an OpenAI client without exposing it globally.

        Args:
            settings: Immutable credentials and provider configuration.

        Returns:
            Fresh low-level client implementing the agent-client port.
        """
        ...

    def create_azure_openai_client(self, settings: Settings) -> AgentClient:
        """Create an Azure OpenAI client without exposing it globally.

        Args:
            settings: Immutable credentials and provider configuration.

        Returns:
            Fresh low-level client implementing the agent-client port.
        """
        ...
