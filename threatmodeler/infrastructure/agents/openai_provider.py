"""OpenAI agent-provider strategy placeholder."""

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.ports.agent_client import AgentClient
from threatmodeler.shared.constants import AgentProviderName


class OpenAIAgentProvider:
    """Adapt a low-level injected client to the OpenAI provider strategy."""

    def __init__(self, client: AgentClient) -> None:
        self._client = client

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Complete a request without exposing the concrete SDK client.

        Args:
            request: Provider-neutral completion request.

        Returns:
            Provider-neutral response labeled with the OpenAI provider name.

        Raises:
            AgentProviderError: If the client reports or encounters a provider failure.
        """
        try:
            response = self._client.complete(request)
            return response.model_copy(update={"provider_name": AgentProviderName.OPENAI})
        except AgentProviderError:
            raise
        except Exception as error:
            raise AgentProviderError(
                "OpenAI provider request failed",
                error_code="OPENAI_REQUEST_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error
