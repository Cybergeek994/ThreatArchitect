"""Port for OpenAI-compatible chat-completion turns with tools."""

from typing import Any, Protocol

from threatmodeler.contracts.integration import AgentRequest


class ChatCompletionTurnClient(Protocol):
    """Define the low-level chat-completion client used by the OpenAI tool-calling adapter."""

    provider_name: str
    model_name: str

    def complete_turn(
        self,
        request: AgentRequest,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> object:
        """Execute one chat-completion turn.

        Args:
            request: Provider-neutral request supplying temperature and token limits.
            messages: Chat messages including prior tool results.
            tools: OpenAI tool definitions, or ``None`` for a plain completion.

        Returns:
            Raw SDK completion object.

        Raises:
            AgentProviderError: If the provider rejects or fails the request.
        """
        ...
