"""Port for Copilot SDK sessions that host in-process construction tools."""

from typing import Protocol

from threatmodeler.contracts.integration import AgentRequest


class CopilotToolSessionClient(Protocol):
    """Define the Copilot session client used by the Copilot tool-calling adapter."""

    model_name: str

    def complete_with_tools(
        self,
        request: AgentRequest,
        *,
        tools: list[object],
        available_tools: list[str],
    ) -> str:
        """Run a Copilot session whose available tools are host construction tools.

        Args:
            request: Provider-neutral request.
            tools: Copilot SDK tool objects.
            available_tools: Allowlist of host tool names that hides built-in tools.

        Returns:
            Assistant message text from the finished session.

        Raises:
            AgentProviderError: If the Copilot runtime rejects or fails the request.
        """
        ...
