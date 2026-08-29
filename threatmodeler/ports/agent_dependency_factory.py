"""Factory port for agent-provider adapters."""

from typing import Protocol

from threatmodeler.config.settings import Settings
from threatmodeler.ports.agent_provider import AgentProvider


class AgentDependencyFactory(Protocol):
    """Define construction of the configured agent provider strategy."""

    def create_agent_provider(self, settings: Settings) -> AgentProvider:
        """Create the selected agent provider adapter."""
        ...
