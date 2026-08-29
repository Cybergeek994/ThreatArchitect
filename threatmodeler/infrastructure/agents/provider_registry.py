"""Registry of agent provider strategies selected by settings."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from threatmodeler.shared.constants import AgentProviderName


class AgentProviderKind(StrEnum):
    """Implementation strategy for a configured agent provider."""

    OPENAI = "openai"
    AZURE = "azure"
    COPILOT = "copilot"


class AgentProviderRegistryEntry(BaseModel):
    """One supported agent provider alias set and implementation kind."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    names: frozenset[str] = Field(min_length=1)
    kind: AgentProviderKind


DEFAULT_AGENT_PROVIDER_ENTRIES: tuple[AgentProviderRegistryEntry, ...] = (
    AgentProviderRegistryEntry(
        names=frozenset({AgentProviderName.OPENAI}),
        kind=AgentProviderKind.OPENAI,
    ),
    AgentProviderRegistryEntry(
        names=frozenset({AgentProviderName.AZURE, AgentProviderName.AZURE_OPENAI}),
        kind=AgentProviderKind.AZURE,
    ),
    AgentProviderRegistryEntry(
        names=frozenset({AgentProviderName.GITHUB_COPILOT, AgentProviderName.COPILOT}),
        kind=AgentProviderKind.COPILOT,
    ),
)


def resolve_agent_provider_entry(
    provider_name: str,
    entries: tuple[AgentProviderRegistryEntry, ...] = DEFAULT_AGENT_PROVIDER_ENTRIES,
) -> AgentProviderRegistryEntry | None:
    """Return the registry entry for a normalized provider name."""
    normalized = provider_name.strip().lower()
    for entry in entries:
        if normalized in entry.names:
            return entry
    return None
