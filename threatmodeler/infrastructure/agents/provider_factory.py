"""Settings-driven agent provider factory."""

from threatmodeler.config.settings import Settings
from threatmodeler.errors.application import ConfigurationError
from threatmodeler.infrastructure.agents.azure_openai_provider import (
    AzureOpenAIAgentProvider,
)
from threatmodeler.infrastructure.agents.chat_completion_client import ChatCompletionAgentClient
from threatmodeler.infrastructure.agents.copilot_client import (
    CopilotSdkAgentClient,
    create_copilot_sdk_client,
)
from threatmodeler.infrastructure.agents.copilot_provider import CopilotAgentProvider
from threatmodeler.infrastructure.agents.copilot_tool_calling_driver import (
    CopilotToolCallingDriver,
)
from threatmodeler.infrastructure.agents.openai_provider import OpenAIAgentProvider
from threatmodeler.infrastructure.agents.openai_tool_calling_driver import (
    OpenAIToolCallingDriver,
)
from threatmodeler.infrastructure.agents.provider_registry import (
    AgentProviderKind,
    AgentProviderRegistryEntry,
    resolve_agent_provider_entry,
)
from threatmodeler.ports.agent_client import AgentClientFactory
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.shared.constants import AgentProviderName, EnvironmentVariable


class AgentProviderFactory:
    """Create the agent-provider strategy selected by immutable settings.

    OpenAI and Azure OpenAI clients are built via the optional injected
    ``AgentClientFactory``. GitHub Copilot clients are built by
    ``create_copilot_sdk_client`` (Copilot SDK is async-native and is not part of
    that OpenAI-shaped factory). No provider client or credential is stored in
    module-level state.
    """

    def __init__(
        self,
        settings: Settings,
        client_factory: AgentClientFactory | None = None,
    ) -> None:
        self._settings = settings
        self._client_factory = client_factory

    def create(self) -> AgentProvider:
        """Create the provider selected by application settings.

        Returns:
            Configured OpenAI, Azure OpenAI, or GitHub Copilot provider strategy.

        Raises:
            ConfigurationError: If the provider is unsupported or configuration is missing.
        """
        entry = self._resolved_entry()
        if entry.kind is AgentProviderKind.OPENAI:
            self._require_openai_api_key()
            client = self._required_client_factory(AgentProviderName.OPENAI).create_openai_client(
                self._settings
            )
            return OpenAIAgentProvider(client)
        if entry.kind is AgentProviderKind.AZURE:
            self._require_azure_configuration(AgentProviderName.AZURE)
            client = self._required_client_factory(AgentProviderName.AZURE).create_azure_openai_client(
                self._settings
            )
            return AzureOpenAIAgentProvider(client)
        return CopilotAgentProvider(create_copilot_sdk_client(self._settings))

    def create_tool_calling_provider(self) -> ToolCallingProvider:
        """Create the tool-calling driver for the selected provider."""
        entry = self._resolved_entry()
        max_turns = self._settings.agent_tool_calling_max_turns
        stall_after_repeats = self._settings.agent_tool_calling_stall_after_repeats
        if entry.kind is AgentProviderKind.COPILOT:
            client = create_copilot_sdk_client(self._settings)
            if not isinstance(client, CopilotSdkAgentClient):
                raise self._tool_calling_client_error(entry, "Copilot SDK client")
            return CopilotToolCallingDriver(
                client,
                max_turns=max_turns,
                stall_after_repeats=stall_after_repeats,
            )
        if entry.kind is AgentProviderKind.OPENAI:
            client = self._create_openai_client(entry)
        else:
            client = self._create_azure_client(entry)
        if not isinstance(client, ChatCompletionAgentClient):
            raise self._tool_calling_client_error(entry, "chat-completion client")
        return OpenAIToolCallingDriver(
            client,
            max_turns=max_turns,
            stall_after_repeats=stall_after_repeats,
        )

    def _resolved_entry(self) -> AgentProviderRegistryEntry:
        entry = resolve_agent_provider_entry(self._settings.agent_provider_name)
        if entry is None:
            raise ConfigurationError(
                "Unsupported agent provider",
                error_code="AGENT_PROVIDER_UNSUPPORTED",
                retryable=False,
                context={"agent_provider_name": self._settings.agent_provider_name},
            )
        return entry

    def _create_openai_client(self, entry: AgentProviderRegistryEntry) -> ChatCompletionAgentClient:
        self._require_openai_api_key()
        client = self._required_client_factory(AgentProviderName.OPENAI).create_openai_client(
            self._settings
        )
        if not isinstance(client, ChatCompletionAgentClient):
            raise self._tool_calling_client_error(entry, "chat-completion client")
        return client

    def _create_azure_client(self, entry: AgentProviderRegistryEntry) -> ChatCompletionAgentClient:
        provider_name = AgentProviderName.AZURE
        self._require_azure_configuration(provider_name)
        client = self._required_client_factory(provider_name).create_azure_openai_client(
            self._settings
        )
        if not isinstance(client, ChatCompletionAgentClient):
            raise self._tool_calling_client_error(entry, "chat-completion client")
        return client

    def _tool_calling_client_error(
        self,
        entry: AgentProviderRegistryEntry,
        expected: str,
    ) -> ConfigurationError:
        provider_name = next(iter(entry.names))
        return ConfigurationError(
            f"The selected agent provider does not expose a {expected}",
            error_code="AGENT_CLIENT_FACTORY_MISSING",
            retryable=False,
            context={"agent_provider_name": provider_name},
        )

    def _required_client_factory(self, provider_name: str) -> AgentClientFactory:
        if self._client_factory is None:
            raise ConfigurationError(
                "The selected agent provider does not have a configured client factory",
                error_code="AGENT_CLIENT_FACTORY_MISSING",
                retryable=False,
                context={"agent_provider_name": provider_name},
            )
        return self._client_factory

    def _require_openai_api_key(self) -> None:
        if self._settings.openai_api_key is None and self._settings.agent_api_key is None:
            raise ConfigurationError(
                "OpenAI provider requires "
                f"{EnvironmentVariable.OPENAI_API_KEY} or "
                f"{EnvironmentVariable.AGENT_API_KEY}",
                error_code="OPENAI_API_KEY_MISSING",
                retryable=False,
                context={
                    "agent_provider_name": AgentProviderName.OPENAI,
                    "required_environment_variables": [
                        EnvironmentVariable.OPENAI_API_KEY,
                        EnvironmentVariable.AGENT_API_KEY,
                    ],
                },
            )

    def _require_azure_configuration(self, provider_name: str) -> None:
        missing_fields: list[str] = []
        if self._settings.azure_openai_api_key is None:
            missing_fields.append("azure_openai_api_key")
        if self._settings.azure_openai_endpoint is None:
            missing_fields.append("azure_openai_endpoint")
        if missing_fields:
            raise ConfigurationError(
                "Azure OpenAI provider requires "
                f"{EnvironmentVariable.AZURE_OPENAI_API_KEY} and "
                f"{EnvironmentVariable.AZURE_OPENAI_ENDPOINT}",
                error_code="AZURE_OPENAI_CONFIG_MISSING",
                retryable=False,
                context={
                    "agent_provider_name": provider_name,
                    "missing_fields": missing_fields,
                    "required_environment_variables": [
                        EnvironmentVariable.AZURE_OPENAI_API_KEY,
                        EnvironmentVariable.AZURE_OPENAI_ENDPOINT,
                    ],
                },
            )
