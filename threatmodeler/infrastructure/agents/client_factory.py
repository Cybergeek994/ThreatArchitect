"""Production SDK-backed agent client factory."""

from openai import AzureOpenAI, OpenAI
from pydantic import SecretStr

from threatmodeler.config.settings import Settings
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.agents.chat_completion_client import ChatCompletionAgentClient
from threatmodeler.ports.agent_client import AgentClient
from threatmodeler.shared.constants import AgentProviderName


class SdkAgentClientFactory:
    """Construct OpenAI and Azure OpenAI SDK clients from immutable settings."""

    def create_openai_client(self, settings: Settings) -> AgentClient:
        """Create an OpenAI SDK client for the configured model deployment.

        Args:
            settings: Immutable credentials and provider configuration.

        Returns:
            Low-level client implementing the agent-client port.
        """
        return create_openai_sdk_client(settings)

    def create_azure_openai_client(self, settings: Settings) -> AgentClient:
        """Create an Azure OpenAI SDK client for the configured deployment.

        Args:
            settings: Immutable credentials and provider configuration.

        Returns:
            Low-level client implementing the agent-client port.
        """
        return create_azure_openai_sdk_client(settings)


def create_openai_sdk_client(settings: Settings) -> ChatCompletionAgentClient:
    """Create an OpenAI chat completion client from immutable settings.

    Args:
        settings: Application settings containing credentials and model name.

    Returns:
        Chat completion client bound to the configured OpenAI model.
    """
    api_key = _resolve_openai_api_key(settings)
    client = OpenAI(api_key=api_key.get_secret_value())
    return ChatCompletionAgentClient(
        client.chat.completions.create,
        provider_name=AgentProviderName.OPENAI,
        model_name=settings.agent_model_name,
    )


def create_azure_openai_sdk_client(settings: Settings) -> ChatCompletionAgentClient:
    """Create an Azure OpenAI chat completion client from immutable settings.

    Args:
        settings: Application settings containing Azure credentials and model name.

    Returns:
        Chat completion client bound to the configured Azure deployment name.
    """
    if settings.azure_openai_api_key is None or settings.azure_openai_endpoint is None:
        raise AgentProviderError(
            "Azure OpenAI provider configuration is incomplete",
            error_code="AZURE_OPENAI_CONFIG_MISSING",
            retryable=False,
        )
    client = AzureOpenAI(
        api_key=settings.azure_openai_api_key.get_secret_value(),
        azure_endpoint=str(settings.azure_openai_endpoint),
        api_version=settings.azure_openai_api_version,
    )
    return ChatCompletionAgentClient(
        client.chat.completions.create,
        provider_name=AgentProviderName.AZURE_OPENAI,
        model_name=settings.agent_model_name,
    )


def _resolve_openai_api_key(settings: Settings) -> SecretStr:
    if settings.openai_api_key is not None:
        return settings.openai_api_key
    if settings.agent_api_key is not None:
        return settings.agent_api_key
    raise AgentProviderError(
        "OpenAI provider requires an API key",
        error_code="OPENAI_API_KEY_MISSING",
        retryable=False,
    )
