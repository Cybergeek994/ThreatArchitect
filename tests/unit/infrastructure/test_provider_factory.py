"""Tests for settings-driven agent provider factory."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from threatmodeler.config.settings import Settings
from threatmodeler.errors.application import ConfigurationError
from threatmodeler.infrastructure.agents.azure_openai_provider import AzureOpenAIAgentProvider
from threatmodeler.infrastructure.agents.chat_completion_client import ChatCompletionAgentClient
from threatmodeler.infrastructure.agents.copilot_client import CopilotSdkAgentClient
from threatmodeler.infrastructure.agents.copilot_provider import CopilotAgentProvider
from threatmodeler.infrastructure.agents.copilot_tool_calling_driver import CopilotToolCallingDriver
from threatmodeler.infrastructure.agents.openai_provider import OpenAIAgentProvider
from threatmodeler.infrastructure.agents.openai_tool_calling_driver import OpenAIToolCallingDriver
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from threatmodeler.shared.constants import AgentProviderName


class TestAgentProviderFactoryCreatePositive:
    """Verify create() builds the selected provider strategy."""

    def test_create_openai_provider(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.OPENAI,
            openai_api_key=SecretStr("sk-test"),
        )
        client = Mock(spec=ChatCompletionAgentClient)
        factory = Mock()
        factory.create_openai_client.return_value = client

        provider = AgentProviderFactory(settings, client_factory=factory).create()

        assert isinstance(provider, OpenAIAgentProvider)
        factory.create_openai_client.assert_called_once_with(settings)

    def test_create_azure_provider(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.AZURE,
            azure_openai_api_key=SecretStr("azure-key"),
            azure_openai_endpoint="https://example.openai.azure.com",
        )
        client = Mock(spec=ChatCompletionAgentClient)
        factory = Mock()
        factory.create_azure_openai_client.return_value = client

        provider = AgentProviderFactory(settings, client_factory=factory).create()

        assert isinstance(provider, AzureOpenAIAgentProvider)
        factory.create_azure_openai_client.assert_called_once_with(settings)

    @pytest.mark.parametrize(
        "provider_name",
        [AgentProviderName.GITHUB_COPILOT, AgentProviderName.COPILOT],
    )

    def test_create_copilot_provider(self, provider_name: str) -> None:
        settings = Settings(agent_provider_name=provider_name, agent_model_name="auto")
        fake_client = Mock(spec=CopilotSdkAgentClient)

        with patch(
            "threatmodeler.infrastructure.agents.provider_factory.create_copilot_sdk_client",
            return_value=fake_client,
        ) as create_client:
            provider = AgentProviderFactory(settings).create()

        assert isinstance(provider, CopilotAgentProvider)
        create_client.assert_called_once_with(settings)


class TestAgentProviderFactoryToolCallingPositive:
    """Verify create_tool_calling_provider() builds the correct driver."""

    def test_create_tool_calling_openai_driver(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.OPENAI,
            openai_api_key=SecretStr("sk-test"),
            agent_tool_calling_max_turns=8,
            agent_tool_calling_stall_after_repeats=3,
        )
        client = Mock(spec=ChatCompletionAgentClient)
        factory = Mock()
        factory.create_openai_client.return_value = client

        driver = AgentProviderFactory(settings, client_factory=factory).create_tool_calling_provider()

        assert isinstance(driver, OpenAIToolCallingDriver)
        assert driver._max_turns == 8
        assert driver._stall_after_repeats == 3

    def test_create_tool_calling_azure_driver(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.AZURE_OPENAI,
            azure_openai_api_key=SecretStr("azure-key"),
            azure_openai_endpoint="https://example.openai.azure.com",
        )
        client = Mock(spec=ChatCompletionAgentClient)
        factory = Mock()
        factory.create_azure_openai_client.return_value = client

        driver = AgentProviderFactory(settings, client_factory=factory).create_tool_calling_provider()

        assert isinstance(driver, OpenAIToolCallingDriver)

    def test_create_tool_calling_copilot_driver(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="auto",
            agent_tool_calling_max_turns=12,
        )
        client = Mock(spec=CopilotSdkAgentClient)

        with patch(
            "threatmodeler.infrastructure.agents.provider_factory.create_copilot_sdk_client",
            return_value=client,
        ):
            driver = AgentProviderFactory(settings).create_tool_calling_provider()

        assert isinstance(driver, CopilotToolCallingDriver)
        assert driver._max_turns == 12


class TestAgentProviderFactoryNegative:
    """Verify factory rejects unsupported or misconfigured providers."""

    def test_unsupported_provider_raises_configuration_error(self) -> None:
        settings = Settings(agent_provider_name="unsupported-provider")

        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(settings).create()

        assert captured.value.error_code == "AGENT_PROVIDER_UNSUPPORTED"

    def test_missing_client_factory_raises_configuration_error(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.OPENAI,
            openai_api_key=SecretStr("sk-test"),
        )

        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(settings).create()

        assert captured.value.error_code == "AGENT_CLIENT_FACTORY_MISSING"

    def test_openai_tool_calling_wrong_client_type_raises(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.OPENAI,
            openai_api_key=SecretStr("sk-test"),
        )
        factory = Mock()
        factory.create_openai_client.return_value = Mock()

        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(settings, client_factory=factory).create_tool_calling_provider()

        assert captured.value.error_code == "AGENT_CLIENT_FACTORY_MISSING"
        assert "chat-completion client" in str(captured.value)

    def test_azure_tool_calling_wrong_client_type_raises(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.AZURE,
            azure_openai_api_key=SecretStr("azure-key"),
            azure_openai_endpoint="https://example.openai.azure.com",
        )
        factory = Mock()
        factory.create_azure_openai_client.return_value = Mock()

        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(settings, client_factory=factory).create_tool_calling_provider()

        assert captured.value.error_code == "AGENT_CLIENT_FACTORY_MISSING"

    def test_copilot_tool_calling_wrong_client_type_raises(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="auto",
        )

        with (
            patch(
                "threatmodeler.infrastructure.agents.provider_factory.create_copilot_sdk_client",
                return_value=Mock(),
            ),
            pytest.raises(ConfigurationError) as captured,
        ):
            AgentProviderFactory(settings).create_tool_calling_provider()

        assert captured.value.error_code == "AGENT_CLIENT_FACTORY_MISSING"
        assert "Copilot SDK client" in str(captured.value)


    def test_provider_factory_rejects_non_chat_completion_client(self) -> None:
        from pydantic import SecretStr

        settings = Settings(
            agent_provider_name="openai",
            openai_api_key=SecretStr("sk-test"),
        )
        factory = Mock()
        factory.create_openai_client.return_value = object()
        with pytest.raises(ConfigurationError):
            AgentProviderFactory(settings, client_factory=factory).create_tool_calling_provider()

    def test_provider_factory_defensive_chat_client_check(self) -> None:
        settings = Settings(
            agent_provider_name="openai",
            openai_api_key=SecretStr("sk-test"),
        )
        factory = AgentProviderFactory(settings, client_factory=Mock())
        with (
            patch.object(factory, "_create_openai_client", return_value=object()),
            pytest.raises(ConfigurationError),
        ):
            factory.create_tool_calling_provider()
