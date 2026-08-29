"""Tests for agent strategies, provider selection, retries, repair, and validation."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import AnyHttpUrl, JsonValue, SecretStr
from threatmodeler.application.agent_gateway import AgentProviderGateway
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import AgentRequest, AgentResponse
from threatmodeler.contracts.workflow import AnalysisSummary
from threatmodeler.errors import (
    AgentProviderError,
    AgentSchemaValidationError,
    ConfigurationError,
)
from threatmodeler.infrastructure.agents.azure_openai_provider import (
    AzureOpenAIAgentProvider,
)
from threatmodeler.infrastructure.agents.openai_provider import OpenAIAgentProvider
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from threatmodeler.orchestration.prompts import SchemaRepairPromptBuilder, SecurePromptTemplate
from threatmodeler.ports.agent_client import AgentClient, AgentClientFactory
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.schema_registry import OutputSchemaRegistry
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider
from threatmodeler.validation.schema_registry import PydanticOutputSchemaRegistry


@pytest.fixture
def agent_request() -> AgentRequest:
    """Create a valid provider-neutral request."""
    return AgentRequest(
        task_name="extract_threats",
        instructions="Identify threats in the supplied architecture.",
        input_payload={"architecture": "Public API and database"},
        expected_schema_name="AnalysisSummary",
        temperature=0.0,
        max_output_tokens=1_000,
    )


@pytest.fixture
def schema_registry() -> PydanticOutputSchemaRegistry:
    """Create an isolated output-schema registry."""
    return PydanticOutputSchemaRegistry({"AnalysisSummary": AnalysisSummary})


@pytest.fixture
def valid_output_payload() -> dict[str, JsonValue]:
    """Return a valid payload for an existing production output contract."""
    return {
        "application_name": "Payments",
        "component_count": 2,
        "data_flow_count": 1,
        "threat_count": 2,
        "missing_information_count": 0,
        "output_directory": str(Path("out")),
    }


@pytest.fixture
def agent_response_factory() -> Callable[..., AgentResponse]:
    """Return a fixture factory for production agent responses."""

    def create(
        output_payload: dict[str, JsonValue] | str,
        *,
        provider_name: str = "mock",
        confidence: float = 0.8,
    ) -> AgentResponse:
        return AgentResponse(
            output_payload=output_payload,
            confidence=confidence,
            provider_name=provider_name,
            model_name="test-model",
        )

    return create


@pytest.fixture
def agent_gateway_factory(
    schema_registry: PydanticOutputSchemaRegistry,
) -> Callable[..., AgentProviderGateway]:
    """Return a configurable gateway factory with isolated dependencies."""

    def create(
        provider: AgentProvider,
        registry: OutputSchemaRegistry | None = None,
        *,
        max_attempts: int = 3,
        max_schema_repair_attempts: int = 1,
    ) -> AgentProviderGateway:
        return AgentProviderGateway(
            provider,
            registry or schema_registry,
            SchemaRepairPromptBuilder(SecurePromptTemplate()),
            PydanticSchemaProvider(),
            max_attempts=max_attempts,
            max_schema_repair_attempts=max_schema_repair_attempts,
        )

    return create


class TestAgentGatewayPositive:
    """Verify supported inputs and successful behavior."""

    def test_mock_provider_works_through_validating_gateway(
        self,
        agent_request: AgentRequest,
        valid_output_payload: dict[str, JsonValue],
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.return_value = agent_response_factory(
            valid_output_payload, confidence=0.95
        )
        gateway = agent_gateway_factory(provider)

        response = gateway.complete(agent_request)

        assert response.provider_name == "mock"
        assert response.confidence == 0.95
        assert response.output_payload == valid_output_payload
        provider.complete.assert_called_once_with(agent_request)

    @pytest.mark.parametrize(
        ("provider_name", "expected_type", "factory_method"),
        [
            ("openai", OpenAIAgentProvider, "create_openai_client"),
            ("azure_openai", AzureOpenAIAgentProvider, "create_azure_openai_client"),
        ],
    )

    def test_factory_selects_client_backed_provider_and_injects_created_client(
        self,
        provider_name: str,
        expected_type: type[OpenAIAgentProvider] | type[AzureOpenAIAgentProvider],
        factory_method: str,
        agent_request: AgentRequest,
        valid_output_payload: dict[str, JsonValue],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        if provider_name == "openai":
            settings = Settings(
                agent_provider_name=provider_name,
                openai_api_key=SecretStr("test-openai-key"),
            )
        else:
            settings = Settings(
                agent_provider_name=provider_name,
                azure_openai_api_key=SecretStr("test-azure-key"),
                azure_openai_endpoint=AnyHttpUrl("https://azure-openai.invalid"),
            )
        client = Mock(spec=AgentClient)
        client.complete.return_value = agent_response_factory(
            valid_output_payload,
            provider_name="low_level_client",
        )
        client_factory = Mock(spec=AgentClientFactory)
        getattr(client_factory, factory_method).return_value = client

        provider = AgentProviderFactory(settings, client_factory).create()
        response = provider.complete(agent_request)

        assert isinstance(provider, expected_type)
        getattr(client_factory, factory_method).assert_called_once_with(settings)
        assert response.provider_name == provider_name


class TestAgentGatewayNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_gateway_repairs_invalid_json_with_schema_bound_prompt(
        self,
        agent_request: AgentRequest,
        valid_output_payload: dict[str, JsonValue],
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.side_effect = [
            agent_response_factory("not-json"),
            agent_response_factory(json.dumps(valid_output_payload)),
        ]
        gateway = agent_gateway_factory(provider)

        response = gateway.complete(agent_request)

        assert response.output_payload == valid_output_payload
        assert provider.complete.call_count == 2
        repair_request = provider.complete.call_args_list[1].args[0]
        assert repair_request.task_name == "repair_extract_threats"
        assert [message.role.value for message in repair_request.messages] == [
            "system",
            "developer",
            "user",
        ]
        assert "json_invalid" in repair_request.messages[-1].content
        assert "not-json" in repair_request.messages[-1].content

    def test_gateway_repairs_schema_invalid_json_object(
        self,
        agent_request: AgentRequest,
        valid_output_payload: dict[str, JsonValue],
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.side_effect = [
            agent_response_factory({"application_name": "Payments"}),
            agent_response_factory(valid_output_payload),
        ]

        response = agent_gateway_factory(provider).complete(agent_request)

        assert response.output_payload == valid_output_payload
        repair_request = provider.complete.call_args_list[1].args[0]
        assert "Field required" in repair_request.messages[-1].content

    def test_gateway_rejects_negative_schema_repair_attempts(
        self, agent_gateway_factory: Callable[..., AgentProviderGateway]
    ) -> None:
        with pytest.raises(ConfigurationError) as captured:
            agent_gateway_factory(Mock(spec=AgentProvider), max_schema_repair_attempts=-1)

        assert captured.value.error_code == "AGENT_SCHEMA_REPAIR_ATTEMPTS_INVALID"

    def test_factory_rejects_test_only_mock_provider(self) -> None:
        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(Settings(agent_provider_name="mock")).create()

        assert captured.value.error_code == "AGENT_PROVIDER_UNSUPPORTED"

    def test_factory_rejects_unknown_provider(self) -> None:
        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(Settings(agent_provider_name="unknown")).create()

        assert captured.value.error_code == "AGENT_PROVIDER_UNSUPPORTED"

    def test_client_backed_provider_requires_injected_client_factory(self) -> None:
        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(
                Settings(
                    agent_provider_name="openai",
                    openai_api_key=SecretStr("test-key"),
                )
            ).create()

        assert captured.value.error_code == "AGENT_CLIENT_FACTORY_MISSING"

    @pytest.mark.parametrize(
        ("settings", "error_code"),
        [
            (Settings(agent_provider_name="openai"), "OPENAI_API_KEY_MISSING"),
            (Settings(agent_provider_name="azure_openai"), "AZURE_OPENAI_CONFIG_MISSING"),
        ],
    )

    def test_provider_factory_rejects_missing_provider_configuration(
        self,
        settings: Settings,
        error_code: str,
    ) -> None:
        with pytest.raises(ConfigurationError) as captured:
            AgentProviderFactory(settings, Mock(spec=AgentClientFactory)).create()

        assert captured.value.error_code == error_code


class TestAgentGatewayErrors:
    """Verify dependency and application failures remain controlled."""

    def test_invalid_provider_response_raises_schema_validation_error(
        self,
        agent_request: AgentRequest,
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.return_value = agent_response_factory({"application_name": "Payments"})
        gateway = agent_gateway_factory(provider, max_schema_repair_attempts=0)

        with pytest.raises(AgentSchemaValidationError) as captured:
            gateway.complete(agent_request)

        assert captured.value.error_code == "AGENT_RESPONSE_SCHEMA_INVALID"
        assert captured.value.retryable is False
        assert captured.value.context is not None
        assert captured.value.context["expected_schema_name"] == "AnalysisSummary"

    def test_unregistered_schema_raises_schema_validation_error(
        self,
        agent_request: AgentRequest,
        agent_gateway_factory: Callable[..., AgentProviderGateway],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        gateway = agent_gateway_factory(provider, PydanticOutputSchemaRegistry({}))

        with pytest.raises(AgentSchemaValidationError) as captured:
            gateway.complete(agent_request)

        assert captured.value.error_code == "AGENT_SCHEMA_NOT_REGISTERED"
        provider.complete.assert_not_called()

    def test_gateway_rejects_invalid_retry_configuration_with_custom_error(
        self, agent_gateway_factory: Callable[..., AgentProviderGateway]
    ) -> None:
        with pytest.raises(ConfigurationError) as captured:
            agent_gateway_factory(Mock(spec=AgentProvider), max_attempts=0)

        assert captured.value.error_code == "AGENT_MAX_ATTEMPTS_INVALID"
        assert captured.value.context == {"max_attempts": 0}

    def test_gateway_retries_retryable_provider_errors(
        self,
        agent_request: AgentRequest,
        valid_output_payload: dict[str, JsonValue],
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        retryable_error = AgentProviderError(
            "temporary provider failure",
            error_code="PROVIDER_TEMPORARY",
            retryable=True,
        )
        provider.complete.side_effect = [
            retryable_error,
            retryable_error,
            agent_response_factory(valid_output_payload, provider_name="flaky"),
        ]
        gateway = agent_gateway_factory(provider, max_attempts=3)

        response = gateway.complete(agent_request)

        assert provider.complete.call_count == 3
        assert isinstance(response.output_payload, dict)
        assert response.output_payload["component_count"] == 2

    def test_gateway_does_not_retry_non_retryable_provider_errors(
        self,
        agent_request: AgentRequest,
        agent_gateway_factory: Callable[..., AgentProviderGateway],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.side_effect = AgentProviderError(
            "permanent provider failure",
            error_code="PROVIDER_PERMANENT",
            retryable=False,
        )
        gateway = agent_gateway_factory(provider, max_attempts=3)

        with pytest.raises(AgentProviderError):
            gateway.complete(agent_request)

        assert provider.complete.call_count == 1

    def test_gateway_fails_cleanly_after_schema_repair_exhaustion(
        self,
        agent_request: AgentRequest,
        agent_gateway_factory: Callable[..., AgentProviderGateway],
        agent_response_factory: Callable[..., AgentResponse],
    ) -> None:
        provider = Mock(spec=AgentProvider)
        provider.complete.side_effect = [
            agent_response_factory({"application_name": "Payments"}),
            agent_response_factory({"application_name": "Still invalid"}),
            agent_response_factory("[]"),
        ]

        with pytest.raises(AgentSchemaValidationError) as captured:
            agent_gateway_factory(provider, max_schema_repair_attempts=2).complete(agent_request)

        assert captured.value.error_code == "AGENT_RESPONSE_SCHEMA_INVALID"
        assert captured.value.context is not None
        assert captured.value.context["schema_repair_attempts"] == 2
        assert provider.complete.call_count == 3

    @pytest.mark.parametrize(
        ("provider_type", "error_code"),
        [
            (OpenAIAgentProvider, "OPENAI_REQUEST_FAILED"),
            (AzureOpenAIAgentProvider, "AZURE_OPENAI_REQUEST_FAILED"),
        ],
    )

    def test_client_provider_translates_unexpected_sdk_failures(
        self,
        provider_type: type[OpenAIAgentProvider] | type[AzureOpenAIAgentProvider],
        error_code: str,
        agent_request: AgentRequest,
    ) -> None:
        client = Mock(spec=AgentClient)
        client.complete.side_effect = RuntimeError("SDK failure")
        provider = provider_type(client)

        with pytest.raises(AgentProviderError) as captured:
            provider.complete(agent_request)

        assert captured.value.error_code == error_code
        assert captured.value.retryable is True

    @pytest.mark.parametrize("provider_type", [OpenAIAgentProvider, AzureOpenAIAgentProvider])

    def test_client_provider_reraises_agent_provider_errors(
        self,
        provider_type: type[OpenAIAgentProvider] | type[AzureOpenAIAgentProvider],
        agent_request: AgentRequest,
    ) -> None:
        client = Mock(spec=AgentClient)
        original = AgentProviderError(
            "rate limited", error_code="AGENT_PROVIDER_RATE_LIMIT", retryable=True
        )
        client.complete.side_effect = original
        provider = provider_type(client)

        with pytest.raises(AgentProviderError) as captured:
            provider.complete(agent_request)

        assert captured.value is original

    def test_retry_loop_assertion_when_max_attempts_is_zero(
        self,
        agent_request: AgentRequest,
        agent_gateway_factory: Callable[..., AgentProviderGateway],
    ) -> None:
        gateway = agent_gateway_factory(Mock(spec=AgentProvider), max_attempts=1)
        object.__setattr__(gateway, "_max_attempts", 0)

        with pytest.raises(AssertionError, match="Agent retry loop completed without a response"):
            gateway._complete_with_retry(agent_request)
