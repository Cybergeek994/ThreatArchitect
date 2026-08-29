"""Tests for threat-modeling service factory wiring."""

from unittest.mock import Mock

import pytest
from threatmodeler.application.threat_modeling_factory import ThreatModelingServiceFactory
from threatmodeler.config.settings import Settings
from threatmodeler.domain.downstream_artifact_generation import (
    AgentDownstreamArtifactGenerationStrategy,
)
from threatmodeler.domain.missing_information_policy import (
    BlockingMissingInformationPolicy,
    PermissiveMissingInformationPolicy,
)
from threatmodeler.orchestration.prompts import SchemaRepairPromptBuilder, SecurePromptTemplate
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.mock_agent_provider import create_mock_agent_provider_for_agent_assisted


@pytest.fixture
def threat_modeling_service_factory_under_test() -> ThreatModelingServiceFactory:
    """Return a factory with default settings."""
    template = SecurePromptTemplate()
    return ThreatModelingServiceFactory(
        settings=Settings(),
        schema_provider=PydanticSchemaProvider(),
        secure_prompt_template=template,
        repair_prompt_builder=SchemaRepairPromptBuilder(template),
        tool_calling_provider=create_mock_agent_provider_for_agent_assisted(),
    )


@pytest.fixture
def blocking_threat_modeling_factory() -> ThreatModelingServiceFactory:
    """Return a factory configured to block on missing information."""
    template = SecurePromptTemplate()
    return ThreatModelingServiceFactory(
        settings=Settings(fail_on_missing_information=True),
        schema_provider=PydanticSchemaProvider(),
        secure_prompt_template=template,
        repair_prompt_builder=SchemaRepairPromptBuilder(template),
        tool_calling_provider=create_mock_agent_provider_for_agent_assisted(),
    )


class TestThreatModelingServiceFactoryPositive:
    """Verify factory selects the agent strategy and policies from settings."""

    def test_default_settings_use_agent_strategy_and_permissive_policy(
        self,
        threat_modeling_service_factory_under_test: ThreatModelingServiceFactory,
    ) -> None:
        service = threat_modeling_service_factory_under_test.create()

        assert isinstance(service._downstream_strategy, AgentDownstreamArtifactGenerationStrategy)
        assert isinstance(service._missing_information_policy, PermissiveMissingInformationPolicy)
        assert isinstance(service._artifact_validator, PydanticArtifactValidator)

    def test_fail_on_missing_setting_selects_blocking_policy(
        self,
        blocking_threat_modeling_factory: ThreatModelingServiceFactory,
    ) -> None:
        service = blocking_threat_modeling_factory.create()

        assert isinstance(service._missing_information_policy, BlockingMissingInformationPolicy)

    def test_custom_validator_is_injected(self) -> None:
        validator = Mock(spec=ArtifactValidator)
        template = SecurePromptTemplate()
        factory = ThreatModelingServiceFactory(
            settings=Settings(),
            schema_provider=PydanticSchemaProvider(),
            secure_prompt_template=template,
            repair_prompt_builder=SchemaRepairPromptBuilder(template),
            tool_calling_provider=create_mock_agent_provider_for_agent_assisted(),
            artifact_validator=validator,
        )

        service = factory.create()

        assert service._artifact_validator is validator


class TestThreatModelingServiceFactoryNegative:
    """Verify default validator is used when none is provided."""

    def test_omitted_validator_defaults_to_pydantic_validator(
        self,
        threat_modeling_service_factory_under_test: ThreatModelingServiceFactory,
    ) -> None:
        service = threat_modeling_service_factory_under_test.create()

        assert type(service._artifact_validator) is PydanticArtifactValidator
