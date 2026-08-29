"""Tests for agent-backed downstream artifact generation."""

from collections.abc import Callable

import pytest
from pydantic import JsonValue
from threatmodeler.contracts.artifacts import ArtifactModel
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.control_mapping import ControlMappingService
from threatmodeler.domain.downstream_artifact_generation import (
    AgentDownstreamArtifactGenerationStrategy,
)
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
from threatmodeler.orchestration.prompts.registry import ArtifactPromptBuilderFactory
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.mock_agent_provider import create_mock_agent_provider_for_agent_assisted


@pytest.fixture
def stride_service() -> StrideThreatGenerationService:
    schema_provider = PydanticSchemaProvider()
    return StrideThreatGenerationService(
        AgentStrideThreatGenerationStrategy(
            create_mock_agent_provider_for_agent_assisted(),
            StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
            schema_provider,
        ),
        ArtifactMetadataService(),
    )


@pytest.fixture
def agent_downstream_strategy_factory() -> Callable[
    [dict[str, dict[str, JsonValue]] | None],
    AgentDownstreamArtifactGenerationStrategy,
]:
    def create(
        task_overrides: dict[str, dict[str, JsonValue]] | None = None,
    ) -> AgentDownstreamArtifactGenerationStrategy:
        schema_provider = PydanticSchemaProvider()
        return AgentDownstreamArtifactGenerationStrategy(
            tool_calling_provider=create_mock_agent_provider_for_agent_assisted(task_overrides),
            prompt_registry=ArtifactPromptBuilderFactory(
                SecurePromptTemplate(),
                schema_provider,
            ).create(),
            schema_provider=schema_provider,
        )

    return create


class TestAgentDownstreamArtifactGenerationPositive:
    """Verify agent-backed artifact generation uses prompt builders."""

    @pytest.mark.parametrize(
        "invoke",
        [
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_dfd(model)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_attack_tree(model, threats)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_abuse_cases(model, threats)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_risk_register(model, threats)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_mitigation_plan(model, risks, threats)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_security_requirements(model, threats, risks)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_missing_information(model)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_control_mapping(model, risks, mitigations, requirements, threats)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_executive_summary(model, threats, risks, mitigations)
            ),
            lambda strategy, model, threats, risks, mitigations, requirements: (
                strategy.generate_technical_report(model, threats, risks)
            ),
        ],
    )

    def test_all_downstream_methods_return_validated_artifacts(
        self,
        canonical_system_model: CanonicalSystemModel,
        invoke: Callable[..., ArtifactModel],
        stride_service: StrideThreatGenerationService,
        agent_downstream_strategy_factory: Callable[
            [dict[str, dict[str, JsonValue]] | None],
            AgentDownstreamArtifactGenerationStrategy,
        ],
    ) -> None:
        metadata = ArtifactMetadataService()
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model, risks
        )
        requirements = MitigationGenerationService(metadata).generate_requirements(
            canonical_system_model, threats, risks
        )
        strategy = agent_downstream_strategy_factory(None)

        artifact = invoke(
            strategy, canonical_system_model, threats, risks, mitigations, requirements
        )

        assert artifact.artifact_id


class TestAgentDownstreamArtifactGenerationErrors:
    """Verify invalid agent output is translated into schema errors."""

    @pytest.mark.parametrize(
        ("task_name", "invoke"),
        [
            (
                "generate_dfd",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_dfd(model)
                ),
            ),
            (
                "generate_attack_tree",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_attack_tree(model, threats)
                ),
            ),
            (
                "generate_abuse_cases",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_abuse_cases(model, threats)
                ),
            ),
            (
                "generate_risk_register",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_risk_register(model, threats)
                ),
            ),
            (
                "generate_mitigation_plan",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_mitigation_plan(model, risks, threats)
                ),
            ),
            (
                "generate_security_requirements",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_security_requirements(model, threats, risks)
                ),
            ),
            (
                "generate_missing_information",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_missing_information(model)
                ),
            ),
            (
                "generate_control_mapping",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_control_mapping(
                        model, risks, mitigations, requirements, threats
                    )
                ),
            ),
            (
                "generate_executive_summary",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_executive_summary(model, threats, risks, mitigations)
                ),
            ),
            (
                "generate_technical_report",
                lambda strategy, model, threats, risks, mitigations, requirements: (
                    strategy.generate_technical_report(model, threats, risks)
                ),
            ),
        ],
    )

    def test_invalid_agent_output_raises_schema_validation_error(
        self,
        canonical_system_model: CanonicalSystemModel,
        task_name: str,
        invoke: Callable[..., ArtifactModel],
        stride_service: StrideThreatGenerationService,
        agent_downstream_strategy_factory: Callable[
            [dict[str, dict[str, JsonValue]] | None],
            AgentDownstreamArtifactGenerationStrategy,
        ],
    ) -> None:
        metadata = ArtifactMetadataService()
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model, risks
        )
        requirements = MitigationGenerationService(metadata).generate_requirements(
            canonical_system_model, threats, risks
        )
        strategy = agent_downstream_strategy_factory({task_name: {"invalid": True}})

        with pytest.raises(AgentSchemaValidationError) as captured:
            invoke(strategy, canonical_system_model, threats, risks, mitigations, requirements)

        assert captured.value.error_code == "AGENT_ARTIFACT_SCHEMA_INVALID"


class TestAgentControlMappingCatalogErrors:
    """Verify invented ASVS identifiers fail the catalog rule."""

    def test_unknown_asvs_id_raises_catalog_error(
        self,
        canonical_system_model: CanonicalSystemModel,
        stride_service: StrideThreatGenerationService,
        agent_downstream_strategy_factory: Callable[
            [dict[str, dict[str, JsonValue]] | None],
            AgentDownstreamArtifactGenerationStrategy,
        ],
    ) -> None:
        metadata = ArtifactMetadataService()
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model, risks
        )
        requirements = MitigationGenerationService(metadata).generate_requirements(
            canonical_system_model, threats, risks
        )
        payload = (
            ControlMappingService(metadata)
            .generate(canonical_system_model, risks, mitigations, requirements)
            .model_dump(mode="json")
        )
        controls = payload["controls"]
        assert isinstance(controls, list)
        first_control = controls[0]
        assert isinstance(first_control, dict)
        first_control["framework_control_id"] = "AC-1"
        strategy = agent_downstream_strategy_factory({"generate_control_mapping": payload})

        with pytest.raises(AgentSchemaValidationError) as captured:
            strategy.generate_control_mapping(
                canonical_system_model, risks, mitigations, requirements, threats
            )

        assert captured.value.error_code == "CONTROL_MAPPING_CATALOG_INVALID"
