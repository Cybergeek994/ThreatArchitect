"""Tests for the artifact prompt-builder registry."""

import pytest
from pydantic import ValidationError
from threatmodeler.orchestration.prompts import SecurePromptTemplate
from threatmodeler.orchestration.prompts.artifact_builders import (
    AbuseCasePromptBuilder,
    AttackTreePromptBuilder,
    ControlMappingPromptBuilder,
    DfdPromptBuilder,
    ExecutiveSummaryPromptBuilder,
    MissingInformationPromptBuilder,
    MitigationPlanPromptBuilder,
    RiskRegisterPromptBuilder,
    SecurityRequirementsPromptBuilder,
    TechnicalReportPromptBuilder,
)
from threatmodeler.orchestration.prompts.registry import ArtifactPromptBuilderFactory
from threatmodeler.ports.artifact_prompt_builder_registry import ArtifactPromptBuilderRegistry
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider


class TestPromptRegistryPositive:
    """Verify the factory exposes one builder per downstream artifact task."""

    def test_factory_creates_frozen_registry_with_ten_builder_types(self) -> None:
        registry = ArtifactPromptBuilderFactory(
            SecurePromptTemplate(),
            PydanticSchemaProvider(),
        ).create()

        assert isinstance(registry, ArtifactPromptBuilderRegistry)
        assert type(registry.missing_information) is MissingInformationPromptBuilder
        assert type(registry.dfd) is DfdPromptBuilder
        assert type(registry.attack_tree) is AttackTreePromptBuilder
        assert type(registry.abuse_cases) is AbuseCasePromptBuilder
        assert type(registry.risk_register) is RiskRegisterPromptBuilder
        assert type(registry.mitigation_plan) is MitigationPlanPromptBuilder
        assert type(registry.security_requirements) is SecurityRequirementsPromptBuilder
        assert type(registry.control_mapping) is ControlMappingPromptBuilder
        assert type(registry.executive_summary) is ExecutiveSummaryPromptBuilder
        assert type(registry.technical_report) is TechnicalReportPromptBuilder


class TestPromptRegistryNegative:
    """Verify the registry cannot be mutated after construction."""

    def test_registry_rejects_field_assignment(self) -> None:
        registry = ArtifactPromptBuilderFactory(
            SecurePromptTemplate(),
            PydanticSchemaProvider(),
        ).create()

        field_name = "dfd"
        with pytest.raises(ValidationError):
            setattr(registry, field_name, registry.attack_tree)
