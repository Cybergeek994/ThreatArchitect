"""Tests for deterministic mitigation and requirement generation."""

import pytest
from threatmodeler.contracts.artifacts import WorkPriority
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.mock_agent_provider import create_mock_agent_provider


class TestMitigationGenerationPositive:
    """Verify mitigations and requirements are derived from validated risks."""

    def test_generate_plan_links_every_risk(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        service = MitigationGenerationService(metadata)

        plan = service.generate_plan(canonical_system_model, risks)

        assert len(plan.mitigations) == len(risks.risks)
        assert {mitigation.risk_ids[0] for mitigation in plan.mitigations} == {
            risk.id for risk in risks.risks
        }

    def test_generate_requirements_map_threats_to_prioritized_controls(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        service = MitigationGenerationService(metadata)

        requirements = service.generate_requirements(
            canonical_system_model,
            threats,
            risks,
        )

        assert len(requirements.requirements) == len(threats.threats)
        assert all(
            requirement.priority is WorkPriority.MEDIUM for requirement in requirements.requirements
        )


class TestMitigationGenerationPriorityAndCategory:
    """Verify severity and STRIDE category mapping branches."""

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", WorkPriority.CRITICAL),
            ("high", WorkPriority.HIGH),
            ("medium", WorkPriority.MEDIUM),
            ("low", WorkPriority.LOW),
        ],
    )

    def test_priority_mapping(
        self,
        severity: str,
        expected: WorkPriority,
    ) -> None:
        from threatmodeler.contracts.artifacts import RiskSeverity

        service = MitigationGenerationService(ArtifactMetadataService())

        assert service._priority(RiskSeverity(severity)) is expected

    @pytest.mark.parametrize(
        ("category", "expected"),
        [
            ("spoofing", "authentication"),
            ("tampering", "integrity"),
            ("repudiation", "integrity"),
            ("information_disclosure", "confidentiality"),
            ("denial_of_service", "availability"),
            ("elevation_of_privilege", "authorization"),
        ],
    )

    def test_requirement_category_mapping(
        self,
        category: str,
        expected: str,
    ) -> None:
        from threatmodeler.contracts.artifacts import SecurityRequirementCategory

        service = MitigationGenerationService(ArtifactMetadataService())

        assert service._requirement_category(category) is SecurityRequirementCategory(expected)
