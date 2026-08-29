"""Tests for agent STRIDE request payloads."""

from unittest.mock import Mock

from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.mock_agent_provider import create_mock_agent_provider


class TestAgentStrideThreatGenerationPositive:
    """Verify STRIDE requests include diagram evidence."""

    def test_generate_includes_diagram_evidence_in_payload(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(update={"diagram_evidence": ["embedded: 1 -> 2"]})
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            ArtifactMetadataService(),
        )

        register = service.generate(model)

        request = provider.complete.call_args.args[0]
        assert register.threats
        assert request.input_payload["diagram_evidence"] == ["embedded: 1 -> 2"]


    def test_stride_generation_bind_journal_skips_non_receiver_strategy(self) -> None:
        from threatmodeler.domain.stride_generation import StrideThreatGenerationService

        service = StrideThreatGenerationService(strategy=Mock(), metadata=Mock())
        service.bind_journal(Mock())
