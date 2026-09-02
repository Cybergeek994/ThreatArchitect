"""Tests for schema-bound agent artifact generation."""

from unittest.mock import Mock

import pytest
from threatmodeler.contracts.artifacts import MissingInformationReport
from threatmodeler.contracts.prompts import PromptBuildResult, PromptMessage, PromptRole
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.agent_schema_bound_generator import (
    AgentSchemaBoundArtifactGenerator,
    _chain_item_validators,
)
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.mock_agent_provider import create_mock_agent_provider


@pytest.fixture
def prompt_builder() -> Mock:
    builder = Mock(spec=PromptBuilder)
    builder.build.return_value = PromptBuildResult(
        task_name="generate_missing_information",
        messages=[
            PromptMessage(role=PromptRole.SYSTEM, content="System"),
            PromptMessage(role=PromptRole.DEVELOPER, content="Developer"),
            PromptMessage(role=PromptRole.USER, content="User"),
        ],
        expected_schema_name="MissingInformationReport",
        expected_schema={"type": "object"},
    )
    return builder


class TestAgentSchemaBoundGeneratorPositive:
    """Verify supported inputs and successful behavior."""

    def test_generate_returns_validated_artifact(
        self,
        canonical_system_model: CanonicalSystemModel,
        prompt_builder: Mock,
    ) -> None:
        expected = ReportGenerationService(ArtifactMetadataService()).generate_missing_information(
            canonical_system_model
        )
        provider = create_mock_agent_provider(
            {"generate_missing_information": expected.model_dump(mode="json")}
        )
        generator = AgentSchemaBoundArtifactGenerator(provider, PydanticSchemaProvider())

        report = generator.generate(
            task_name="generate_missing_information",
            output_model=MissingInformationReport,
            prompt_builder=prompt_builder,
            input_payload={"system_model": generator.serialize(canonical_system_model)},
        )

        request = provider.complete_with_tools.call_args.args[0]
        assert report.artifact_id == expected.artifact_id
        assert request.task_name == "generate_missing_information"
        assert request.temperature == 0.0
        assert request.max_output_tokens == 8_000

    def test_serialize_round_trips_json_compatible_payload(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        generator = AgentSchemaBoundArtifactGenerator(
            create_mock_agent_provider(),
            PydanticSchemaProvider(),
        )

        payload = generator.serialize(canonical_system_model)
        application = payload["application"]
        assert isinstance(application, dict)
        assert application["name"] == canonical_system_model.application.name


class TestAgentSchemaBoundGeneratorNegative:
    """Verify extra fields in agent output do not break generation."""

    def test_extra_fields_are_rejected_by_closed_schema(
        self,
        canonical_system_model: CanonicalSystemModel,
        prompt_builder: Mock,
    ) -> None:
        expected = ReportGenerationService(ArtifactMetadataService()).generate_missing_information(
            canonical_system_model
        )
        payload = expected.model_dump(mode="json")
        payload["unexpected"] = True
        provider = create_mock_agent_provider({"generate_missing_information": payload})
        generator = AgentSchemaBoundArtifactGenerator(provider, PydanticSchemaProvider())

        with pytest.raises(AgentSchemaValidationError):
            generator.generate(
                task_name="generate_missing_information",
                output_model=MissingInformationReport,
                prompt_builder=prompt_builder,
                input_payload={},
            )


class TestAgentSchemaBoundGeneratorErrors:
    """Verify invalid agent output is translated into schema errors."""

    def test_invalid_payload_raises_schema_validation_error(self, prompt_builder: Mock) -> None:
        provider = create_mock_agent_provider({"generate_missing_information": {"invalid": True}})
        generator = AgentSchemaBoundArtifactGenerator(provider, PydanticSchemaProvider())

        with pytest.raises(AgentSchemaValidationError) as captured:
            generator.generate(
                task_name="generate_missing_information",
                output_model=MissingInformationReport,
                prompt_builder=prompt_builder,
                input_payload={},
            )

        assert captured.value.error_code == "AGENT_ARTIFACT_SCHEMA_INVALID"
        context = captured.value.context or {}
        assert context["task_name"] == "generate_missing_information"
        assert context["expected_schema_name"] == "MissingInformationReport"
        assert context["validation_errors"]


class TestChainItemValidators:
    """Verify optional item-validator chaining."""

    def test_chain_returns_none_for_empty_input(self) -> None:
        assert _chain_item_validators(None, None) is None

    def test_chain_combines_multiple_validators(self) -> None:
        def first(_list_field: str, _payload: object, _lists: object) -> list[str]:
            return ["first"]

        def second(_list_field: str, _payload: object, _lists: object) -> list[str]:
            return ["second"]

        chained = _chain_item_validators(first, second)
        assert chained is not None
        assert chained("controls", {}, {}) == ["first", "second"]
