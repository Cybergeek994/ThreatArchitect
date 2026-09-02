"""Tests for the MVP1 artifact generation facade and file workflow."""

import json
from collections.abc import Callable
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.contracts import ArtifactGenerationResult
from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import AgentSchemaValidationError, ArtifactValidationError
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.shared.constants import LogLevel
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator
from typer.testing import CliRunner

from tests.fixtures.bundle_properties import assert_bundle_integrity


class TestArtifactGenerationEnginePositive:
    """Verify supported inputs and successful behavior."""

    def test_facade_generates_complete_validated_bundle(
        self,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        threat_modeling_service_factory: Callable[
            [AgentProvider, ArtifactValidator | None], ThreatModelingService
        ],
    ) -> None:
        validator = Mock(spec=ArtifactValidator)
        validator.validate.side_effect = PydanticArtifactValidator().validate
        service = threat_modeling_service_factory(agent_provider, validator)

        bundle = service.generate(canonical_system_model)

        assert isinstance(bundle, ArtifactBundle)
        assert validator.validate.call_count == 23
        assert bundle.component_inventory.components[0].id == "component-api"
        assert bundle.asset_inventory.assets[0].data_store_ids == ["store-payments"]
        assert bundle.data_flow_diagram.data_flows[0].id == "flow-payment"
        assert bundle.authentication_authorization_model.authentication_mechanisms
        assert bundle.stride_threat_register.threats[0].component_id == "component-api"
        assert bundle.risk_register.risks[0].threat_ids
        assert bundle.mitigation_plan.mitigations[0].risk_ids
        assert bundle.security_requirements.requirements[0].threat_ids
        assert bundle.control_mapping.controls[0].requirement_ids
        assert bundle.missing_information_report.items[0].question == (
            "Token lifetime is not documented."
        )
        assert ArtifactBundle.model_validate_json(bundle.model_dump_json()) == bundle
        assert_bundle_integrity(bundle, system_model=canonical_system_model)

    def test_file_workflow_writes_all_twenty_named_artifacts(
        self,
        tmp_path: Path,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        artifact_generation_service_factory: Callable[[AgentProvider], ArtifactGenerationService],
    ) -> None:
        input_path = tmp_path / "system-model.json"
        output_dir = tmp_path / "out"
        input_path.write_text(canonical_system_model.model_dump_json(indent=2))

        result = artifact_generation_service_factory(agent_provider).generate(
            input_path, output_dir
        )

        expected_names = {
            "component-inventory.json",
            "asset-inventory.json",
            "actor-model.json",
            "dfd.json",
            "trust-boundary-map.json",
            "entry-points.json",
            "authz-model.json",
            "deployment-model.json",
            "architecture-graph.json",
            "stride-threats.json",
            "attack-tree.json",
            "abuse-cases.json",
            "risk-register.json",
            "mitigation-plan.json",
            "security-requirements.json",
            "assumptions.json",
            "missing-information.json",
            "control-mapping.json",
            "executive-summary.json",
            "technical-report.json",
            "completeness-report.json",
            "artifact-bundle.json",
        }
        assert len(result.artifacts) == 22
        assert {artifact.path.name for artifact in result.artifacts} == expected_names
        assert result.bundle.path.name == "artifact-bundle.json"
        assert {path.name for path in output_dir.glob("*.json")} == expected_names
        assert not list(output_dir.glob("*.tmp"))
        bundle_payload = json.loads((output_dir / "artifact-bundle.json").read_text())
        assert bundle_payload["stride_threat_register"]["threats"]

        restored = ArtifactGenerationResult.model_validate_json(result.model_dump_json())
        assert restored == result

    def test_model_cli_generates_all_artifacts_from_one_input(
        self,
        tmp_path: Path,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        artifact_generation_service_factory: Callable[[AgentProvider], ArtifactGenerationService],
    ) -> None:
        input_path = tmp_path / "system-model.json"
        output_dir = tmp_path / "out"
        input_path.write_text(canonical_system_model.model_dump_json())
        logger = StandardLoggerFactory(LogLevel.INFO, StringIO()).create("test.model")

        unused_ingestion_factory = Mock(
            side_effect=AssertionError("Ingestion should not run during modeling")
        )
        unused_extraction_factory = Mock(
            side_effect=AssertionError("Extraction should not run during modeling")
        )
        unused_rendering_factory = Mock(
            side_effect=AssertionError("Rendering should not run during modeling")
        )
        unused_analysis_factory = Mock(
            side_effect=AssertionError("Analysis should not run during modeling")
        )

        app = create_app(
            unused_ingestion_factory,
            unused_extraction_factory,
            lambda: artifact_generation_service_factory(agent_provider),
            unused_rendering_factory,
            unused_analysis_factory,
            CliErrorHandler(logger),
        )

        result = CliRunner().invoke(
            app,
            ["model", "--input", str(input_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 0
        assert len(list(output_dir.glob("*.json"))) == 22
        assert "artifact-bundle.json" in result.stdout
        unused_ingestion_factory.assert_not_called()
        unused_extraction_factory.assert_not_called()
        unused_rendering_factory.assert_not_called()
        unused_analysis_factory.assert_not_called()


class TestArtifactGenerationEngineNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_invalid_agent_threat_output_fails_before_downstream_generation(
        self,
        agent_provider_factory: Callable[..., Mock],
        canonical_system_model: CanonicalSystemModel,
        threat_modeling_service_factory: Callable[
            [AgentProvider, ArtifactValidator | None], ThreatModelingService
        ],
    ) -> None:
        provider = agent_provider_factory(
            responses={"generate_stride_threats": {"unvalidated": "free form"}}
        )

        with pytest.raises(AgentSchemaValidationError) as captured:
            threat_modeling_service_factory(provider, None).generate(canonical_system_model)

        assert captured.value.error_code == "STRIDE_THREAT_REGISTER_INVALID"

    def test_facade_handles_empty_components_and_data_flows(
        self,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        threat_modeling_service_factory: Callable[
            [AgentProvider, ArtifactValidator | None], ThreatModelingService
        ],
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "components": [],
                "data_stores": [],
                "data_flows": [],
                "trust_boundaries": [],
                "entry_points": [],
            }
        )

        bundle = threat_modeling_service_factory(agent_provider, None).generate(model)

        assert bundle.component_inventory.components == []
        assert bundle.data_flow_diagram.data_flows == []
        assert bundle.stride_threat_register.threats == []

    def test_file_workflow_rejects_invalid_system_model_json(
        self,
        tmp_path: Path,
        agent_provider: Mock,
        artifact_generation_service_factory: Callable[[AgentProvider], ArtifactGenerationService],
    ) -> None:
        input_path = tmp_path / "invalid-system-model.json"
        input_path.write_text('{"application": {}}', encoding="utf-8")

        with pytest.raises(AgentSchemaValidationError) as captured:
            artifact_generation_service_factory(agent_provider).generate(
                input_path, tmp_path / "out"
            )

        assert captured.value.error_code == "SYSTEM_MODEL_LOAD_FAILED"

    def test_generation_result_rejects_an_implicit_or_misnamed_bundle(
        self,
        tmp_path: Path,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        artifact_generation_service_factory: Callable[[AgentProvider], ArtifactGenerationService],
    ) -> None:
        input_path = tmp_path / "system-model.json"
        input_path.write_text(canonical_system_model.model_dump_json())
        result = artifact_generation_service_factory(agent_provider).generate(
            input_path, tmp_path / "out"
        )
        misnamed_bundle = result.bundle.model_copy(
            update={"path": result.bundle.path.with_name("other.json")}
        )

        with pytest.raises(ValidationError, match=r"artifact-bundle\.json"):
            ArtifactGenerationResult(
                artifacts=result.artifacts,
                bundle=misnamed_bundle,
            )


class TestArtifactGenerationEngineErrors:
    """Verify dependency and application failures remain controlled."""

    def test_facade_propagates_artifact_validation_failure(
        self,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        threat_modeling_service_factory: Callable[
            [AgentProvider, ArtifactValidator | None], ThreatModelingService
        ],
    ) -> None:
        validator = Mock(spec=ArtifactValidator)
        validator.validate.side_effect = ArtifactValidationError(
            "Injected artifact validation failure",
            error_code="TEST_ARTIFACT_INVALID",
        )
        service = threat_modeling_service_factory(agent_provider, validator)

        with pytest.raises(ArtifactValidationError, match="Injected"):
            service.generate(canonical_system_model)
