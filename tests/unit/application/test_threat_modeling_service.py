"""Tests for the threat-modeling facade."""

from collections.abc import Callable
from unittest.mock import Mock

import pytest
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.downstream_artifact_generation import DownstreamArtifactGenerationStrategy
from threatmodeler.domain.inventory_generation import InventoryGenerationService
from threatmodeler.domain.missing_information_policy import (
    BlockingMissingInformationPolicy,
    PermissiveMissingInformationPolicy,
)
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.stride_generation import StrideThreatGenerationService
from threatmodeler.errors import MissingInformationError
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator


class TestThreatModelingServicePositive:
    """Verify the facade coordinates injected collaborators."""

    def test_generate_invokes_downstream_methods_in_pipeline_order(
        self,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
        threat_modeling_service_factory: Callable[
            [AgentProvider, ArtifactValidator | None], ThreatModelingService
        ],
    ) -> None:
        service = threat_modeling_service_factory(agent_provider, None)
        original = service._downstream_strategy
        downstream = Mock(spec=DownstreamArtifactGenerationStrategy)
        downstream.generate_dfd.side_effect = original.generate_dfd
        downstream.generate_architecture_graph.side_effect = original.generate_architecture_graph
        downstream.generate_attack_tree.side_effect = original.generate_attack_tree
        downstream.generate_abuse_cases.side_effect = original.generate_abuse_cases
        downstream.generate_risk_register.side_effect = original.generate_risk_register
        downstream.generate_mitigation_plan.side_effect = original.generate_mitigation_plan
        downstream.generate_security_requirements.side_effect = (
            original.generate_security_requirements
        )
        downstream.generate_missing_information.side_effect = original.generate_missing_information
        downstream.generate_control_mapping.side_effect = original.generate_control_mapping
        downstream.generate_executive_summary.side_effect = original.generate_executive_summary
        downstream.generate_technical_report.side_effect = original.generate_technical_report
        service._downstream_strategy = downstream

        bundle = service.generate(canonical_system_model)

        assert bundle.artifact_id == "artifact-bundle"
        assert [call[0] for call in downstream.method_calls] == [
            "generate_dfd",
            "generate_architecture_graph",
            "generate_attack_tree",
            "generate_abuse_cases",
            "generate_risk_register",
            "generate_mitigation_plan",
            "generate_security_requirements",
            "generate_missing_information",
            "generate_control_mapping",
            "generate_executive_summary",
            "generate_technical_report",
        ]

    def test_validator_is_called_for_each_artifact_and_the_bundle(
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
        service._missing_information_policy = PermissiveMissingInformationPolicy()

        bundle = service.generate(canonical_system_model)

        assert validator.validate.call_count == 23
        assert bundle.stride_threat_register.threats


class TestThreatModelingServiceErrors:
    """Verify blocking policy fails before artifact generation."""

    def test_blocking_policy_raises_before_inventory_generation(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        inventory = Mock(spec=InventoryGenerationService)
        service = ThreatModelingService(
            inventory_service=inventory,
            stride_service=Mock(spec=StrideThreatGenerationService),
            downstream_strategy=Mock(spec=DownstreamArtifactGenerationStrategy),
            report_service=Mock(spec=ReportGenerationService),
            completeness_service=Mock(),
            artifact_validator=Mock(spec=ArtifactValidator),
            metadata=ArtifactMetadataService(),
            missing_information_policy=BlockingMissingInformationPolicy(),
        )

        with pytest.raises(MissingInformationError) as captured:
            service.generate(canonical_system_model)

        assert captured.value.error_code == "MISSING_INFORMATION_BLOCKING"
        inventory.generate_component_inventory.assert_not_called()
