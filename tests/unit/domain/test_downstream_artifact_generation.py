"""Tests for deterministic downstream artifact generation."""

from unittest.mock import Mock

from threatmodeler.contracts.artifacts import MitigationPlan, RiskRegister, StrideThreatRegister
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.attack_tree_generation import AttackTreeGenerationService
from threatmodeler.domain.control_mapping import ControlMappingService
from threatmodeler.domain.dfd_generation import DfdGenerationService
from threatmodeler.domain.downstream_artifact_generation import (
    DeterministicDownstreamArtifactGenerationStrategy,
)
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import StrideThreatGenerationService


class TestDeterministicDownstreamArtifactGenerationPositive:
    """Verify deterministic strategy delegates to injected domain services."""

    def test_all_methods_delegate_to_injected_services(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        dfd_service = Mock(spec=DfdGenerationService)
        attack_tree_service = Mock(spec=AttackTreeGenerationService)
        stride_service = Mock(spec=StrideThreatGenerationService)
        risk_service = Mock(spec=RiskScoringService)
        mitigation_service = Mock(spec=MitigationGenerationService)
        control_mapping_service = Mock(spec=ControlMappingService)
        report_service = Mock(spec=ReportGenerationService)
        strategy = DeterministicDownstreamArtifactGenerationStrategy(
            dfd_service=dfd_service,
            attack_tree_service=attack_tree_service,
            stride_service=stride_service,
            risk_service=risk_service,
            mitigation_service=mitigation_service,
            control_mapping_service=control_mapping_service,
            report_service=report_service,
        )
        threats = Mock(spec=StrideThreatRegister)
        risks = Mock(spec=RiskRegister)
        mitigations = Mock(spec=MitigationPlan)
        requirements = Mock()

        assert strategy.generate_dfd(canonical_system_model) is dfd_service.generate.return_value
        assert (
            strategy.generate_attack_tree(canonical_system_model, threats)
            is attack_tree_service.generate.return_value
        )
        assert (
            strategy.generate_abuse_cases(canonical_system_model, threats)
            is stride_service.generate_abuse_cases.return_value
        )
        assert (
            strategy.generate_risk_register(canonical_system_model, threats)
            is risk_service.generate.return_value
        )
        assert (
            strategy.generate_mitigation_plan(canonical_system_model, risks, threats)
            is mitigation_service.generate_plan.return_value
        )
        assert (
            strategy.generate_security_requirements(canonical_system_model, threats, risks)
            is mitigation_service.generate_requirements.return_value
        )
        assert (
            strategy.generate_missing_information(canonical_system_model)
            is report_service.generate_missing_information.return_value
        )
        assert (
            strategy.generate_control_mapping(
                canonical_system_model, risks, mitigations, requirements, threats
            )
            is control_mapping_service.generate.return_value
        )
        assert (
            strategy.generate_executive_summary(canonical_system_model, threats, risks, mitigations)
            is report_service.generate_executive_summary.return_value
        )
        assert (
            strategy.generate_technical_report(canonical_system_model, threats, risks)
            is report_service.generate_technical_report.return_value
        )
        dfd_service.generate.assert_called_once_with(canonical_system_model)
        attack_tree_service.generate.assert_called_once_with(canonical_system_model, threats)
        stride_service.generate_abuse_cases.assert_called_once_with(canonical_system_model, threats)
        risk_service.generate.assert_called_once_with(canonical_system_model, threats)
        mitigation_service.generate_plan.assert_called_once_with(canonical_system_model, risks)
        mitigation_service.generate_requirements.assert_called_once_with(
            canonical_system_model, threats, risks
        )
        report_service.generate_missing_information.assert_called_once_with(canonical_system_model)
        control_mapping_service.generate.assert_called_once_with(
            canonical_system_model, risks, mitigations, requirements
        )
        report_service.generate_executive_summary.assert_called_once_with(
            canonical_system_model, threats, risks, mitigations
        )
        report_service.generate_technical_report.assert_called_once_with(
            canonical_system_model, threats, risks
        )


class TestDeterministicDownstreamArtifactGenerationNegative:
    """Verify unused collaborators are not invoked for isolated methods."""

    def test_generate_dfd_does_not_call_risk_or_mitigation_services(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        risk_service = Mock(spec=RiskScoringService)
        mitigation_service = Mock(spec=MitigationGenerationService)
        strategy = DeterministicDownstreamArtifactGenerationStrategy(
            dfd_service=Mock(spec=DfdGenerationService),
            attack_tree_service=Mock(spec=AttackTreeGenerationService),
            stride_service=Mock(spec=StrideThreatGenerationService),
            risk_service=risk_service,
            mitigation_service=mitigation_service,
            control_mapping_service=Mock(spec=ControlMappingService),
            report_service=Mock(spec=ReportGenerationService),
        )

        strategy.generate_dfd(canonical_system_model)

        risk_service.generate.assert_not_called()
        mitigation_service.generate_plan.assert_not_called()
