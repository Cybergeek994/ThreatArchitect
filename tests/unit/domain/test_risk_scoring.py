"""Unit tests for deterministic risk scoring."""

import pytest
from threatmodeler.contracts.artifacts import (
    RiskLikelihood,
    RiskSeverity,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    ThreatProvenance,
    ThreatStatus,
)
from threatmodeler.contracts.artifacts.threats import (
    ThreatExploitabilityAssessment,
    ThreatImpactAssessment,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.risk_scoring import RiskScoringService

from tests.fixtures.graph_fixtures import (
    architecture_graph_for_model,
    attack_path_narrative,
    default_attack_path_id,
)


@pytest.fixture
def threat_factory(canonical_system_model: CanonicalSystemModel):
    """Return a factory for creating test threats with optional OWASP assessments."""

    def create(
        threat_id: str = "threat-test",
        category: StrideCategory = StrideCategory.SPOOFING,
        component_id: str | None = "component-api",
        exploitability: ThreatExploitabilityAssessment | None = None,
        impact_assessment: ThreatImpactAssessment | None = None,
    ) -> StrideThreat:
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        return StrideThreat(
            id=threat_id,
            name="Test threat",
            description="Test threat description.",
            evidence=canonical_system_model.components[0].evidence,
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            component_id=component_id,
            category=category,
            status=ThreatStatus.IDENTIFIED,
            impact="Test impact.",
            exploitability=exploitability,
            impact_assessment=impact_assessment,
            provenance=ThreatProvenance(
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
                attack_path_id=attack_path_id,
                attack_path=attack_path_narrative(graph, attack_path_id),
                rationale="Identified from fixture architecture evidence.",
            ),
        )

    return create


@pytest.fixture
def exploitability_factory():
    """Return a factory for creating exploitability assessments."""

    def create(
        *,
        remote: bool = False,
        auth_required: bool = True,
        automatable: bool = False,
    ) -> ThreatExploitabilityAssessment:
        return ThreatExploitabilityAssessment(
            exploitable_remotely=remote,
            requires_authentication=auth_required,
            exploit_automatable=automatable,
        )

    return create


@pytest.fixture
def impact_factory():
    """Return a factory for creating impact assessments."""

    def create(
        *,
        full_compromise: bool = False,
        admin_access: bool = False,
        crash_possible: bool = False,
        data_exposure: bool = False,
    ) -> ThreatImpactAssessment:
        return ThreatImpactAssessment(
            full_system_compromise=full_compromise,
            admin_access_possible=admin_access,
            system_crash_possible=crash_possible,
            sensitive_data_exposure=data_exposure,
        )

    return create


class TestRiskScoringPositive:
    """Verify architecture-aware qualitative scoring."""

    def test_external_component_threats_receive_likely_rating(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        threat = StrideThreat(
            id="threat-external",
            name="Spoof customer",
            description="Customer identity may be spoofed at the API.",
            evidence=canonical_system_model.components[0].evidence,
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            component_id="component-api",
            category=StrideCategory.SPOOFING,
            status=ThreatStatus.IDENTIFIED,
            impact="Unauthorized access to payment operations.",
            provenance=ThreatProvenance(
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
                attack_path_id=attack_path_id,
                attack_path=attack_path_narrative(graph, attack_path_id),
                rationale="Identified from external API exposure evidence.",
            ),
        )
        threat_register = StrideThreatRegister(
            artifact_id="stride-threat-register",
            title="STRIDE Threat Register",
            description="Test threats",
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            threats=[threat],
        )
        service = RiskScoringService(ArtifactMetadataService())

        risk_register = service.generate(canonical_system_model, threat_register)

        assert risk_register.risks[0].likelihood is RiskLikelihood.LIKELY

    def test_internal_component_threats_receive_possible_rating(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        threat = StrideThreat(
            id="threat-internal",
            name="Tamper with batch job",
            description="Internal processing may be tampered with.",
            evidence=canonical_system_model.components[0].evidence,
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            component_id="component-api",
            category=StrideCategory.TAMPERING,
            status=ThreatStatus.IDENTIFIED,
            impact="Integrity loss for internal records.",
            provenance=ThreatProvenance(
                attack_path_id=attack_path_id,
                attack_path=attack_path_narrative(graph, attack_path_id),
                rationale="Identified from internal processing architecture evidence.",
            ),
        )
        threat_register = StrideThreatRegister(
            artifact_id="stride-threat-register",
            title="STRIDE Threat Register",
            description="Test threats",
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            threats=[threat],
        )
        internal_entry = canonical_system_model.entry_points[0].model_copy(
            update={"exposure": ExposureType.INTERNAL}
        )
        model = canonical_system_model.model_copy(update={"entry_points": [internal_entry]})
        service = RiskScoringService(ArtifactMetadataService())

        risk_register = service.generate(model, threat_register)

        assert risk_register.risks[0].likelihood is RiskLikelihood.POSSIBLE


class TestRiskScoringSeverityMatrix:
    """Verify STRIDE category to severity mapping branches."""

    @pytest.mark.parametrize(
        ("category", "expected"),
        [
            (StrideCategory.INFORMATION_DISCLOSURE, RiskSeverity.HIGH),
            (StrideCategory.ELEVATION_OF_PRIVILEGE, RiskSeverity.HIGH),
            (StrideCategory.SPOOFING, RiskSeverity.MEDIUM),
            (StrideCategory.TAMPERING, RiskSeverity.MEDIUM),
            (StrideCategory.DENIAL_OF_SERVICE, RiskSeverity.MEDIUM),
            (StrideCategory.REPUDIATION, RiskSeverity.LOW),
        ],
    )
    def test_severity_mapping_from_category(
        self,
        category: StrideCategory,
        expected: RiskSeverity,
    ) -> None:
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity_from_category(category) is expected

    def test_likelihood_uses_component_ids_when_component_id_is_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        threat = StrideThreat(
            id="threat-multi-target",
            name="Spoof customer",
            description="Customer identity may be spoofed at the API.",
            evidence=canonical_system_model.components[0].evidence,
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            component_id=None,
            component_ids=["component-api"],
            category=StrideCategory.SPOOFING,
            status=ThreatStatus.IDENTIFIED,
            impact="Unauthorized access to payment operations.",
            provenance=ThreatProvenance(
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
                attack_path_id=attack_path_id,
                attack_path=attack_path_narrative(graph, attack_path_id),
                rationale="Identified from multi-target API exposure evidence.",
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        likelihood = service._likelihood(
            threat,
            {canonical_system_model.entry_points[0].component_id},
        )

        assert likelihood is RiskLikelihood.LIKELY


class TestOwaspRiskAssessment:
    """Verify OWASP-style risk assessment using qualitative questions."""

    def test_full_system_compromise_yields_critical_severity(
        self,
        threat_factory,
        impact_factory,
    ) -> None:
        threat = threat_factory(
            impact_assessment=impact_factory(full_compromise=True),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity(threat) is RiskSeverity.CRITICAL

    def test_admin_access_yields_high_severity(
        self,
        threat_factory,
        impact_factory,
    ) -> None:
        threat = threat_factory(
            impact_assessment=impact_factory(admin_access=True),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity(threat) is RiskSeverity.HIGH

    def test_sensitive_data_exposure_yields_high_severity(
        self,
        threat_factory,
        impact_factory,
    ) -> None:
        threat = threat_factory(
            impact_assessment=impact_factory(data_exposure=True),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity(threat) is RiskSeverity.HIGH

    def test_system_crash_yields_high_severity(
        self,
        threat_factory,
        impact_factory,
    ) -> None:
        threat = threat_factory(
            impact_assessment=impact_factory(crash_possible=True),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity(threat) is RiskSeverity.HIGH

    def test_no_impact_flags_falls_back_to_category(
        self,
        threat_factory,
        impact_factory,
    ) -> None:
        threat = threat_factory(
            category=StrideCategory.REPUDIATION,
            impact_assessment=impact_factory(),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._severity(threat) is RiskSeverity.LOW

    def test_remote_automatable_no_auth_yields_almost_certain(
        self,
        threat_factory,
        exploitability_factory,
    ) -> None:
        threat = threat_factory(
            exploitability=exploitability_factory(
                remote=True,
                automatable=True,
                auth_required=False,
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._likelihood(threat, set()) is RiskLikelihood.ALMOST_CERTAIN

    def test_remote_automatable_with_auth_yields_likely(
        self,
        threat_factory,
        exploitability_factory,
    ) -> None:
        threat = threat_factory(
            exploitability=exploitability_factory(
                remote=True,
                automatable=True,
                auth_required=True,
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._likelihood(threat, set()) is RiskLikelihood.LIKELY

    def test_remote_not_automatable_yields_likely(
        self,
        threat_factory,
        exploitability_factory,
    ) -> None:
        threat = threat_factory(
            exploitability=exploitability_factory(
                remote=True,
                automatable=False,
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._likelihood(threat, set()) is RiskLikelihood.LIKELY

    def test_local_automatable_yields_possible(
        self,
        threat_factory,
        exploitability_factory,
    ) -> None:
        threat = threat_factory(
            exploitability=exploitability_factory(
                remote=False,
                automatable=True,
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._likelihood(threat, set()) is RiskLikelihood.POSSIBLE

    def test_local_manual_yields_unlikely(
        self,
        threat_factory,
        exploitability_factory,
    ) -> None:
        threat = threat_factory(
            exploitability=exploitability_factory(
                remote=False,
                automatable=False,
            ),
        )
        service = RiskScoringService(ArtifactMetadataService())

        assert service._likelihood(threat, set()) is RiskLikelihood.UNLIKELY
