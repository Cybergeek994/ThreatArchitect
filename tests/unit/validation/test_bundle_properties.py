"""Tests for cross-artifact bundle property validation."""

from collections.abc import Callable
from unittest.mock import Mock

import pytest
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.contracts.artifacts import ArtifactBundle, Mitigation, RiskRecord
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator

from tests.fixtures.bundle_properties import (
    assert_bundle_integrity,
    bundle_property_violations,
    collect_bundle_artifact_ids,
    collect_bundle_known_ids,
)


@pytest.fixture
def generated_bundle(
    agent_provider: Mock,
    canonical_system_model: CanonicalSystemModel,
    threat_modeling_service_factory: Callable[
        [AgentProvider, ArtifactValidator | None], ThreatModelingService
    ],
) -> ArtifactBundle:
    """Return a complete bundle from the canonical fixture pipeline."""
    return threat_modeling_service_factory(agent_provider, None).generate(
        canonical_system_model
    )


class TestCollectBundleKnownIdsPositive:
    """Verify known-id harvesting for bundle property checks."""

    def test_collects_entity_and_artifact_ids(
        self,
        generated_bundle: ArtifactBundle,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        known = collect_bundle_known_ids(generated_bundle, system_model=canonical_system_model)

        assert "component-api" in known
        assert "threat-component-api" in known
        assert "trust-level-customer" in known
        assert "component-inventory" in collect_bundle_artifact_ids(generated_bundle)


class TestBundlePropertyInvariantsPositive:
    """Verify valid bundles satisfy property invariants."""

    def test_generated_bundle_passes_integrity_checks(
        self,
        generated_bundle: ArtifactBundle,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        assert_bundle_integrity(generated_bundle, system_model=canonical_system_model)

    def test_checker_returns_no_violations_for_valid_bundle(
        self,
        generated_bundle: ArtifactBundle,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        violations = bundle_property_violations(
            generated_bundle,
            system_model=canonical_system_model,
        )
        assert violations == []


class TestBundlePropertyInvariantsNegative:
    """Verify broken linkage and orphan references are reported."""

    def test_orphan_threat_reference_on_risk_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_risk = generated_bundle.risk_register.risks[0].model_copy(
            update={"threat_ids": ["missing-threat"]}
        )
        broken = generated_bundle.model_copy(
            update={
                "risk_register": generated_bundle.risk_register.model_copy(
                    update={"risks": [broken_risk]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any("unknown threat_ids 'missing-threat'" in violation for violation in violations)

    def test_orphan_component_reference_on_threat_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_threat = generated_bundle.stride_threat_register.threats[0].model_copy(
            update={"component_id": "missing-component"}
        )
        broken = generated_bundle.model_copy(
            update={
                "stride_threat_register": generated_bundle.stride_threat_register.model_copy(
                    update={"threats": [broken_threat]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any(
            "unknown component_id 'missing-component'" in violation for violation in violations
        )

    def test_mitigation_without_risk_or_threat_links_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_mitigation = generated_bundle.mitigation_plan.mitigations[0].model_copy(
            update={"risk_ids": [], "threat_ids": []}
        )
        broken = generated_bundle.model_copy(
            update={
                "mitigation_plan": generated_bundle.mitigation_plan.model_copy(
                    update={"mitigations": [broken_mitigation]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any(
            "must reference risk_ids and/or threat_ids" in violation for violation in violations
        )

    def test_unknown_referenced_artifact_id_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_section = generated_bundle.technical_report.sections[0].model_copy(
            update={"referenced_artifact_ids": ["missing-artifact"]}
        )
        broken = generated_bundle.model_copy(
            update={
                "technical_report": generated_bundle.technical_report.model_copy(
                    update={"sections": [broken_section]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any(
            "unknown referenced_artifact_id 'missing-artifact'" in violation
            for violation in violations
        )

    def test_risk_without_threat_ids_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_risk = RiskRecord.model_construct(
            id="risk-empty-threats",
            name="Broken risk",
            description="Risk without upstream threats",
            confidence=0.5,
            threat_ids=[],
            severity=generated_bundle.risk_register.risks[0].severity,
            likelihood=generated_bundle.risk_register.risks[0].likelihood,
            status=generated_bundle.risk_register.risks[0].status,
        )
        broken = generated_bundle.model_copy(
            update={
                "risk_register": generated_bundle.risk_register.model_copy(
                    update={"risks": [broken_risk]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any("must reference at least one threat_id" in violation for violation in violations)

    def test_mitigation_with_only_orphan_risk_ids_is_reported(
        self,
        generated_bundle: ArtifactBundle,
    ) -> None:
        broken_mitigation = Mitigation.model_construct(
            id="mitigation-orphan-risk",
            name="Broken mitigation",
            description="Mitigation with dangling risk reference",
            confidence=0.5,
            risk_ids=["missing-risk"],
            threat_ids=[],
            status=generated_bundle.mitigation_plan.mitigations[0].status,
            priority=generated_bundle.mitigation_plan.mitigations[0].priority,
        )
        broken = generated_bundle.model_copy(
            update={
                "mitigation_plan": generated_bundle.mitigation_plan.model_copy(
                    update={"mitigations": [broken_mitigation]}
                )
            }
        )

        violations = bundle_property_violations(broken)

        assert any("unknown risk_ids 'missing-risk'" in violation for violation in violations)
