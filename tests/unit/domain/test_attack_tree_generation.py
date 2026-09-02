"""Unit tests for deterministic attack-tree generation."""

from threatmodeler.contracts.artifacts import (
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    ThreatProvenance,
    ThreatStatus,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.attack_tree_generation import AttackTreeGenerationService

from tests.fixtures.graph_fixtures import (
    architecture_graph_for_model,
    attack_path_narrative,
    default_attack_path_id,
)


class TestAttackTreeGenerationPositive:
    """Verify hierarchical attack-tree derivation."""

    def test_attack_tree_builds_precondition_children(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        threat = StrideThreat(
            id="threat-tree",
            name="Tamper payment flow",
            description="An attacker may modify payment requests.",
            evidence=canonical_system_model.components[0].evidence,
            confidence=0.8,
            assumptions=canonical_system_model.assumptions,
            component_id="component-api",
            category=StrideCategory.TAMPERING,
            status=ThreatStatus.IDENTIFIED,
            attack_preconditions=["Reach the API", "Obtain a valid token"],
            impact="Payment integrity could be compromised.",
            provenance=ThreatProvenance(
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
                attack_path_id=attack_path_id,
                attack_path=attack_path_narrative(graph, attack_path_id),
                rationale="Identified because payment flow integrity depends on the API.",
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
        service = AttackTreeGenerationService(ArtifactMetadataService())

        attack_tree = service.generate(canonical_system_model, threat_register)

        root = attack_tree.root_nodes[0]
        assert root.operator == "and"
        assert len(root.children) == 2
        assert all(child.operator == "leaf" for child in root.children)
