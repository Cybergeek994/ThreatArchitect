"""Tests for STRIDE threat provenance item validators."""

from typing import cast

import pytest
from pydantic import JsonValue
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.validation.threat_provenance_validator import (
    AttackPathGraphConsistencyRule,
    CrossedBoundaryRule,
    EntryActorLinkRule,
    EvidenceRequiredRule,
    ExternalEntryPointRule,
    ProvenanceFieldsPresentRule,
    ThreatListField,
    ThreatProvenanceValidatorFactory,
)

from tests.fixtures.graph_fixtures import (
    architecture_graph_for_model,
    attack_path_narrative,
    default_attack_path_id,
    stride_validator_input_payload,
)


def _threat_payload(
    model: CanonicalSystemModel,
    **overrides: object,
) -> dict[str, JsonValue]:
    graph = architecture_graph_for_model(model)
    attack_path_id = default_attack_path_id(graph)
    payload: dict[str, JsonValue] = {
        "id": "threat-api",
        "name": "Spoof API",
        "description": "desc",
        "evidence": [{"summary": "supported", "source_references": []}],
        "confidence": 0.8,
        "component_id": "component-api",
        "category": "spoofing",
        "status": "identified",
        "impact": "impact",
        "provenance": {
            "entry_point_id": "entry-payments",
            "actor_id": "actor-customer",
            "attack_path_id": attack_path_id,
            "attack_path": attack_path_narrative(graph, attack_path_id),
            "rationale": "Identified because the API is externally exposed.",
        },
    }
    payload.update(cast(dict[str, JsonValue], overrides))
    return payload


class TestThreatProvenanceRules:
    """Verify hard provenance predicates."""

    def test_evidence_required(self, canonical_system_model: CanonicalSystemModel) -> None:
        rule = EvidenceRequiredRule()
        assert rule.validate_threat(_threat_payload(canonical_system_model, evidence=[]))

    def test_provenance_must_be_object(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ProvenanceFieldsPresentRule()
        assert rule.validate_threat(_threat_payload(canonical_system_model, provenance="bad"))

    def test_provenance_fields_required(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ProvenanceFieldsPresentRule()
        assert rule.validate_threat(
            _threat_payload(canonical_system_model, provenance={"attack_path": []})
        )

    def test_provenance_rationale_must_be_nonempty(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ProvenanceFieldsPresentRule()
        violations = rule.validate_threat(
            _threat_payload(
                canonical_system_model,
                provenance={
                    "attack_path_id": "path",
                    "attack_path": ["step"],
                    "rationale": "  ",
                },
            )
        )
        assert any("rationale" in item for item in violations)

    def test_external_entry_requires_entry_point_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ExternalEntryPointRule(canonical_system_model)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path_id": default_attack_path_id(
                    architecture_graph_for_model(canonical_system_model)
                ),
                "attack_path": ["step"],
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "entry_point_id" in violations[0]

    def test_external_entry_rejects_mismatched_entry_point_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ExternalEntryPointRule(canonical_system_model)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "entry_point_id": "entry-unknown",
                "attack_path_id": default_attack_path_id(
                    architecture_graph_for_model(canonical_system_model)
                ),
                "attack_path": ["step"],
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "does not match" in violations[0]

    def test_external_entry_skips_when_no_external_entries(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    entry.model_copy(update={"exposure": ExposureType.INTERNAL})
                    for entry in canonical_system_model.entry_points
                ]
            }
        )
        rule = ExternalEntryPointRule(model)
        assert rule.validate_threat(_threat_payload(model)) == []

    def test_external_entry_skips_when_components_do_not_match(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = ExternalEntryPointRule(canonical_system_model)
        payload = _threat_payload(
            canonical_system_model,
            component_id="component-other",
            component_ids=[],
        )
        assert rule.validate_threat(payload) == []

    def test_crossed_boundary_requires_trust_boundary_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = CrossedBoundaryRule(canonical_system_model)
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            data_flow_id="flow-payment",
            provenance={
                "entry_point_id": "entry-payments",
                "actor_id": "actor-customer",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "trust_boundary_id" in violations[0]

    def test_crossed_boundary_rejects_unknown_boundary_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = CrossedBoundaryRule(canonical_system_model)
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            data_flow_id="flow-payment",
            provenance={
                "entry_point_id": "entry-payments",
                "actor_id": "actor-customer",
                "trust_boundary_id": "boundary-missing",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "not a known trust boundary" in violations[0]

    def test_crossed_boundary_skips_when_flow_not_crossed(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = CrossedBoundaryRule(canonical_system_model)
        payload = _threat_payload(canonical_system_model, data_flow_id="flow-other")
        assert rule.validate_threat(payload) == []

    def test_crossed_boundary_accepts_known_boundary_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = CrossedBoundaryRule(canonical_system_model)
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            data_flow_id="flow-payment",
            provenance={
                "entry_point_id": "entry-payments",
                "actor_id": "actor-customer",
                "trust_boundary_id": "boundary-production",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        assert rule.validate_threat(payload) == []

    def test_crossed_boundary_skips_when_no_crossed_flows(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "data_flows": [
                    flow.model_copy(update={"trust_boundary_crossed": False})
                    for flow in canonical_system_model.data_flows
                ]
            }
        )
        rule = CrossedBoundaryRule(model)
        assert rule.validate_threat(_threat_payload(model, data_flow_id="flow-payment")) == []

    def test_entry_actor_link_requires_matching_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = EntryActorLinkRule(canonical_system_model)
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "entry_point_id": "entry-payments",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "actor_id" in violations[0]

    def test_entry_actor_link_rejects_mismatched_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = EntryActorLinkRule(canonical_system_model)
        graph = architecture_graph_for_model(canonical_system_model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "entry_point_id": "entry-payments",
                "actor_id": "actor-other",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "must match" in violations[0]

    def test_entry_actor_link_skips_when_provenance_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        rule = EntryActorLinkRule(canonical_system_model)
        assert rule.validate_threat({"id": "threat-x"}) == []

    def test_entry_actor_link_skips_when_entry_has_no_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    entry.model_copy(update={"actor_id": None})
                    for entry in canonical_system_model.entry_points
                ]
            }
        )
        rule = EntryActorLinkRule(model)
        graph = architecture_graph_for_model(model)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            model,
            provenance={
                "entry_point_id": "entry-payments",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        assert rule.validate_threat(payload) == []


class TestAttackPathGraphConsistencyRule:
    """Verify graph-backed attack path consistency."""

    def test_skips_when_provenance_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        assert rule.validate_threat({"id": "threat-x"}) == []

    def test_skips_when_attack_path_id_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path": ["step"],
                "rationale": "reason",
            },
        )
        assert rule.validate_threat(payload) == []

    def test_rejects_unknown_attack_path_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path_id": "missing-path",
                "attack_path": ["step"],
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations
        assert "not a known attack path" in violations[0]

    def test_rejects_non_list_attack_path_narrative(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": "bad",
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert violations == ["provenance.attack_path must be a list"]

    def test_rejects_mismatched_narrative_length(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": ["only-one-step"],
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert any("step count" in item for item in violations)

    def test_rejects_mismatched_narrative_label(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        narrative = attack_path_narrative(graph, attack_path_id)
        narrative[0] = "wrong-name"
        payload = _threat_payload(
            canonical_system_model,
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": narrative,
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert any("must match graph node name" in item for item in violations)

    def test_rejects_component_refs_off_attack_path(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            component_id="component-other",
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert any("component references must appear" in item for item in violations)

    def test_rejects_data_flow_refs_off_attack_path(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            data_flow_id="flow-payment",
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert any("data_flow references must appear" in item for item in violations)

    def test_rejects_asset_refs_off_attack_path(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            asset_id="asset-secret",
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        violations = rule.validate_threat(payload)
        assert any("asset references must appear" in item for item in violations)

    def test_accepts_list_component_asset_and_flow_refs_on_path(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        rule = AttackPathGraphConsistencyRule(graph)
        attack_path_id = default_attack_path_id(graph)
        path = next(item for item in graph.attack_paths if item.id == attack_path_id)
        component_id = next(
            node.component_id
            for node in graph.nodes
            if node.id in {step.node_id for step in path.steps} and node.component_id
        )
        payload = _threat_payload(
            canonical_system_model,
            component_ids=[component_id],
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        assert rule.validate_threat(payload) == []


class TestThreatProvenanceHelperFunctions:
    """Verify helper collectors used by graph consistency rules."""

    def test_threat_data_flow_ids_collects_list_values(self) -> None:
        from threatmodeler.validation.threat_provenance_validator import _threat_data_flow_ids

        assert _threat_data_flow_ids({"data_flow_ids": ["flow-a", "flow-b", 1, ""]}) == {
            "flow-a",
            "flow-b",
        }

    def test_threat_asset_ids_collects_list_values(self) -> None:
        from threatmodeler.validation.threat_provenance_validator import _threat_asset_ids

        assert _threat_asset_ids({"asset_ids": ["asset-a", ""]}) == {"asset-a"}

    def test_node_asset_ids_and_edge_flow_ids_collect_path_refs(self) -> None:
        from threatmodeler.validation.threat_provenance_validator import (
            _edge_flow_ids,
            _node_asset_ids,
        )

        class _Node:
            def __init__(self, asset_id: str | None = None) -> None:
                self.asset_id = asset_id

        class _Edge:
            def __init__(self, data_flow_id: str | None = None) -> None:
                self.data_flow_id = data_flow_id

        nodes = {"node-a": _Node("asset-a"), "node-b": _Node(None)}
        edges = {"edge-a": _Edge("flow-a")}

        assert _node_asset_ids(nodes, {"node-a", "node-b"}) == {"asset-a"}
        assert _edge_flow_ids(edges, {"edge-a", "edge-missing"}) == {"flow-a"}

    def test_node_component_ids_skips_non_string_component_refs(self) -> None:
        from threatmodeler.validation.threat_provenance_validator import _node_component_ids

        class _Node:
            component_id = 123

        assert _node_component_ids({"node-a": _Node()}, {"node-a"}) == set()

    def test_rejects_narrative_when_path_node_missing_from_lookup(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        from threatmodeler.validation.threat_provenance_validator import (
            _narrative_alignment_violations,
        )

        graph = architecture_graph_for_model(canonical_system_model)
        attack_path = graph.attack_paths[0]
        violations = _narrative_alignment_violations(
            ["label"],
            attack_path,
            {},
        )
        assert violations == [
            "attack path references unknown graph nodes for narrative alignment"
        ]


class TestThreatProvenanceValidatorFactory:
    """Verify factory composition and wiring."""

    def test_build_accepts_valid_threat(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        validator = ThreatProvenanceValidatorFactory(canonical_system_model, graph).build()
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            component_ids=["component-api"],
            affected_component_ids=["component-api"],
            provenance={
                "entry_point_id": "entry-payments",
                "actor_id": "actor-customer",
                "trust_boundary_id": "boundary-production",
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "Identified because the API is externally exposed.",
            },
        )
        assert validator(ThreatListField.THREATS, payload, {}) == []

    def test_helper_paths_for_non_string_ids(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        validator = ThreatProvenanceValidatorFactory(canonical_system_model, graph).build()
        attack_path_id = default_attack_path_id(graph)
        payload = _threat_payload(
            canonical_system_model,
            component_id="",
            component_ids="not-a-list",
            affected_component_ids=None,
            data_flow_id="",
            data_flow_ids="not-a-list",
            provenance={
                "attack_path_id": attack_path_id,
                "attack_path": attack_path_narrative(graph, attack_path_id),
                "rationale": "reason",
            },
        )
        assert validator(ThreatListField.THREATS, payload, {}) == []

    def test_ignores_non_threat_list_fields(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        validator = ThreatProvenanceValidatorFactory(canonical_system_model, graph).build()
        assert validator("cases", {}, {}) == []

    def test_from_input_payload(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        factory = ThreatProvenanceValidatorFactory.from_input_payload(
            stride_validator_input_payload(canonical_system_model)
        )
        assert factory.build() is not None

    def test_from_input_payload_rejects_missing_system_model(self) -> None:
        with pytest.raises(ValueError, match="system_model"):
            ThreatProvenanceValidatorFactory.from_input_payload({})

    def test_from_input_payload_rejects_missing_architecture_graph(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        with pytest.raises(ValueError, match="architecture_graph"):
            ThreatProvenanceValidatorFactory.from_input_payload(
                {"system_model": canonical_system_model.model_dump(mode="json")}
            )


class TestExposureTypeExternalFacing:
    """Verify ExposureType helper used by provenance coverage."""

    def test_partner_is_external_facing(self) -> None:
        assert ExposureType.PARTNER.is_external_facing() is True

    def test_internal_is_not_external_facing(self) -> None:
        assert ExposureType.INTERNAL.is_external_facing() is False
