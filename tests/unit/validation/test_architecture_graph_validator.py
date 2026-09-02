"""Tests for architecture graph construction validators."""

from typing import Any

import pytest
from pydantic import JsonValue

from threatmodeler.contracts.artifacts.enums import GraphListField, GraphNodeKind
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph
from threatmodeler.validation.architecture_graph_validator import (
    ActorAnchorRule,
    ArchitectureGraphFinishValidator,
    ArchitectureGraphValidatorFactory,
    AttackPathItemValidator,
    ComponentAnchorRule,
    DataStoreAnchorRule,
    EntrySurfaceAnchorRule,
    EvidenceOrComponentAnchorRule,
    ExternalServiceAnchorRule,
    GraphEdgeItemValidator,
    GraphNodeAnchorRuleFactory,
    GraphNodeItemValidator,
    SecretAnchorRule,
)

from tests.fixtures.graph_fixtures import architecture_graph_for_model


def _node(
    node_id: str,
    kind: str,
    *,
    actor_id: str | None = None,
    component_id: str | None = None,
    data_store_id: str | None = None,
    asset_id: str | None = None,
    entry_point_id: str | None = None,
    external_dependency_id: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "id": node_id,
        "name": node_id,
        "description": "node",
        "confidence": 0.8,
        "kind": kind,
    }
    if actor_id is not None:
        payload["actor_id"] = actor_id
    if component_id is not None:
        payload["component_id"] = component_id
    if data_store_id is not None:
        payload["data_store_id"] = data_store_id
    if asset_id is not None:
        payload["asset_id"] = asset_id
    if entry_point_id is not None:
        payload["entry_point_id"] = entry_point_id
    if external_dependency_id is not None:
        payload["external_dependency_id"] = external_dependency_id
    if evidence is not None:
        payload["evidence"] = evidence
    return payload


def _edge(
    edge_id: str,
    source_node_id: str,
    target_node_id: str,
) -> dict[str, JsonValue]:
    return {
        "id": edge_id,
        "name": edge_id,
        "description": "edge",
        "confidence": 0.8,
        "kind": "calls",
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
    }


def _attack_path(
    path_id: str,
    *,
    entry_node_id: str,
    target_node_id: str,
    steps: list[dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    return {
        "id": path_id,
        "name": path_id,
        "description": "path",
        "confidence": 0.8,
        "entry_node_id": entry_node_id,
        "target_node_id": target_node_id,
        "steps": steps,
    }


class TestGraphNodeAnchorRules:
    """Verify per-kind anchor validation strategies."""

    def test_actor_anchor_rule(self) -> None:
        rule = ActorAnchorRule()
        assert rule.validate_node({"kind": "actor"}) == ["actor nodes require actor_id"]
        assert rule.validate_node({"kind": "actor", "actor_id": "actor-1"}) == []

    def test_component_anchor_rule(self) -> None:
        rule = ComponentAnchorRule()
        assert rule.validate_node({"kind": "service"}) == ["nodes of this kind require component_id"]
        assert rule.validate_node({"kind": "service", "component_id": "component-1"}) == []

    def test_data_store_anchor_rule(self) -> None:
        rule = DataStoreAnchorRule()
        assert rule.validate_node({"kind": "database"}) == [
            "database, queue, and storage nodes require component_id or data_store_id"
        ]
        assert rule.validate_node({"kind": "database", "data_store_id": "store-1"}) == []
        assert rule.validate_node({"kind": "database", "component_id": "component-1"}) == []

    def test_secret_anchor_rule(self) -> None:
        rule = SecretAnchorRule()
        assert rule.validate_node({"kind": "secret"}) == ["secret nodes require asset_id"]
        assert rule.validate_node({"kind": "secret", "asset_id": "asset-1"}) == []

    def test_entry_surface_anchor_rule(self) -> None:
        rule = EntrySurfaceAnchorRule()
        assert rule.validate_node({"kind": "entry_surface"}) == [
            "entry_surface nodes require entry_point_id"
        ]
        assert rule.validate_node({"kind": "entry_surface", "entry_point_id": "entry-1"}) == []

    def test_evidence_or_component_anchor_rule(self) -> None:
        rule = EvidenceOrComponentAnchorRule()
        assert rule.validate_node({"kind": "agent"}) == [
            "agent, llm, and tool nodes require component_id or non-empty evidence"
        ]
        assert rule.validate_node({"kind": "agent", "component_id": "component-1"}) == []
        assert rule.validate_node(
            {"kind": "agent", "evidence": [{"summary": "supported", "source_references": []}]}
        ) == []

    def test_external_service_anchor_rule(self) -> None:
        rule = ExternalServiceAnchorRule()
        assert rule.validate_node({"kind": "external_service"}) == [
            "external_service nodes require component_id or external_dependency_id"
        ]
        assert rule.validate_node(
            {"kind": "external_service", "external_dependency_id": "dep-1"}
        ) == []

    @pytest.mark.parametrize(
        ("kind", "expected_type"),
        [
            (GraphNodeKind.ACTOR, ActorAnchorRule),
            (GraphNodeKind.SERVICE, ComponentAnchorRule),
            (GraphNodeKind.API, ComponentAnchorRule),
            (GraphNodeKind.IDENTITY, ComponentAnchorRule),
            (GraphNodeKind.DATABASE, DataStoreAnchorRule),
            (GraphNodeKind.QUEUE, DataStoreAnchorRule),
            (GraphNodeKind.STORAGE, DataStoreAnchorRule),
            (GraphNodeKind.SECRET, SecretAnchorRule),
            (GraphNodeKind.ENTRY_SURFACE, EntrySurfaceAnchorRule),
            (GraphNodeKind.AGENT, EvidenceOrComponentAnchorRule),
            (GraphNodeKind.LLM, EvidenceOrComponentAnchorRule),
            (GraphNodeKind.TOOL, EvidenceOrComponentAnchorRule),
            (GraphNodeKind.EXTERNAL_SERVICE, ExternalServiceAnchorRule),
        ],
    )
    def test_anchor_rule_factory_resolves_kind(
        self,
        kind: GraphNodeKind,
        expected_type: type,
    ) -> None:
        rule = GraphNodeAnchorRuleFactory.for_kind(kind)
        assert isinstance(rule, expected_type)


class TestGraphNodeItemValidator:
    """Verify incremental graph node validation."""

    def test_ignores_non_node_lists(self) -> None:
        validator = GraphNodeItemValidator()
        assert validator("edges", {}, {}) == []

    def test_rejects_non_string_kind(self) -> None:
        validator = GraphNodeItemValidator()
        assert validator(GraphListField.NODES, {"kind": 1}, {}) == [
            "graph node kind must be a string"
        ]

    def test_rejects_unknown_kind(self) -> None:
        validator = GraphNodeItemValidator()
        violations = validator(GraphListField.NODES, {"kind": "unknown-kind"}, {})
        assert violations == ["unknown graph node kind 'unknown-kind'"]

    def test_delegates_to_anchor_rule(self) -> None:
        validator = GraphNodeItemValidator()
        violations = validator(
            GraphListField.NODES,
            _node("node-1", GraphNodeKind.ACTOR.value),
            {},
        )
        assert "actor_id" in violations[0]


class TestGraphEdgeItemValidator:
    """Verify incremental graph edge validation."""

    def test_ignores_non_edge_lists(self) -> None:
        validator = GraphEdgeItemValidator()
        assert validator(GraphListField.NODES, {}, {}) == []

    def test_rejects_unknown_source_and_target(self) -> None:
        validator = GraphEdgeItemValidator()
        lists = {GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")]}
        violations = validator(
            GraphListField.EDGES,
            _edge("edge-1", "missing", "node-a"),
            lists,
        )
        assert any("source_node_id" in item for item in violations)

    def test_rejects_unknown_target(self) -> None:
        validator = GraphEdgeItemValidator()
        lists = {GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")]}
        violations = validator(
            GraphListField.EDGES,
            _edge("edge-1", "node-a", "missing"),
            lists,
        )
        assert any("target_node_id" in item for item in violations)

    def test_rejects_self_loop(self) -> None:
        validator = GraphEdgeItemValidator()
        lists = {GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")]}
        violations = validator(
            GraphListField.EDGES,
            _edge("edge-1", "node-a", "node-a"),
            lists,
        )
        assert any("distinct nodes" in item for item in violations)


class TestAttackPathItemValidator:
    """Verify incremental attack path walk validation."""

    def test_ignores_non_attack_path_lists(self) -> None:
        validator = AttackPathItemValidator()
        assert validator(GraphListField.NODES, {}, {}) == []

    def test_requires_non_empty_steps(self) -> None:
        validator = AttackPathItemValidator()
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path("path-1", entry_node_id="a", target_node_id="a", steps=[]),
            {},
        )
        assert violations == ["attack path steps must be a non-empty list"]

    def test_rejects_unknown_entry_and_target(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")],
            GraphListField.EDGES: [],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="missing",
                target_node_id="missing",
                steps=[{"node_id": "missing"}],
            ),
            lists,
        )
        assert len(violations) == 2

    def test_validates_step_walk(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
            ],
            GraphListField.EDGES: [_edge("edge-1", "node-a", "node-b")],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[
                    {"node_id": "node-a"},
                    {"node_id": "node-b", "via_edge_id": "edge-1"},
                ],
            ),
            lists,
        )
        assert violations == []

    def test_rejects_mismatched_first_step(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
            ],
            GraphListField.EDGES: [],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[{"node_id": "node-b", "via_edge_id": "edge-1"}],
            ),
            lists,
        )
        assert any("first step" in item for item in violations)

    def test_rejects_unknown_step_node_id(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")],
            GraphListField.EDGES: [],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-a",
                steps=[{"node_id": "missing"}],
            ),
            lists,
        )
        assert any("references unknown node_id" in item for item in violations)

    def test_skips_edge_walk_when_edge_payload_is_not_object(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
            ],
            GraphListField.EDGES: [_edge("edge-1", "node-a", "node-b")],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[
                    {"node_id": "node-a"},
                    {"node_id": "node-b", "via_edge_id": "edge-1"},
                ],
            ),
            lists,
        )
        assert violations == []

    def test_rejects_non_object_step(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")],
            GraphListField.EDGES: [],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-a",
                steps=["bad"],
            ),
            lists,
        )
        assert any("must be an object" in item for item in violations)

    def test_skips_edge_walk_when_edge_lookup_is_not_dict(self) -> None:
        from threatmodeler.validation.architecture_graph_validator import _walk_violations

        violations = _walk_violations(
            [{"node_id": "node-a"}, {"node_id": "node-b", "via_edge_id": "edge-1"}],
            {"node-a", "node-b"},
            {"edge-1"},
            {"edge-1": "not-a-dict"},
            "node-a",
            "node-b",
        )
        assert violations == []


    def test_rejects_missing_step_node_id(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [_node("node-a", GraphNodeKind.SERVICE.value, component_id="c-a")],
            GraphListField.EDGES: [],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-a",
                steps=[{"via_edge_id": "edge-1"}],
            ),
            lists,
        )
        assert any("requires node_id" in item for item in violations)

    def test_rejects_missing_via_edge_id_on_later_step(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
            ],
            GraphListField.EDGES: [_edge("edge-1", "node-a", "node-b")],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[{"node_id": "node-a"}, {"node_id": "node-b"}],
            ),
            lists,
        )
        assert any("requires via_edge_id" in item for item in violations)

    def test_rejects_unknown_via_edge_id(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
            ],
            GraphListField.EDGES: [_edge("edge-1", "node-a", "node-b")],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[
                    {"node_id": "node-a"},
                    {"node_id": "node-b", "via_edge_id": "missing-edge"},
                ],
            ),
            lists,
        )
        assert any("unknown via_edge_id" in item for item in violations)

    def test_rejects_edge_that_does_not_reach_step_node(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
                _node("node-c", GraphNodeKind.SERVICE.value, component_id="c-c"),
            ],
            GraphListField.EDGES: [
                _edge("edge-ab", "node-a", "node-b"),
                _edge("edge-ac", "node-a", "node-c"),
            ],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-b",
                steps=[
                    {"node_id": "node-a"},
                    {"node_id": "node-b", "via_edge_id": "edge-ac"},
                ],
            ),
            lists,
        )
        assert any("does not reach node_id" in item for item in violations)

    def test_rejects_edge_that_does_not_connect_previous_node(self) -> None:
        validator = AttackPathItemValidator()
        lists = {
            GraphListField.NODES: [
                _node("node-a", GraphNodeKind.ENTRY_SURFACE.value, entry_point_id="entry-1"),
                _node("node-b", GraphNodeKind.SERVICE.value, component_id="c-b"),
                _node("node-c", GraphNodeKind.SERVICE.value, component_id="c-c"),
            ],
            GraphListField.EDGES: [
                _edge("edge-ab", "node-a", "node-b"),
                _edge("edge-bc", "node-b", "node-c"),
            ],
        }
        violations = validator(
            GraphListField.ATTACK_PATHS,
            _attack_path(
                "path-1",
                entry_node_id="node-a",
                target_node_id="node-c",
                steps=[
                    {"node_id": "node-a"},
                    {"node_id": "node-c", "via_edge_id": "edge-bc"},
                ],
            ),
            lists,
        )
        assert any("does not originate from previous node" in item for item in violations)


class TestGraphNodeAnchorRuleFactoryDefault:
    """Verify fallback anchor rule selection."""

    def test_default_rule_is_component_anchor(self) -> None:
        from unittest.mock import Mock

        unknown_kind = Mock()
        unknown_kind.__eq__ = lambda self, other: False
        rule = GraphNodeAnchorRuleFactory.for_kind(unknown_kind)
        assert isinstance(rule, ComponentAnchorRule)


class TestArchitectureGraphFinishValidator:
    """Verify finished graph payload validation."""

    def test_rejects_invalid_payload(self) -> None:
        violations = ArchitectureGraphFinishValidator()({"nodes": "bad"})
        assert violations

    def test_accepts_valid_graph(
        self,
        canonical_system_model,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        violations = ArchitectureGraphFinishValidator()(graph.model_dump(mode="json"))
        assert violations == []

    def test_rejects_broken_edge_references(
        self,
        canonical_system_model,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        payload = graph.model_dump(mode="json")
        payload["edges"][0]["target_node_id"] = "missing-node"
        violations = ArchitectureGraphFinishValidator()(payload)
        assert any("unknown target_node_id" in item for item in violations)

    def test_rejects_broken_edge_source_reference(
        self,
        canonical_system_model,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        payload = graph.model_dump(mode="json")
        payload["edges"][0]["source_node_id"] = "missing-node"
        violations = ArchitectureGraphFinishValidator()(payload)
        assert any("unknown source_node_id" in item for item in violations)

    def test_rejects_broken_attack_path_target(
        self,
        canonical_system_model,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        payload = graph.model_dump(mode="json")
        payload["attack_paths"][0]["target_node_id"] = "missing-node"
        violations = ArchitectureGraphFinishValidator()(payload)
        assert any("last step node_id must match target_node_id" in item for item in violations)


class TestArchitectureGraphValidatorFactory:
    """Verify factory wiring for agent construction."""

    def test_build_item_validator_composes_rules(self) -> None:
        factory = ArchitectureGraphValidatorFactory()
        validator = factory.build_item_validator()
        lists = {
            GraphListField.NODES: [_node("node-a", GraphNodeKind.ACTOR.value, actor_id="actor-1")],
            GraphListField.EDGES: [],
            GraphListField.ATTACK_PATHS: [],
        }
        assert validator(GraphListField.NODES, lists[GraphListField.NODES][0], lists) == []

    def test_build_finish_validator_wraps_finish_validator(self) -> None:
        factory = ArchitectureGraphValidatorFactory()
        validator = factory.build_finish_validator()
        graph = ArchitectureGraph.model_validate(
            {
                "artifact_id": "architecture-graph",
                "title": "Graph",
                "description": "Graph",
                "confidence": 0.8,
                "assumptions": [],
                "nodes": [],
                "edges": [],
                "attack_paths": [],
            }
        )
        assert validator("nodes", graph.model_dump(mode="json"), {}) == []
