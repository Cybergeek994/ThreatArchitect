"""Strategy-based validation for architecture graph construction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Protocol

from pydantic import JsonValue

from threatmodeler.contracts.artifacts.enums import GraphListField, GraphNodeKind
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph, AttackPath
from threatmodeler.ports.artifact_construction_session_factory import ItemValidator
from threatmodeler.validation.composite_item_validator import CompositeItemValidator


class GraphNodeAnchorRule(Protocol):
    """Validate canonical anchors for one graph node kind."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        """Return violations for one graph node payload."""
        ...


class ActorAnchorRule:
    """Require actor_id for actor nodes."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if not _non_empty_str(payload.get("actor_id")):
            return ["actor nodes require actor_id"]
        return []


class ComponentAnchorRule:
    """Require component_id for component-backed node kinds."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if not _non_empty_str(payload.get("component_id")):
            return ["nodes of this kind require component_id"]
        return []


class DataStoreAnchorRule:
    """Require component_id or data_store_id for persistence nodes."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if _non_empty_str(payload.get("component_id")) or _non_empty_str(
            payload.get("data_store_id")
        ):
            return []
        return ["database, queue, and storage nodes require component_id or data_store_id"]


class SecretAnchorRule:
    """Require asset_id for secret nodes."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if not _non_empty_str(payload.get("asset_id")):
            return ["secret nodes require asset_id"]
        return []


class EntrySurfaceAnchorRule:
    """Require entry_point_id for entry surface nodes."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if not _non_empty_str(payload.get("entry_point_id")):
            return ["entry_surface nodes require entry_point_id"]
        return []


class EvidenceOrComponentAnchorRule:
    """Require component_id or evidence for semantic AI node kinds."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if _non_empty_str(payload.get("component_id")):
            return []
        evidence = payload.get("evidence")
        if isinstance(evidence, list) and evidence:
            return []
        return ["agent, llm, and tool nodes require component_id or non-empty evidence"]


class ExternalServiceAnchorRule:
    """Require component_id or external_dependency_id for external services."""

    def validate_node(self, payload: dict[str, JsonValue]) -> list[str]:
        if _non_empty_str(payload.get("component_id")) or _non_empty_str(
            payload.get("external_dependency_id")
        ):
            return []
        return ["external_service nodes require component_id or external_dependency_id"]


class GraphNodeAnchorRuleFactory:
    """Resolve anchor validation strategy for a graph node kind."""

    @classmethod
    def for_kind(cls, kind: GraphNodeKind) -> GraphNodeAnchorRule:
        """Return the anchor rule strategy for ``kind``."""
        if kind is GraphNodeKind.ACTOR:
            return ActorAnchorRule()
        if kind in {GraphNodeKind.SERVICE, GraphNodeKind.API, GraphNodeKind.IDENTITY}:
            return ComponentAnchorRule()
        if kind in {GraphNodeKind.DATABASE, GraphNodeKind.QUEUE, GraphNodeKind.STORAGE}:
            return DataStoreAnchorRule()
        if kind is GraphNodeKind.SECRET:
            return SecretAnchorRule()
        if kind is GraphNodeKind.ENTRY_SURFACE:
            return EntrySurfaceAnchorRule()
        if kind in {GraphNodeKind.AGENT, GraphNodeKind.LLM, GraphNodeKind.TOOL}:
            return EvidenceOrComponentAnchorRule()
        if kind is GraphNodeKind.EXTERNAL_SERVICE:
            return ExternalServiceAnchorRule()
        return ComponentAnchorRule()


class GraphNodeItemValidator:
    """Validate graph nodes during incremental construction."""

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        del lists
        if list_field != GraphListField.NODES:
            return []
        kind_value = payload.get("kind")
        if not isinstance(kind_value, str):
            return ["graph node kind must be a string"]
        try:
            kind = GraphNodeKind(kind_value)
        except ValueError:
            return [f"unknown graph node kind '{kind_value}'"]
        return GraphNodeAnchorRuleFactory.for_kind(kind).validate_node(payload)


class GraphEdgeItemValidator:
    """Validate graph edges reference existing session nodes."""

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        if list_field != GraphListField.EDGES:
            return []
        node_ids = _node_ids(lists.get(GraphListField.NODES, ()))
        violations: list[str] = []
        source_id = payload.get("source_node_id")
        target_id = payload.get("target_node_id")
        if isinstance(source_id, str) and source_id and source_id not in node_ids:
            violations.append(f"source_node_id '{source_id}' is not a known graph node")
        if isinstance(target_id, str) and target_id and target_id not in node_ids:
            violations.append(f"target_node_id '{target_id}' is not a known graph node")
        if isinstance(source_id, str) and isinstance(target_id, str) and source_id == target_id:
            violations.append("graph edges must connect distinct nodes")
        return violations


class AttackPathItemValidator:
    """Validate attack path walks against session nodes and edges."""

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        if list_field != GraphListField.ATTACK_PATHS:
            return []
        node_ids = _node_ids(lists.get(GraphListField.NODES, ()))
        edge_ids = _item_ids(lists.get(GraphListField.EDGES, ()))
        edges_by_id = {
            item["id"]: item
            for item in lists.get(GraphListField.EDGES, ())
            if isinstance(item.get("id"), str)
        }
        return _attack_path_violations(payload, node_ids, edge_ids, edges_by_id)


class ArchitectureGraphFinishValidator:
    """Validate a finished architecture graph payload."""

    def __call__(self, payload: dict[str, JsonValue]) -> list[str]:
        try:
            graph = ArchitectureGraph.model_validate(payload)
        except Exception as error:  # noqa: BLE001 - surface pydantic message
            return [str(error)]
        violations: list[str] = []
        node_ids = {node.id for node in graph.nodes}
        edge_ids = {edge.id for edge in graph.edges}
        edges_by_id = {edge.id: edge for edge in graph.edges}
        for edge in graph.edges:
            if edge.source_node_id not in node_ids:
                violations.append(
                    f"edge '{edge.id}' references unknown source_node_id "
                    f"'{edge.source_node_id}'"
                )
            if edge.target_node_id not in node_ids:
                violations.append(
                    f"edge '{edge.id}' references unknown target_node_id "
                    f"'{edge.target_node_id}'"
                )
        for attack_path in graph.attack_paths:
            violations.extend(
                _finished_attack_path_violations(
                    attack_path,
                    node_ids,
                    edge_ids,
                    edges_by_id,
                )
            )
        return violations


class ArchitectureGraphValidatorFactory:
    """Build validators for architecture graph agent construction."""

    def build_item_validator(self) -> ItemValidator:
        """Return incremental item validator for graph construction tools."""
        return CompositeItemValidator(
            (
                GraphNodeItemValidator(),
                GraphEdgeItemValidator(),
                AttackPathItemValidator(),
            )
        )

    def build_finish_validator(self) -> ItemValidator:
        """Return finish validator wrapping full graph validation."""

        class _FinishAdapter:
            def __call__(
                self,
                list_field: str,
                payload: dict[str, JsonValue],
                lists: Mapping[str, list[dict[str, JsonValue]]],
            ) -> list[str]:
                del list_field, lists
                return ArchitectureGraphFinishValidator()(payload)

        return _FinishAdapter()


def _attack_path_violations(
    payload: dict[str, JsonValue],
    node_ids: set[str],
    edge_ids: set[str],
    edges_by_id: Mapping[str, dict[str, JsonValue]],
) -> list[str]:
    steps = payload.get("steps")
    if not isinstance(steps, list) or not steps:
        return ["attack path steps must be a non-empty list"]
    entry_node_id = payload.get("entry_node_id")
    target_node_id = payload.get("target_node_id")
    violations: list[str] = []
    if isinstance(entry_node_id, str) and entry_node_id not in node_ids:
        violations.append(f"entry_node_id '{entry_node_id}' is not a known graph node")
    if isinstance(target_node_id, str) and target_node_id not in node_ids:
        violations.append(f"target_node_id '{target_node_id}' is not a known graph node")
    if violations:
        return violations
    return _walk_violations(steps, node_ids, edge_ids, edges_by_id, entry_node_id, target_node_id)


def _finished_attack_path_violations(
    attack_path: AttackPath,
    node_ids: set[str],
    edge_ids: set[str],
    edges_by_id: Mapping[str, GraphEdge],
) -> list[str]:
    serialized_steps = [step.model_dump(mode="json") for step in attack_path.steps]
    edge_payload = {
        edge_id: edge.model_dump(mode="json") for edge_id, edge in edges_by_id.items()
    }
    return _walk_violations(
        serialized_steps,
        node_ids,
        edge_ids,
        edge_payload,
        attack_path.entry_node_id,
        attack_path.target_node_id,
        path_id=attack_path.id,
    )


def _walk_violations(
    steps: Sequence[JsonValue],
    node_ids: set[str],
    edge_ids: set[str],
    edges_by_id: Mapping[str, JsonValue],
    entry_node_id: JsonValue,
    target_node_id: JsonValue,
    path_id: str | None = None,
) -> list[str]:
    prefix = f"attack path '{path_id}'" if path_id else "attack path"
    violations: list[str] = []
    previous_node_id: str | None = None
    for index, raw_step in enumerate(steps):
        if not isinstance(raw_step, dict):
            violations.append(f"{prefix} step {index} must be an object")
            continue
        node_id = raw_step.get("node_id")
        via_edge_id = raw_step.get("via_edge_id")
        if not isinstance(node_id, str) or not node_id:
            violations.append(f"{prefix} step {index} requires node_id")
            continue
        if node_id not in node_ids:
            violations.append(f"{prefix} step {index} references unknown node_id '{node_id}'")
        if index == 0:
            if via_edge_id is not None:
                violations.append(f"{prefix} first step must not include via_edge_id")
            if isinstance(entry_node_id, str) and node_id != entry_node_id:
                violations.append(
                    f"{prefix} first step node_id must match entry_node_id '{entry_node_id}'"
                )
        else:
            if not isinstance(via_edge_id, str) or not via_edge_id:
                violations.append(f"{prefix} step {index} requires via_edge_id")
            elif via_edge_id not in edge_ids:
                violations.append(
                    f"{prefix} step {index} references unknown via_edge_id '{via_edge_id}'"
                )
            else:
                edge = edges_by_id.get(via_edge_id)
                if isinstance(edge, dict):
                    source_id = edge.get("source_node_id")
                    target_id = edge.get("target_node_id")
                    if previous_node_id is not None and source_id != previous_node_id:
                        violations.append(
                            f"{prefix} step {index} via_edge_id '{via_edge_id}' "
                            f"does not originate from previous node '{previous_node_id}'"
                        )
                    if target_id != node_id:
                        violations.append(
                            f"{prefix} step {index} via_edge_id '{via_edge_id}' "
                            f"does not reach node_id '{node_id}'"
                        )
        previous_node_id = node_id if isinstance(node_id, str) else previous_node_id
    if isinstance(target_node_id, str) and previous_node_id != target_node_id:
        violations.append(
            f"{prefix} last step node_id must match target_node_id '{target_node_id}'"
        )
    return violations


def _node_ids(nodes: Sequence[dict[str, JsonValue]]) -> set[str]:
    return _item_ids(nodes)


def _item_ids(items: Sequence[dict[str, JsonValue]]) -> set[str]:
    return {
        item_id
        for item in items
        if isinstance(item_id := item.get("id"), str) and item_id
    }


def _non_empty_str(value: JsonValue) -> bool:
    return isinstance(value, str) and bool(value)
