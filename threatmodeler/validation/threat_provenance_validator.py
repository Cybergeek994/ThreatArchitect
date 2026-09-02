"""Strategy-based validation of STRIDE threat provenance during construction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Protocol

from pydantic import JsonValue

from threatmodeler.contracts.artifacts.enums import StrideInputPayloadField
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph, AttackPath
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.ports.artifact_construction_session_factory import ItemValidator
from threatmodeler.validation.composite_item_validator import CompositeItemValidator


class ThreatListField(StrEnum):
    """List field name for STRIDE threat construction tools."""

    THREATS = "threats"


class ThreatProvenanceRule(Protocol):
    """One hard provenance rule applied to a threat payload."""

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        """Return violations for one threat payload."""
        ...


class EvidenceRequiredRule:
    """Reject threats with empty evidence."""

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        evidence = payload.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            return ["threat evidence must be a non-empty list"]
        return []


class ProvenanceFieldsPresentRule:
    """Reject threats missing required provenance narrative fields."""

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            return ["threat provenance must be an object"]
        violations: list[str] = []
        attack_path_id = provenance.get("attack_path_id")
        if not isinstance(attack_path_id, str) or not attack_path_id:
            violations.append("provenance.attack_path_id must be a non-empty string")
        attack_path = provenance.get("attack_path")
        if not isinstance(attack_path, list) or not attack_path:
            violations.append("provenance.attack_path must be a non-empty list")
        rationale = provenance.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            violations.append("provenance.rationale must be a non-empty string")
        return violations


class ExternalEntryPointRule:
    """Require entry_point_id when threat components match external-facing entries."""

    def __init__(self, model: CanonicalSystemModel) -> None:
        self._entries_by_component: dict[str, tuple[str, ...]] = {}
        for entry in model.entry_points:
            if not entry.exposure.is_external_facing():
                continue
            existing = self._entries_by_component.get(entry.component_id, ())
            self._entries_by_component[entry.component_id] = (*existing, entry.id)

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        if not self._entries_by_component:
            return []
        component_ids = _threat_component_ids(payload)
        required_entry_ids: list[str] = []
        for component_id in component_ids:
            required_entry_ids.extend(self._entries_by_component.get(component_id, ()))
        if not required_entry_ids:
            return []
        provenance = payload.get("provenance")
        entry_point_id = (
            provenance.get("entry_point_id") if isinstance(provenance, dict) else None
        )
        if not isinstance(entry_point_id, str) or not entry_point_id:
            return [
                "provenance.entry_point_id is required when the threat references a "
                "component of an external or partner entry point"
            ]
        if entry_point_id not in required_entry_ids:
            allowed = ", ".join(sorted(set(required_entry_ids)))
            return [
                f"provenance.entry_point_id '{entry_point_id}' does not match an "
                f"external/partner entry point for the referenced components. "
                f"Expected one of: {allowed}."
            ]
        return []


class CrossedBoundaryRule:
    """Require trust_boundary_id when linked flows cross a documented boundary."""

    def __init__(self, model: CanonicalSystemModel) -> None:
        self._crossed_flow_ids = {
            flow.id for flow in model.data_flows if flow.trust_boundary_crossed
        }
        self._boundary_ids = {boundary.id for boundary in model.trust_boundaries}

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        if not self._crossed_flow_ids or not self._boundary_ids:
            return []
        flow_ids = _threat_data_flow_ids(payload)
        if not flow_ids.intersection(self._crossed_flow_ids):
            return []
        provenance = payload.get("provenance")
        trust_boundary_id = (
            provenance.get("trust_boundary_id") if isinstance(provenance, dict) else None
        )
        if not isinstance(trust_boundary_id, str) or not trust_boundary_id:
            return [
                "provenance.trust_boundary_id is required when the threat references a "
                "data flow with trust_boundary_crossed=true"
            ]
        if trust_boundary_id not in self._boundary_ids:
            allowed = ", ".join(sorted(self._boundary_ids))
            return [
                f"provenance.trust_boundary_id '{trust_boundary_id}' is not a known "
                f"trust boundary id. Known ids: {allowed}."
            ]
        return []


class EntryActorLinkRule:
    """Require actor_id when the linked entry point declares an actor_id."""

    def __init__(self, model: CanonicalSystemModel) -> None:
        self._actor_by_entry = {
            entry.id: entry.actor_id
            for entry in model.entry_points
            if entry.actor_id is not None
        }

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            return []
        entry_point_id = provenance.get("entry_point_id")
        if not isinstance(entry_point_id, str) or entry_point_id not in self._actor_by_entry:
            return []
        expected_actor_id = self._actor_by_entry[entry_point_id]
        actor_id = provenance.get("actor_id")
        if not isinstance(actor_id, str) or not actor_id:
            return [
                "provenance.actor_id is required when provenance.entry_point_id "
                f"'{entry_point_id}' has a declared actor_id"
            ]
        if actor_id != expected_actor_id:
            return [
                f"provenance.actor_id '{actor_id}' must match entry point "
                f"'{entry_point_id}' actor_id '{expected_actor_id}'"
            ]
        return []


class AttackPathGraphConsistencyRule:
    """Validate threat provenance against architecture graph attack paths."""

    def __init__(self, graph: ArchitectureGraph) -> None:
        self._graph = graph
        self._paths_by_id = {path.id: path for path in graph.attack_paths}
        self._nodes_by_id = {node.id: node for node in graph.nodes}
        self._edges_by_id = {edge.id: edge for edge in graph.edges}

    def validate_threat(self, payload: dict[str, JsonValue]) -> list[str]:
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            return []
        attack_path_id = provenance.get("attack_path_id")
        if not isinstance(attack_path_id, str) or not attack_path_id:
            return []
        attack_path = self._paths_by_id.get(attack_path_id)
        if attack_path is None:
            known = ", ".join(sorted(self._paths_by_id))
            return [
                f"provenance.attack_path_id '{attack_path_id}' is not a known attack path. "
                f"Known ids: {known}."
            ]
        violations: list[str] = []
        narrative = provenance.get("attack_path")
        violations.extend(_narrative_alignment_violations(narrative, attack_path, self._nodes_by_id))
        violations.extend(
            _threat_link_violations(payload, attack_path, self._nodes_by_id, self._edges_by_id)
        )
        return violations


class ThreatProvenanceRuleAdapter:
    """Adapt a ThreatProvenanceRule to the ItemValidator callable contract."""

    def __init__(self, rule: ThreatProvenanceRule) -> None:
        self._rule = rule

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        del lists
        if list_field != ThreatListField.THREATS:
            return []
        return self._rule.validate_threat(payload)


class ThreatProvenanceValidatorFactory:
    """Build a composite item validator for STRIDE threat provenance rules."""

    def __init__(
        self,
        model: CanonicalSystemModel,
        graph: ArchitectureGraph,
    ) -> None:
        self._model = model
        self._graph = graph

    @classmethod
    def from_input_payload(
        cls,
        input_payload: Mapping[str, JsonValue],
    ) -> ThreatProvenanceValidatorFactory:
        """Parse upstream artifacts from an agent input payload.

        Args:
            input_payload: Agent request payload containing system model and graph.

        Returns:
            Factory bound to validated upstream artifacts.

        Raises:
            ValueError: If required payload fields are missing or invalid.
        """
        system_model_payload = input_payload.get(StrideInputPayloadField.SYSTEM_MODEL)
        if not isinstance(system_model_payload, dict):
            raise ValueError("input_payload.system_model must be an object")
        graph_payload = input_payload.get(StrideInputPayloadField.ARCHITECTURE_GRAPH)
        if not isinstance(graph_payload, dict):
            raise ValueError("input_payload.architecture_graph must be an object")
        model = CanonicalSystemModel.model_validate(system_model_payload)
        graph = ArchitectureGraph.model_validate(graph_payload)
        return cls(model, graph)

    def build(self) -> ItemValidator:
        """Return a composite ItemValidator for all hard provenance rules."""
        rules: Sequence[ThreatProvenanceRule] = (
            EvidenceRequiredRule(),
            ProvenanceFieldsPresentRule(),
            ExternalEntryPointRule(self._model),
            CrossedBoundaryRule(self._model),
            EntryActorLinkRule(self._model),
            AttackPathGraphConsistencyRule(self._graph),
        )
        adapters = [ThreatProvenanceRuleAdapter(rule) for rule in rules]
        return CompositeItemValidator(adapters)

def _threat_component_ids(payload: dict[str, JsonValue]) -> set[str]:
    ids: set[str] = set()
    component_id = payload.get("component_id")
    if isinstance(component_id, str) and component_id:
        ids.add(component_id)
    for key in ("component_ids", "affected_component_ids"):
        raw = payload.get(key)
        if isinstance(raw, list):
            ids.update(item for item in raw if isinstance(item, str) and item)
    return ids


def _threat_data_flow_ids(payload: dict[str, JsonValue]) -> set[str]:
    ids: set[str] = set()
    data_flow_id = payload.get("data_flow_id")
    if isinstance(data_flow_id, str) and data_flow_id:
        ids.add(data_flow_id)
    raw = payload.get("data_flow_ids")
    if isinstance(raw, list):
        ids.update(item for item in raw if isinstance(item, str) and item)
    return ids


def _narrative_alignment_violations(
    narrative: JsonValue,
    attack_path: AttackPath,
    nodes_by_id: Mapping[str, object],
) -> list[str]:
    if not isinstance(narrative, list):
        return ["provenance.attack_path must be a list"]
    expected_names = [
        getattr(nodes_by_id.get(step.node_id), "name", None) for step in attack_path.steps
    ]
    if any(name is None for name in expected_names):
        return ["attack path references unknown graph nodes for narrative alignment"]
    expected = [name for name in expected_names if isinstance(name, str)]
    if len(narrative) != len(expected):
        return [
            "provenance.attack_path length must match the cited graph attack path step count"
        ]
    for index, (label, node_name) in enumerate(zip(narrative, expected, strict=True)):
        if not isinstance(label, str) or label != node_name:
            return [
                f"provenance.attack_path step {index} must match graph node name '{node_name}'"
            ]
    return []


def _threat_link_violations(
    payload: dict[str, JsonValue],
    attack_path: AttackPath,
    nodes_by_id: Mapping[str, object],
    edges_by_id: Mapping[str, object],
) -> list[str]:
    path_node_ids = {step.node_id for step in attack_path.steps}
    path_edge_ids = {
        step.via_edge_id for step in attack_path.steps if step.via_edge_id is not None
    }
    linked_component_ids = _threat_component_ids(payload)
    linked_flow_ids = _threat_data_flow_ids(payload)
    linked_asset_ids = _threat_asset_ids(payload)
    violations: list[str] = []
    if linked_component_ids and not linked_component_ids.intersection(
        _node_component_ids(nodes_by_id, path_node_ids)
    ):
        violations.append(
            "threat component references must appear on the cited attack path graph nodes"
        )
    if linked_flow_ids and not linked_flow_ids.intersection(
        _edge_flow_ids(edges_by_id, path_edge_ids)
    ):
        violations.append(
            "threat data_flow references must appear on the cited attack path graph edges"
        )
    if linked_asset_ids and not linked_asset_ids.intersection(
        _node_asset_ids(nodes_by_id, path_node_ids)
    ):
        violations.append(
            "threat asset references must appear on the cited attack path graph nodes"
        )
    return violations


def _threat_asset_ids(payload: dict[str, JsonValue]) -> set[str]:
    ids: set[str] = set()
    asset_id = payload.get("asset_id")
    if isinstance(asset_id, str) and asset_id:
        ids.add(asset_id)
    raw = payload.get("asset_ids")
    if isinstance(raw, list):
        ids.update(item for item in raw if isinstance(item, str) and item)
    return ids


def _node_component_ids(nodes_by_id: Mapping[str, object], path_node_ids: set[str]) -> set[str]:
    component_ids: set[str] = set()
    for node_id in path_node_ids:
        node = nodes_by_id.get(node_id)
        component_id = getattr(node, "component_id", None)
        if isinstance(component_id, str) and component_id:
            component_ids.add(component_id)
    return component_ids


def _node_asset_ids(nodes_by_id: Mapping[str, object], path_node_ids: set[str]) -> set[str]:
    asset_ids: set[str] = set()
    for node_id in path_node_ids:
        node = nodes_by_id.get(node_id)
        asset_id = getattr(node, "asset_id", None)
        if isinstance(asset_id, str) and asset_id:
            asset_ids.add(asset_id)
    return asset_ids


def _edge_flow_ids(edges_by_id: Mapping[str, object], path_edge_ids: set[str]) -> set[str]:
    flow_ids: set[str] = set()
    for edge_id in path_edge_ids:
        edge = edges_by_id.get(edge_id)
        flow_id = getattr(edge, "data_flow_id", None)
        if isinstance(flow_id, str) and flow_id:
            flow_ids.add(flow_id)
    return flow_ids
