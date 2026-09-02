"""Deterministic architecture graph compilation from canonical model."""

from threatmodeler.contracts.artifacts.enums import GraphEdgeKind, GraphNodeKind, StrideCategory
from threatmodeler.contracts.artifacts.graph import (
    ArchitectureGraph,
    AttackPath,
    AttackPathStep,
    GraphEdge,
    GraphNode,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel, ComponentType, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class ArchitectureGraphGenerationService:
    """Compile a typed architecture graph deterministically from the canonical model."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate(self, model: CanonicalSystemModel) -> ArchitectureGraph:
        """Build nodes, edges, and attack paths from canonical architecture entities."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        attack_paths: list[AttackPath] = []

        for actor in model.actors:
            nodes.append(
                GraphNode(
                    **self._metadata.item_fields(
                        f"graph-node-actor-{actor.id}",
                        actor.name,
                        actor.description,
                        actor.evidence,
                        actor.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=GraphNodeKind.ACTOR,
                    actor_id=actor.id,
                )
            )

        for entry in model.entry_points:
            if not entry.exposure.is_external_facing():
                continue
            nodes.append(
                GraphNode(
                    **self._metadata.item_fields(
                        f"graph-node-entry-{entry.id}",
                        entry.name,
                        entry.description,
                        entry.evidence,
                        entry.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=GraphNodeKind.ENTRY_SURFACE,
                    entry_point_id=entry.id,
                    component_id=entry.component_id,
                )
            )

        for component in model.components:
            nodes.append(
                GraphNode(
                    **self._metadata.item_fields(
                        f"graph-node-component-{component.id}",
                        component.name,
                        component.description,
                        component.evidence,
                        component.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=_component_node_kind(component.component_type),
                    component_id=component.id,
                )
            )

        for store in model.data_stores:
            nodes.append(
                GraphNode(
                    **self._metadata.item_fields(
                        f"graph-node-store-{store.id}",
                        store.name,
                        store.description,
                        store.evidence,
                        store.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=_store_node_kind(store.data_store_type.value),
                    data_store_id=store.id,
                )
            )

        component_node_id = {
            node.component_id: node.id
            for node in nodes
            if node.component_id is not None and node.kind is not GraphNodeKind.ENTRY_SURFACE
        }
        entry_nodes = [
            node for node in nodes if node.kind is GraphNodeKind.ENTRY_SURFACE
        ]

        for flow in model.data_flows:
            source_node_id = component_node_id.get(flow.source_component_id)
            target_node_id = component_node_id.get(flow.destination_component_id)
            if source_node_id is None or target_node_id is None:
                continue
            edges.append(
                GraphEdge(
                    **self._metadata.item_fields(
                        f"graph-edge-flow-{flow.id}",
                        flow.name,
                        flow.description,
                        flow.evidence,
                        flow.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=GraphEdgeKind.CALLS,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    data_flow_id=flow.id,
                    protocol=flow.protocol,
                    authentication_method=flow.authentication_method,
                    encrypted_in_transit=flow.encrypted_in_transit,
                )
            )

        for entry_node in entry_nodes:
            component_node = component_node_id.get(entry_node.component_id or "")
            if component_node is None:
                continue
            edge_id = f"graph-edge-exposes-{entry_node.id}"
            edges.append(
                GraphEdge(
                    **self._metadata.item_fields(
                        edge_id,
                        f"Expose {entry_node.name}",
                        f"Public ingress to {entry_node.component_id}.",
                        entry_node.evidence,
                        entry_node.confidence,
                        model.assumptions,
                    ).model_dump(),
                    kind=GraphEdgeKind.EXPOSES,
                    source_node_id=entry_node.id,
                    target_node_id=component_node,
                )
            )
            attack_paths.append(
                AttackPath(
                    **self._metadata.item_fields(
                        f"attack-path-{entry_node.id}-{component_node}",
                        f"Path via {entry_node.name}",
                        f"Reach {entry_node.component_id} through {entry_node.name}.",
                        entry_node.evidence,
                        entry_node.confidence,
                        model.assumptions,
                    ).model_dump(),
                    steps=[
                        AttackPathStep(node_id=entry_node.id, via_edge_id=None),
                        AttackPathStep(node_id=component_node, via_edge_id=edge_id),
                    ],
                    entry_node_id=entry_node.id,
                    target_node_id=component_node,
                    stride_categories=[StrideCategory.SPOOFING],
                )
            )

        if not attack_paths and nodes:
            first_node = nodes[0]
            attack_paths.append(
                AttackPath(
                    **self._metadata.item_fields(
                        f"attack-path-{first_node.id}",
                        f"Path to {first_node.name}",
                        f"Reach {first_node.name}.",
                        first_node.evidence,
                        first_node.confidence,
                        model.assumptions,
                    ).model_dump(),
                    steps=[AttackPathStep(node_id=first_node.id, via_edge_id=None)],
                    entry_node_id=first_node.id,
                    target_node_id=first_node.id,
                    stride_categories=[StrideCategory.SPOOFING],
                )
            )

        return ArchitectureGraph(
            **self._metadata.artifact_fields(
                "architecture-graph",
                "Architecture Graph",
                "Typed architecture graph with enumerated attack paths.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    [*nodes, *edges, *attack_paths],
                    when_empty=model.application.confidence,
                ),
            ).model_dump(),
            nodes=nodes,
            edges=edges,
            attack_paths=attack_paths,
        )


def _component_node_kind(component_type: ComponentType) -> GraphNodeKind:
    if component_type is ComponentType.API:
        return GraphNodeKind.API
    if component_type is ComponentType.IDENTITY_PROVIDER:
        return GraphNodeKind.IDENTITY
    if component_type is ComponentType.EXTERNAL_SERVICE:
        return GraphNodeKind.EXTERNAL_SERVICE
    return GraphNodeKind.SERVICE


def _store_node_kind(store_type: str) -> GraphNodeKind:
    if store_type == "queue":
        return GraphNodeKind.QUEUE
    if store_type == "object_storage":
        return GraphNodeKind.STORAGE
    return GraphNodeKind.DATABASE
