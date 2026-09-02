"""Shared architecture graph fixtures for tests."""

from pydantic import JsonValue

from threatmodeler.contracts.artifacts.enums import StrideInputPayloadField
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph
from threatmodeler.contracts.artifacts.stride_context import PreStrideArtifacts, StrideUpstreamContext
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.architecture_graph_generation import ArchitectureGraphGenerationService
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.dfd_generation import DfdGenerationService
from threatmodeler.domain.inventory_generation import InventoryGenerationService


def architecture_graph_for_model(model: CanonicalSystemModel) -> ArchitectureGraph:
    """Build a deterministic architecture graph for ``model``."""
    return ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)


def stride_validator_input_payload(model: CanonicalSystemModel) -> dict[str, JsonValue]:
    """Build minimal STRIDE validator input payload with architecture graph."""
    graph = architecture_graph_for_model(model)
    return {
        StrideInputPayloadField.SYSTEM_MODEL: model.model_dump(mode="json"),
        StrideInputPayloadField.ARCHITECTURE_GRAPH: graph.model_dump(mode="json"),
    }


def default_attack_path_id(graph: ArchitectureGraph) -> str:
    """Return the first attack path id from ``graph``."""
    return graph.attack_paths[0].id


def attack_path_narrative(graph: ArchitectureGraph, attack_path_id: str) -> list[str]:
    """Return ordered node names for ``attack_path_id``."""
    nodes_by_id = {node.id: node for node in graph.nodes}
    for path in graph.attack_paths:
        if path.id == attack_path_id:
            return [nodes_by_id[step.node_id].name for step in path.steps]
    raise ValueError(f"unknown attack path id '{attack_path_id}'")


def stride_upstream_context_for_model(model: CanonicalSystemModel) -> StrideUpstreamContext:
    """Build validated STRIDE upstream context for ``model``."""
    metadata = ArtifactMetadataService()
    inventory = InventoryGenerationService(metadata)
    dfd_service = DfdGenerationService(metadata)
    graph_service = ArchitectureGraphGenerationService(metadata)
    pre_stride = PreStrideArtifacts(
        system_model=model,
        component_inventory=inventory.generate_component_inventory(model),
        asset_inventory=inventory.generate_asset_inventory(model),
        actor_model=inventory.generate_actor_model(model),
        data_flow_diagram=dfd_service.generate(model),
        trust_boundary_map=inventory.generate_trust_boundary_map(model),
        entry_point_inventory=inventory.generate_entry_point_inventory(model),
        authentication_authorization_model=(
            inventory.generate_authentication_authorization_model(model)
        ),
        deployment_model=inventory.generate_deployment_model(model),
    )
    return StrideUpstreamContext(
        **pre_stride.model_dump(),
        architecture_graph=graph_service.generate(model),
    )
