"""Structured graph JSON flow diagram renderer."""

from pydantic import BaseModel

from threatmodeler.contracts import FlowDiagramEdge, FlowDiagramGraph, FlowDiagramNode
from threatmodeler.contracts.artifacts import DataFlowDiagramModel
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactRenderingError


class FlowDiagramRenderer:
    """Render a validated DFD as a structured nodes-and-edges JSON graph."""

    def __init__(self, artifact_name: str = "dfd") -> None:
        self._artifact_name = artifact_name

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render a deterministic graph JSON document.

        Args:
            artifact: Validated data flow diagram model to transform.

        Returns:
            JSON artifact containing normalized nodes and directional edges.

        Raises:
            ArtifactRenderingError: If the artifact is not a data flow diagram model.
        """
        if not isinstance(artifact, DataFlowDiagramModel):
            raise ArtifactRenderingError(
                "Flow diagram rendering requires DataFlowDiagramModel",
                error_code="FLOW_DIAGRAM_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        nodes = [
            FlowDiagramNode(
                id=component.id,
                label=component.name,
                node_type=component.component_type.value,
            )
            for component in sorted(artifact.components, key=lambda item: item.id)
        ]
        nodes.extend(
            FlowDiagramNode(
                id=store.id,
                label=store.name,
                node_type=f"data_store:{store.data_store_type.value}",
            )
            for store in sorted(artifact.data_stores, key=lambda item: item.id)
        )
        edges = [
            FlowDiagramEdge(
                id=flow.id,
                source=flow.source_component_id,
                target=flow.destination_component_id,
                label=f"{flow.name}: {flow.protocol}",
                encrypted_in_transit=flow.encrypted_in_transit,
                trust_boundary_crossed=flow.trust_boundary_crossed,
            )
            for flow in sorted(artifact.data_flows, key=lambda item: item.id)
        ]
        graph = FlowDiagramGraph(nodes=nodes, edges=edges)
        return RenderedArtifact(
            name=self._artifact_name,
            content=graph.model_dump_json(indent=2),
            media_type="application/json",
            file_extension=".json",
        )
