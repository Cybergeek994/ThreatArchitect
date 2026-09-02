"""Mermaid architecture graph renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import ArchitectureGraph, GraphEdge, GraphNode
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.renderers.mermaid_base import MermaidRendererBase


class MermaidArchitectureGraphRenderer(MermaidRendererBase):
    """Render typed architecture graph nodes and edges as Mermaid."""

    def __init__(self, artifact_name: str = "architecture-graph") -> None:
        self._artifact_name = artifact_name

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render graph nodes and edges deterministically."""
        if not isinstance(artifact, ArchitectureGraph):
            raise ArtifactRenderingError(
                "Mermaid architecture graph rendering requires ArchitectureGraph",
                error_code="MERMAID_ARCHITECTURE_GRAPH_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        lines = ["flowchart TD"]
        for node in sorted(artifact.nodes, key=lambda item: item.id):
            self._append_node(node, lines)
        for edge in sorted(artifact.edges, key=lambda item: item.id):
            self._append_edge(edge, lines)
        return RenderedArtifact(
            name=self._artifact_name,
            content="\n".join(lines) + "\n",
            media_type="text/vnd.mermaid",
            file_extension=".mmd",
        )

    def _append_node(self, node: GraphNode, lines: list[str]) -> None:
        node_id = self.safe_id(node.id)
        label = self.escape_label(f"{node.name} ({node.kind.value})")
        lines.append(f"    {node_id}[\"{label}\"]")

    def _append_edge(self, edge: GraphEdge, lines: list[str]) -> None:
        source_id = self.safe_id(edge.source_node_id)
        target_id = self.safe_id(edge.target_node_id)
        label = self.escape_label(edge.kind.value)
        lines.append(f"    {source_id} -->|{label}| {target_id}")
