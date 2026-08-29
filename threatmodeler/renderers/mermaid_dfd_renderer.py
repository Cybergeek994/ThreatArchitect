"""Mermaid data flow diagram renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import DataFlowDiagramModel
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.renderers.mermaid_base import MermaidRendererBase


class MermaidDfdRenderer(MermaidRendererBase):
    """Render a validated DFD artifact as Mermaid flowchart text.

    Uses OWASP-aligned node shapes:
    - Components: Shape varies by type (API=stadium, web_app=hexagon, etc.)
    - Data stores: Cylinder shape
    - Flows: Thick arrows for encrypted, dotted for boundary crossings
    """

    def __init__(self, artifact_name: str = "dfd") -> None:
        self._artifact_name = artifact_name

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render components, stores, and directional flows deterministically.

        Args:
            artifact: Validated data flow diagram model.

        Returns:
            Mermaid flowchart artifact representing the data flow diagram.

        Raises:
            ArtifactRenderingError: If the artifact is not a data flow diagram model.
        """
        if not isinstance(artifact, DataFlowDiagramModel):
            raise ArtifactRenderingError(
                "Mermaid DFD rendering requires DataFlowDiagramModel",
                error_code="MERMAID_DFD_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        lines = ["flowchart LR"]

        for component in sorted(artifact.components, key=lambda item: item.id):
            shape = self.shape_for_component_type(component.component_type)
            node_def = self.format_node(
                self.safe_id(component.id),
                self.escape_label(component.name),
                shape,
            )
            lines.append(node_def)

        for store in sorted(artifact.data_stores, key=lambda item: item.id):
            shape = self.shape_for_data_store_type(store.data_store_type)
            node_def = self.format_node(
                self.safe_id(store.id),
                self.escape_label(store.name),
                shape,
            )
            lines.append(node_def)

        for flow in sorted(artifact.data_flows, key=lambda item: item.id):
            label = self.escape_label(f"{flow.name}: {flow.protocol}")
            arrow = self.format_flow_arrow(
                encrypted=flow.encrypted_in_transit,
                boundary_crossed=flow.trust_boundary_crossed,
            )
            if flow.trust_boundary_crossed:
                label = f"⚠ {label}"
            lines.append(
                f"  {self.safe_id(flow.source_component_id)} {arrow}|{label}| "
                f"{self.safe_id(flow.destination_component_id)}"
            )

        return RenderedArtifact(
            name=self._artifact_name,
            content="\n".join(lines) + "\n",
            media_type="text/vnd.mermaid",
            file_extension=".mmd",
        )
