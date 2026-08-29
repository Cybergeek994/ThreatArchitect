"""Mermaid trust boundary renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import TrustBoundaryMap
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.contracts.system_model import TrustBoundaryType
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.renderers.mermaid_base import MermaidRendererBase


class MermaidTrustBoundaryRenderer(MermaidRendererBase):
    """Render trust boundaries as deterministic Mermaid subgraphs.

    Uses OWASP-aligned styling:
    - Trust boundaries rendered as subgraphs with dashed borders
    - Crossing flows marked with warning indicator
    - External boundaries given distinct visual treatment
    """

    def __init__(self, artifact_name: str = "trust-boundaries") -> None:
        self._artifact_name = artifact_name

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render boundary membership, crossing flows, and unassigned components.

        Args:
            artifact: Validated trust boundary map.

        Returns:
            Mermaid artifact containing boundary subgraphs and crossing flow edges.

        Raises:
            ArtifactRenderingError: If the artifact is not a trust boundary map.
        """
        if not isinstance(artifact, TrustBoundaryMap):
            raise ArtifactRenderingError(
                "Mermaid trust boundary rendering requires TrustBoundaryMap",
                error_code="MERMAID_TRUST_BOUNDARY_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        lines = ["flowchart TB"]
        boundary_ids: list[str] = []

        for boundary in sorted(artifact.trust_boundaries, key=lambda item: item.id):
            boundary_id = self.safe_id(f"boundary_{boundary.id}")
            boundary_ids.append(boundary_id)
            label = self._format_boundary_label(boundary.name, boundary.boundary_type)
            lines.append(f'  subgraph {boundary_id}["{label}"]')
            for component_id in sorted(boundary.component_ids):
                safe_component_id = self.safe_id(component_id)
                lines.append(f'    {safe_component_id}["{self.escape_label(component_id)}"]')
            lines.append("  end")

        for component_id in sorted(artifact.unassigned_component_ids):
            lines.append(f'  {self.safe_id(component_id)}["{self.escape_label(component_id)}"]')

        for flow in sorted(artifact.crossing_flows, key=lambda item: item.data_flow_id):
            label = f"⚠ {self.escape_label(flow.data_flow_id)}"
            lines.append(
                f"  {self.safe_id(flow.source_component_id)} -.->|{label}| "
                f"{self.safe_id(flow.destination_component_id)}"
            )

        for boundary_id in boundary_ids:
            lines.append(f"  style {boundary_id} stroke-dasharray: 5 5")

        return RenderedArtifact(
            name=self._artifact_name,
            content="\n".join(lines) + "\n",
            media_type="text/vnd.mermaid",
            file_extension=".mmd",
        )

    def _format_boundary_label(
        self,
        name: str,
        boundary_type: TrustBoundaryType,
    ) -> str:
        """Format a boundary label with type indicator.

        Args:
            name: Human-readable boundary name.
            boundary_type: The type of trust boundary.

        Returns:
            Formatted label with boundary type prefix.
        """
        type_prefix = {
            TrustBoundaryType.EXTERNAL: "🌐",
            TrustBoundaryType.NETWORK: "🔒",
            TrustBoundaryType.IDENTITY: "👤",
            TrustBoundaryType.PROCESS: "⚙",
            TrustBoundaryType.PHYSICAL: "🏢",
            TrustBoundaryType.ORGANIZATIONAL: "🏛",
            TrustBoundaryType.UNKNOWN: "",
        }
        prefix = type_prefix.get(boundary_type, "")
        escaped_name = self.escape_label(name)
        if prefix:
            return f"{prefix} {escaped_name}"
        return escaped_name
