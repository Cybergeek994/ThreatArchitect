"""Mermaid attack tree renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import AttackTree, AttackTreeNode
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.renderers.mermaid_base import MermaidNodeShape, MermaidRendererBase


class MermaidAttackTreeRenderer(MermaidRendererBase):
    """Render validated recursive attack-tree nodes as Mermaid.

    Uses OWASP-aligned visual differentiation:
    - Goals: Double circles (root attack objectives)
    - Attack steps: Rounded rectangles (intermediate actions)
    - Vulnerabilities: Rectangles (exploitable weaknesses)
    - Countermeasures: Hexagons (defensive controls)
    """

    def __init__(self, artifact_name: str = "attack-tree") -> None:
        self._artifact_name = artifact_name
        self._node_type_shapes = {
            "goal": MermaidNodeShape.DOUBLE_CIRCLE,
            "attack_step": MermaidNodeShape.ROUNDED,
            "vulnerability": MermaidNodeShape.RECTANGLE,
            "countermeasure": MermaidNodeShape.HEXAGON,
        }

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render attack nodes and parent-child relationships deterministically.

        Args:
            artifact: Validated recursive attack tree.

        Returns:
            Mermaid flowchart artifact representing the recursive attack tree.

        Raises:
            ArtifactRenderingError: If the artifact is not an attack tree.
        """
        if not isinstance(artifact, AttackTree):
            raise ArtifactRenderingError(
                "Mermaid attack tree rendering requires AttackTree",
                error_code="MERMAID_ATTACK_TREE_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        lines = ["flowchart TD"]
        for root in sorted(artifact.root_nodes, key=lambda item: item.id):
            self._append_node(root, lines)
        return RenderedArtifact(
            name=self._artifact_name,
            content="\n".join(lines) + "\n",
            media_type="text/vnd.mermaid",
            file_extension=".mmd",
        )

    def _append_node(self, node: AttackTreeNode, lines: list[str]) -> None:
        node_id = self.safe_id(node.id)
        label = self._format_node_label(node)
        shape = self._node_type_shapes.get(node.node_type, MermaidNodeShape.ROUNDED)
        node_def = self.format_node(node_id, label, shape)
        lines.append(node_def)
        for child in sorted(node.children, key=lambda item: item.id):
            self._append_node(child, lines)
            edge_label = self._format_edge_label(node.operator)
            if edge_label:
                lines.append(f"  {node_id} -->|{edge_label}| {self.safe_id(child.id)}")
            else:
                lines.append(f"  {node_id} --> {self.safe_id(child.id)}")

    def _format_node_label(self, node: AttackTreeNode) -> str:
        """Format a node label with operator and optional difficulty.

        Args:
            node: Attack tree node to format.

        Returns:
            Escaped label string for Mermaid.
        """
        parts = [node.name, f"[{node.operator}]"]
        if node.difficulty:
            parts.append(f"({node.difficulty})")
        return self.escape_label(" ".join(parts))

    def _format_edge_label(self, operator: str) -> str:
        """Return edge label based on parent operator.

        Args:
            operator: Parent node's logical operator.

        Returns:
            Edge label or empty string for leaf nodes.
        """
        if operator == "and":
            return "AND"
        if operator == "or":
            return "OR"
        return ""
