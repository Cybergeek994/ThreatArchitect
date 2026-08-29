"""Shared deterministic Mermaid rendering helpers."""

import re
from enum import StrEnum

from threatmodeler.contracts.system_model import ComponentType, DataStoreType


class MermaidNodeShape(StrEnum):
    """Mermaid flowchart node shape syntax patterns.

    Each value is a format string with {label} placeholder for the node text.
    Shapes are chosen to align with OWASP DFD notation where possible.
    """

    RECTANGLE = '["{label}"]'
    ROUNDED = '("{label}")'
    STADIUM = '(["{label}"])'
    CYLINDER = '[("{label}")]'
    HEXAGON = '{{"{label}"}}'
    PARALLELOGRAM = '[/"{label}"/]'
    PARALLELOGRAM_ALT = '[\\"{label}"\\]'
    SUBROUTINE = '[["{label}"]]'
    ASYMMETRIC = '>"{label}"]'
    DOUBLE_CIRCLE = '((("{label}")))'
    CIRCLE = '(("{label}"))'


class MermaidRendererBase:
    """Provide safe Mermaid identifiers and labels without shared state."""

    def safe_id(self, value: str) -> str:
        """Convert an external identifier into a Mermaid-safe identifier.

        Args:
            value: Model identifier requiring Mermaid-safe normalization.

        Returns:
            Identifier containing only Mermaid-compatible characters.
        """
        normalized = re.sub(r"[^A-Za-z0-9_]", "_", value)
        return f"node_{normalized}"

    def escape_label(self, value: str) -> str:
        """Escape label text for a Mermaid quoted label.

        Args:
            value: Human-readable label to embed in Mermaid text.

        Returns:
            Label with special characters safely escaped.
        """
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return " ".join(escaped.replace("|", "&#124;").split())

    def shape_for_component_type(self, component_type: ComponentType) -> MermaidNodeShape:
        """Return the OWASP-aligned Mermaid shape for a component type.

        Args:
            component_type: The component type to map to a shape.

        Returns:
            Mermaid node shape matching OWASP DFD notation.
        """
        shape_mapping = {
            ComponentType.WEB_APP: MermaidNodeShape.HEXAGON,
            ComponentType.API: MermaidNodeShape.STADIUM,
            ComponentType.DATABASE: MermaidNodeShape.CYLINDER,
            ComponentType.QUEUE: MermaidNodeShape.SUBROUTINE,
            ComponentType.JOB: MermaidNodeShape.ROUNDED,
            ComponentType.STORAGE: MermaidNodeShape.CYLINDER,
            ComponentType.SERVERLESS: MermaidNodeShape.HEXAGON,
            ComponentType.CONTAINER: MermaidNodeShape.SUBROUTINE,
            ComponentType.EXTERNAL_SERVICE: MermaidNodeShape.ASYMMETRIC,
            ComponentType.IDENTITY_PROVIDER: MermaidNodeShape.HEXAGON,
            ComponentType.UNKNOWN: MermaidNodeShape.RECTANGLE,
        }
        return shape_mapping.get(component_type, MermaidNodeShape.RECTANGLE)

    def shape_for_data_store_type(self, store_type: DataStoreType) -> MermaidNodeShape:
        """Return the OWASP-aligned Mermaid shape for a data store type.

        OWASP shows data stores as open rectangles (parallel lines).
        Mermaid cylinder shape is the closest approximation.

        Args:
            store_type: The data store type to map to a shape.

        Returns:
            Mermaid node shape for data stores.
        """
        return MermaidNodeShape.CYLINDER

    def format_node(
        self,
        node_id: str,
        label: str,
        shape: MermaidNodeShape,
    ) -> str:
        """Format a Mermaid node definition with the given shape.

        Args:
            node_id: Safe Mermaid identifier for the node.
            label: Escaped label text for the node.
            shape: Mermaid shape to use for the node.

        Returns:
            Complete Mermaid node definition string.
        """
        return f"  {node_id}{shape.value.format(label=label)}"

    def format_flow_arrow(
        self,
        *,
        encrypted: bool = False,
        boundary_crossed: bool = False,
    ) -> str:
        """Return the appropriate Mermaid arrow style for a data flow.

        Args:
            encrypted: True if the flow is encrypted in transit.
            boundary_crossed: True if the flow crosses a trust boundary.

        Returns:
            Mermaid arrow syntax (e.g., '-->', '==>', '-.->').
        """
        if encrypted:
            return "==>"
        if boundary_crossed:
            return "-.->"
        return "-->"
