"""Strategy-based extraction of diagram labels and Draw.io topology."""

import html
import re
import xml.etree.ElementTree as element_tree
from typing import Protocol

from threatmodeler.contracts.integration import (
    DiagramEdge,
    DiagramNode,
    DiagramTopologySnapshot,
)


class DiagramLabelExtractor(Protocol):
    """Define interchangeable extractors for supported diagram formats."""

    def supports(self, content: str) -> bool:
        """Return whether this extractor can parse the supplied content."""
        ...

    def extract(self, content: str) -> list[str]:
        """Extract de-duplicated visible labels from supported diagram content."""
        ...


class DrawioLabelExtractor:
    """Extract labels from Draw.io ``mxGraphModel`` and ``mxCell`` payloads."""

    def supports(self, content: str) -> bool:
        """Return whether the content contains Draw.io diagram markers."""
        return "mxGraphModel" in content or "mxCell" in content

    def extract(self, content: str) -> list[str]:
        """Extract Draw.io cell labels from supported diagram XML."""
        labels: list[str] = []
        seen: set[str] = set()
        try:
            root = element_tree.fromstring(content)
        except element_tree.ParseError:
            return self._extract_with_regex(content)
        for element in root.iter():
            if not element.tag.endswith("mxCell"):
                continue
            value = element.attrib.get("value")
            if value is None:
                continue
            label = self._clean_label(value)
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
        if labels:
            return labels
        return self._extract_with_regex(content)

    def _extract_with_regex(self, content: str) -> list[str]:
        labels: list[str] = []
        seen: set[str] = set()
        for match in re.finditer(r'value="([^"]+)"', content):
            label = self._clean_label(match.group(1))
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
        return labels

    def _clean_label(self, value: str) -> str:
        without_tags = re.sub(r"<[^>]+>", " ", value)
        return " ".join(html.unescape(without_tags).split())


class GliffyLabelExtractor:
    """Extract labels from Gliffy ``<text>`` diagram payloads."""

    def supports(self, content: str) -> bool:
        """Return whether the content contains Gliffy diagram markers."""
        return "gliffy" in content.lower()

    def extract(self, content: str) -> list[str]:
        """Extract Gliffy text labels from supported diagram XML."""
        labels: list[str] = []
        seen: set[str] = set()
        for match in re.finditer(r"<text[^>]*>([^<]+)</text>", content, flags=re.IGNORECASE):
            label = " ".join(html.unescape(match.group(1)).split())
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
        return labels


class DrawioTopologyExtractor:
    """Extract node and edge topology from Draw.io ``mxCell`` payloads."""

    def supports(self, content: str) -> bool:
        """Return whether the content contains Draw.io diagram markers."""
        return "mxGraphModel" in content or "mxCell" in content

    def extract(self, content: str, source_filename: str) -> DiagramTopologySnapshot:
        """Extract labeled vertices and directed edges from Draw.io XML.

        Args:
            content: Raw or HTML-encoded Draw.io XML.
            source_filename: Identifier for the diagram source.

        Returns:
            Topology snapshot with de-duplicated nodes and edges.
        """
        try:
            root = element_tree.fromstring(content)
        except element_tree.ParseError:
            return self._extract_with_regex(content, source_filename)
        nodes: list[DiagramNode] = []
        edges: list[DiagramEdge] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str, str]] = set()
        for element in root.iter():
            if not element.tag.endswith("mxCell"):
                continue
            cell_id = element.attrib.get("id")
            if not cell_id:
                continue
            if element.attrib.get("edge") == "1":
                source_id = element.attrib.get("source")
                target_id = element.attrib.get("target")
                if not source_id or not target_id:
                    continue
                label = self._clean_label(element.attrib.get("value", "")) or None
                key = (source_id, target_id, label or "")
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                edges.append(DiagramEdge(source_id=source_id, target_id=target_id, label=label))
                continue
            if element.attrib.get("vertex") != "1":
                continue
            label = self._clean_label(element.attrib.get("value", ""))
            if not label or cell_id in seen_nodes:
                continue
            seen_nodes.add(cell_id)
            nodes.append(DiagramNode(node_id=cell_id, label=label))
        if nodes or edges:
            return DiagramTopologySnapshot(
                source_filename=source_filename,
                nodes=nodes,
                edges=edges,
            )
        return self._extract_with_regex(content, source_filename)

    def _extract_with_regex(self, content: str, source_filename: str) -> DiagramTopologySnapshot:
        nodes: list[DiagramNode] = []
        seen_nodes: set[str] = set()
        for match in re.finditer(r'<mxCell\b([^>]*)\bvertex="1"([^>]*)', content):
            attributes = f"{match.group(1)} {match.group(2)}"
            cell_id = self._attribute(attributes, "id")
            label = self._clean_label(self._attribute(attributes, "value") or "")
            if not cell_id or not label or cell_id in seen_nodes:
                continue
            seen_nodes.add(cell_id)
            nodes.append(DiagramNode(node_id=cell_id, label=label))
        edges: list[DiagramEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for match in re.finditer(r'<mxCell\b([^>]*)\bedge="1"([^>]*)', content):
            attributes = f"{match.group(1)} {match.group(2)}"
            source_id = self._attribute(attributes, "source")
            target_id = self._attribute(attributes, "target")
            if not source_id or not target_id:
                continue
            edge_label = self._clean_label(self._attribute(attributes, "value") or "") or None
            key = (source_id, target_id, edge_label or "")
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(DiagramEdge(source_id=source_id, target_id=target_id, label=edge_label))
        return DiagramTopologySnapshot(
            source_filename=source_filename,
            nodes=nodes,
            edges=edges,
        )

    def _attribute(self, attributes: str, name: str) -> str | None:
        match = re.search(rf'\b{name}="([^"]*)"', attributes)
        return match.group(1) if match else None

    def _clean_label(self, value: str) -> str:
        without_tags = re.sub(r"<[^>]+>", " ", value)
        return " ".join(html.unescape(without_tags).split())


class DiagramContentExtractor:
    """Select and apply the first compatible diagram-label extraction strategy."""

    def __init__(self, extractors: tuple[DiagramLabelExtractor, ...] | None = None) -> None:
        self._extractors = extractors or (DrawioLabelExtractor(), GliffyLabelExtractor())
        self._topology_extractor = DrawioTopologyExtractor()

    def extract_labels(self, content: str) -> list[str]:
        """Extract visible labels from supported diagram XML payloads.

        Args:
            content: Raw diagram XML or HTML-encoded diagram XML.

        Returns:
            De-duplicated diagram labels in document order.
        """
        normalized = html.unescape(content.strip())
        if not normalized:
            return []
        for extractor in self._extractors:
            if extractor.supports(normalized):
                return extractor.extract(normalized)
        return []

    def extract_topology(self, content: str, source_filename: str) -> DiagramTopologySnapshot:
        """Extract Draw.io topology when the payload is a Draw.io diagram.

        Args:
            content: Raw diagram XML or HTML-encoded diagram XML.
            source_filename: Identifier for the diagram source.

        Returns:
            Topology snapshot, empty when the payload is not Draw.io XML.
        """
        normalized = html.unescape(content.strip())
        if not normalized or not self._topology_extractor.supports(normalized):
            return DiagramTopologySnapshot(source_filename=source_filename)
        return self._topology_extractor.extract(normalized, source_filename)


def extract_diagram_labels(content: str) -> list[str]:
    """Extract visible labels using the production diagram content extractor."""
    return DiagramContentExtractor().extract_labels(content)


def extract_diagram_topology(content: str, source_filename: str) -> DiagramTopologySnapshot:
    """Extract Draw.io topology using the production diagram content extractor."""
    return DiagramContentExtractor().extract_topology(content, source_filename)
