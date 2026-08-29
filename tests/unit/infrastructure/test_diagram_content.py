"""Tests for Draw.io and Gliffy diagram label extraction."""

import pytest
from threatmodeler.infrastructure.parsing.diagram_content import (
    extract_diagram_labels,
    extract_diagram_topology,
)


class TestDiagramContentPositive:
    """Verify supported diagram payloads are parsed."""

    def test_extract_drawio_cell_labels(self) -> None:
        xml = """
        <mxGraphModel>
          <root>
            <mxCell id="0"/>
            <mxCell id="1" value="Payments API" vertex="1"/>
            <mxCell id="2" value="Customer DB" vertex="1"/>
          </root>
        </mxGraphModel>
        """

        labels = extract_diagram_labels(xml)

        assert labels == ["Payments API", "Customer DB"]

    def test_extract_gliffy_text_labels(self) -> None:
        xml = """
        <gliffy><text>Web Client</text><text>Order Service</text></gliffy>
        """

        labels = extract_diagram_labels(xml)

        assert labels == ["Web Client", "Order Service"]

    def test_extract_drawio_labels_from_html_encoded_content(self) -> None:
        xml = '&lt;mxCell value="Auth Gateway" vertex="1"/&gt;'

        labels = extract_diagram_labels(xml)

        assert labels == ["Auth Gateway"]

    def test_duplicate_drawio_labels_are_deduplicated(self) -> None:
        xml = """
        <mxGraphModel>
          <root>
            <mxCell id="1" value="Payments API" vertex="1"/>
            <mxCell id="2" value="Payments API" vertex="1"/>
          </root>
        </mxGraphModel>
        """

        assert extract_diagram_labels(xml) == ["Payments API"]

    def test_html_in_drawio_labels_is_stripped(self) -> None:
        xml = (
            '<mxGraphModel><mxCell value="&lt;b&gt;Auth Gateway&lt;/b&gt;" '
            'vertex="1"/></mxGraphModel>'
        )

        assert extract_diagram_labels(xml) == ["Auth Gateway"]

    def test_malformed_xml_falls_back_to_regex(self) -> None:
        xml = '<mxCell value="Fallback Label" vertex="1"'

        assert extract_diagram_labels(xml) == ["Fallback Label"]

    def test_gliffy_marker_is_case_insensitive(self) -> None:
        xml = "<GLIFFY><TEXT>Web Client</TEXT></GLIFFY>"

        assert extract_diagram_labels(xml) == ["Web Client"]


class TestDiagramContentNegative:
    """Verify unsupported or empty payloads are ignored."""

    def test_empty_content_returns_no_labels(self) -> None:
        assert extract_diagram_labels("") == []

    def test_unrecognized_content_returns_no_labels(self) -> None:
        assert extract_diagram_labels("plain architecture notes") == []

    @pytest.mark.parametrize("value", ["", "   ", "<b></b>"])

    def test_blank_drawio_values_are_ignored(self, value: str) -> None:
        xml = f'<mxGraphModel><mxCell value="{value}" vertex="1"/></mxGraphModel>'

        assert extract_diagram_labels(xml) == []


class TestDiagramContentGliffyDedup:
    """Verify Gliffy duplicate labels are skipped."""

    def test_duplicate_gliffy_labels_are_deduplicated(self) -> None:
        xml = "<gliffy><text>Web Client</text><text>Web Client</text></gliffy>"

        assert extract_diagram_labels(xml) == ["Web Client"]


class TestDrawioTopologyPositive:
    """Verify Draw.io edges and vertices are extracted."""

    def test_extract_drawio_nodes_and_edges(self) -> None:
        xml = """
        <mxGraphModel>
          <root>
            <mxCell id="1" value="Payments API" vertex="1"/>
            <mxCell id="2" value="Customer DB" vertex="1"/>
            <mxCell id="e1" edge="1" source="1" target="2" value="TLS"/>
          </root>
        </mxGraphModel>
        """

        topology = extract_diagram_topology(xml, "runtime.drawio")

        assert topology.source_filename == "runtime.drawio"
        assert [node.label for node in topology.nodes] == ["Payments API", "Customer DB"]
        assert topology.edges[0].source_id == "1"
        assert topology.edges[0].target_id == "2"
        assert topology.edges[0].label == "TLS"

    def test_malformed_drawio_falls_back_to_regex_topology(self) -> None:
        xml = (
            '<mxCell id="1" value="API" vertex="1"/>'
            '<mxCell id="e1" edge="1" source="1" target="2" value="HTTPS"'
        )

        topology = extract_diagram_topology(xml, "broken.drawio")

        assert topology.nodes[0].label == "API"
        assert topology.edges[0].source_id == "1"

    def test_drawio_skips_incomplete_edges_blank_vertices_and_duplicates(self) -> None:
        xml = """
        <mxGraphModel>
          <root>
            <mxCell id="1" value="Payments API" vertex="1"/>
            <mxCell id="2" value="" vertex="1"/>
            <mxCell id="e0" edge="1"/>
            <mxCell id="e1" edge="1" source="1" target="2" value="TLS"/>
            <mxCell id="e2" edge="1" source="1" target="2" value="TLS"/>
          </root>
        </mxGraphModel>
        """

        topology = extract_diagram_topology(xml, "runtime.drawio")

        assert [node.label for node in topology.nodes] == ["Payments API"]
        assert len(topology.edges) == 1

    def test_regex_topology_skips_incomplete_and_duplicate_edges(self) -> None:
        xml = (
            '<mxCell id="1" value="API" vertex="1"/>'
            '<mxCell id="e0" edge="1" source="1"'
            '<mxCell id="e1" edge="1" source="1" target="2" value="HTTPS"'
            '<mxCell id="e2" edge="1" source="1" target="2" value="HTTPS"'
        )

        topology = extract_diagram_topology(xml, "broken.drawio")

        assert len(topology.edges) == 1


class TestDrawioTopologyNegative:
    """Verify unsupported payloads produce empty topology."""

    def test_gliffy_content_returns_empty_topology(self) -> None:
        topology = extract_diagram_topology("<gliffy><text>Web Client</text></gliffy>", "gliffy")

        assert topology.nodes == []
        assert topology.edges == []


    def test_diagram_topology_skips_edges_missing_source_or_target(self) -> None:
        xml = (
            '<mxCell id="1" value="API" vertex="1"/>'
            '<mxCell id="e0" edge="1" target="2"/>'
            '<mxCell id="e1" edge="1" source="1"/>'
            '<mxCell id="e2" edge="1" source="1" target="2" value="HTTPS"/>'
        )
        topology = extract_diagram_topology(xml, "broken.drawio")
        assert len(topology.edges) == 1

    def test_diagram_topology_regex_duplicate_edge_continue(self) -> None:
        xml = (
            '<mxCell id="1" value="API" vertex="1"/>'
            '<mxCell id="e1" edge="1" source="1" target="2" value="HTTPS"/>'
            '<mxCell id="e2" edge="1" source="1" target="2" value="HTTPS"/>'
        )
        topology = extract_diagram_topology(xml, "dup.drawio")
        assert len(topology.edges) == 1
