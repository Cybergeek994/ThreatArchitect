"""Parser-only tests for Confluence HTML and storage-format markup."""

from collections.abc import Callable

import pytest
from threatmodeler.contracts import AttachmentContent, AttachmentKind, ParsedInputRequest
from threatmodeler.contracts.source import SourceReference, SourceType
from threatmodeler.infrastructure.parsing.confluence_html_extractor import ConfluenceHtmlExtractor
from threatmodeler.infrastructure.parsing.confluence_page_parser import ConfluencePageParser


@pytest.fixture
def source_reference() -> SourceReference:
    """Create provenance for parser tests."""
    return SourceReference(
        source_type=SourceType.CONFLUENCE_ATTACHMENT,
        source_id="architecture",
        location="file:///architecture",
        excerpt="Architecture review export",
    )


@pytest.fixture
def parse_request_factory(
    source_reference: SourceReference,
) -> Callable[[str, str], ParsedInputRequest]:
    """Return a factory for parser requests with shared provenance."""

    def create(content: str, media_type: str) -> ParsedInputRequest:
        return ParsedInputRequest(
            document_id="payments-architecture",
            content=content,
            media_type=media_type,
            source_reference=source_reference,
        )

    return create


class TestConfluencePageParserPositive:
    """Verify supported HTML, XHTML, and Confluence storage markup."""

    def test_xhtml_media_type_is_parsed_as_html(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><h1>Actors</h1><p>Checkout client.</p></body></html>"

        document = ConfluencePageParser().parse(
            parse_request_factory(html, "application/xhtml+xml")
        )

        assert document.media_type == "application/xhtml+xml"
        assert document.headings[0].text == "Actors"
        assert document.paragraphs[0].text == "Checkout client."

    def test_object_and_ri_attachment_tags_become_image_references(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            "<p>Runtime architecture.</p>"
            '<object data="runtime.drawio" aria-label="Runtime"></object>'
            '<ri:attachment ri:filename="trust-map.gliffy" />'
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        sources = [reference.source for reference in document.image_references]
        assert "runtime.drawio" in sources
        assert "trust-map.gliffy" in sources
        assert all(reference.is_diagram for reference in document.image_references)

    def test_macro_plain_text_body_contributes_multiple_diagram_labels(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            "<ac:plain-text-body>"
            "<mxGraphModel>"
            '<mxCell value="Billing API" vertex="1"/>'
            '<mxCell value="Customer DB" vertex="1"/>'
            "</mxGraphModel>"
            "</ac:plain-text-body>"
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.startswith("Diagram:")
        ] == [
            "Diagram: Billing API",
            "Diagram: Customer DB",
        ]

    def test_duplicate_attachment_diagram_paragraphs_are_skipped(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        drawio_xml = b'<mxGraphModel><mxCell value="Auth Gateway" vertex="1"/></mxGraphModel>'
        digest = hashlib.sha256(drawio_xml).hexdigest()
        attachment = AttachmentContent(
            attachment_id="diagram-1",
            filename="runtime.drawio",
            media_type="application/xml",
            kind=AttachmentKind.DIAGRAM,
            content_base64=base64.b64encode(drawio_xml).decode("ascii"),
            size_bytes=len(drawio_xml),
            sha256=digest,
            source_reference=source_reference,
        )
        request = ParsedInputRequest(
            document_id="payments-architecture",
            content="<h1>Architecture</h1>",
            media_type="text/html",
            source_reference=source_reference,
            attachments=[attachment, attachment.model_copy(update={"attachment_id": "diagram-2"})],
        )

        document = ConfluencePageParser().parse(request)

        attachment_labels = [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.startswith("Diagram (runtime.drawio):")
        ]
        assert attachment_labels == ["Diagram (runtime.drawio): Auth Gateway"]

    def test_markup_inside_ignored_script_tags_is_not_extracted(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><script><div>Hidden</div></script><p>Visible</p></body></html>"

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.paragraphs[0].text == "Visible"
        assert "Hidden" not in document.raw_text

    def test_table_without_header_row_keeps_all_rows(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body><table>"
            "<tr><td>Payments API</td><td>Python</td></tr>"
            "<tr><td>Customer DB</td><td>PostgreSQL</td></tr>"
            "</table></body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.tables[0].headers == []
        assert document.tables[0].rows == [
            ["Payments API", "Python"],
            ["Customer DB", "PostgreSQL"],
        ]

    def test_duplicate_embedded_diagram_labels_are_not_repeated(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            '<ac:structured-macro ac:name="drawio">'
            "<ac:plain-text-body>"
            "<mxGraphModel>"
            '<mxCell value="Payments API" vertex="1"/>'
            '<mxCell value="Payments API" vertex="1"/>'
            "</mxGraphModel>"
            "</ac:plain-text-body>"
            "</ac:structured-macro>"
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        diagram_paragraphs = [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.startswith("Diagram:")
        ]
        assert diagram_paragraphs == ["Diagram: Payments API"]


class TestConfluencePageParserNegative:
    """Verify attachment diagram labels use a distinct prefix from embedded labels."""

    def test_attachment_diagram_labels_include_filename(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        drawio_xml = (
            b'<mxGraphModel><mxCell id="1" value="Auth Gateway" vertex="1"/></mxGraphModel>'
        )
        digest = hashlib.sha256(drawio_xml).hexdigest()
        request = ParsedInputRequest(
            document_id="payments-architecture",
            content="<h1>Architecture</h1>",
            media_type="text/html",
            source_reference=source_reference,
            attachments=[
                AttachmentContent(
                    attachment_id="diagram-1",
                    filename="runtime.drawio",
                    media_type="application/xml",
                    kind=AttachmentKind.DIAGRAM,
                    content_base64=base64.b64encode(drawio_xml).decode("ascii"),
                    size_bytes=len(drawio_xml),
                    sha256=digest,
                    source_reference=source_reference,
                )
            ],
        )

        document = ConfluencePageParser().parse(request)

        assert any(
            paragraph.text == "Diagram (runtime.drawio): Auth Gateway"
            for paragraph in document.paragraphs
        )

    def test_rich_text_macro_body_contributes_diagram_paragraphs(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            "<ac:rich-text-body>"
            '<mxGraphModel><mxCell value="Billing API" vertex="1"/></mxGraphModel>'
            "</ac:rich-text-body>"
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert any(paragraph.text == "Diagram: Billing API" for paragraph in document.paragraphs)

    def test_macro_body_without_labels_is_appended_as_paragraph(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            "<ac:plain-text-body>Supporting architecture notes.</ac:plain-text-body>"
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert any(
            paragraph.text == "Supporting architecture notes." for paragraph in document.paragraphs
        )

    def test_script_content_is_ignored_in_html(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><script>ignored()</script><h1>Visible</h1></body></html>"

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.headings[0].text == "Visible"
        assert "ignored" not in document.raw_text

    def test_markdown_title_falls_back_to_first_heading(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        markdown = "## Components\n\nDetails."

        document = ConfluencePageParser().parse(parse_request_factory(markdown, "text/markdown"))

        assert document.title == "Components"

    def test_attachment_image_reference_is_not_duplicated(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        image_bytes = b"image-bytes"
        digest = hashlib.sha256(image_bytes).hexdigest()
        request = ParsedInputRequest(
            document_id="payments-architecture",
            content='<p>Runtime</p><img src="runtime.png" alt="Runtime" />',
            media_type="text/html",
            source_reference=source_reference,
            attachments=[
                AttachmentContent(
                    attachment_id="image-1",
                    filename="runtime.png",
                    media_type="image/png",
                    kind=AttachmentKind.IMAGE,
                    content_base64=base64.b64encode(image_bytes).decode("ascii"),
                    size_bytes=len(image_bytes),
                    sha256=digest,
                    source_reference=source_reference,
                )
            ],
        )

        document = ConfluencePageParser().parse(request)

        assert len(document.image_references) == 1

    def test_empty_heading_and_list_items_are_skipped(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><h1> </h1><ul><li></li><li>Valid</li></ul></body></html>"

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.headings == []
        assert [paragraph.text for paragraph in document.paragraphs] == ["- Valid"]

    def test_duplicate_attachment_diagram_labels_are_skipped(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        drawio_xml = (
            b'<mxGraphModel><mxCell id="1" value="Auth Gateway" vertex="1"/>'
            b'<mxCell id="2" value="Auth Gateway" vertex="1"/></mxGraphModel>'
        )
        digest = hashlib.sha256(drawio_xml).hexdigest()
        request = ParsedInputRequest(
            document_id="payments-architecture",
            content="<h1>Architecture</h1>",
            media_type="text/html",
            source_reference=source_reference,
            attachments=[
                AttachmentContent(
                    attachment_id="diagram-1",
                    filename="runtime.drawio",
                    media_type="application/xml",
                    kind=AttachmentKind.DIAGRAM,
                    content_base64=base64.b64encode(drawio_xml).decode("ascii"),
                    size_bytes=len(drawio_xml),
                    sha256=digest,
                    source_reference=source_reference,
                )
            ],
        )

        document = ConfluencePageParser().parse(request)

        attachment_labels = [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.startswith("Diagram (runtime.drawio):")
        ]
        assert attachment_labels == ["Diagram (runtime.drawio): Auth Gateway"]

    def test_image_without_source_is_ignored(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><img alt='Missing source' /><p>Visible</p></body></html>"

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.image_references == []
        assert document.paragraphs[0].text == "Visible"

    def test_nested_markup_inside_script_is_ignored(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = "<html><body><script><p>Hidden</p></script><p>Visible</p></body></html>"

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.paragraphs[0].text == "Visible"
        assert "Hidden" not in document.raw_text

    def test_empty_paragraphs_and_table_rows_are_skipped(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body><p></p><table><tr><td></td></tr>"
            "<tr><th>Name</th></tr><tr><td>API</td></tr></table></body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.paragraphs == []
        assert document.tables[0].headers == ["Name"]
        assert document.tables[0].rows == [["API"]]

    def test_embedded_diagram_labels_skip_existing_paragraphs(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        html = (
            "<html><body>"
            "<p>Diagram: Payments API</p>"
            '<mxGraphModel><mxCell value="Payments API" vertex="1"/></mxGraphModel>'
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        diagram_paragraphs = [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.startswith("Diagram:")
        ]
        assert diagram_paragraphs == ["Diagram: Payments API"]

    def test_non_visual_attachments_are_not_merged_into_image_references(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        pdf_bytes = b"%PDF-1.4"
        digest = hashlib.sha256(pdf_bytes).hexdigest()
        request = ParsedInputRequest(
            document_id="payments-architecture",
            content="<p>Architecture notes</p>",
            media_type="text/html",
            source_reference=source_reference,
            attachments=[
                AttachmentContent(
                    attachment_id="doc-1",
                    filename="notes.pdf",
                    media_type="application/pdf",
                    kind=AttachmentKind.DOCUMENT,
                    content_base64=base64.b64encode(pdf_bytes).decode("ascii"),
                    size_bytes=len(pdf_bytes),
                    sha256=digest,
                    source_reference=source_reference,
                )
            ],
        )

        document = ConfluencePageParser().parse(request)

        assert document.image_references == []


class TestHtmlExtractionParserInternals:
    """Cover HTML parser branches that standard exports do not exercise."""

    def test_nested_start_tags_are_ignored_inside_script_blocks(self) -> None:
        parser = ConfluenceHtmlExtractor()
        parser._ignored_depth = 1

        parser.handle_starttag("p", [])

        assert parser.paragraphs == []

    def test_nested_end_tags_are_ignored_inside_script_blocks(self) -> None:
        parser = ConfluenceHtmlExtractor()
        parser._ignored_depth = 1

        parser.handle_endtag("p")

        assert parser.paragraphs == []

    def test_table_cells_outside_rows_are_ignored(self) -> None:
        parser = ConfluenceHtmlExtractor()
        parser.handle_starttag("td", [])
        parser.handle_data("orphan")
        parser.handle_endtag("td")

        assert parser.tables == []

    def test_table_cell_end_is_ignored_when_row_context_is_missing(self) -> None:
        parser = ConfluenceHtmlExtractor()
        parser._cell_parts = ["orphan"]

        parser.handle_endtag("td")

        assert parser._cell_parts is None
        assert parser.tables == []

    def test_macro_body_appends_each_diagram_label(self) -> None:
        parser = ConfluenceHtmlExtractor()
        drawio_xml = (
            "<mxGraphModel>"
            '<mxCell value="Billing API" vertex="1"/>'
            '<mxCell value="Customer DB" vertex="1"/>'
            "</mxGraphModel>"
        )

        parser._append_macro_body(drawio_xml)

        assert [paragraph.text for paragraph in parser.paragraphs] == [
            "Diagram: Billing API",
            "Diagram: Customer DB",
        ]
