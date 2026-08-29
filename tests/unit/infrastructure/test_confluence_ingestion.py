"""Tests for local Confluence HTML and Markdown ingestion."""

import json
from collections.abc import Callable
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from pytest import MonkeyPatch
from threatmodeler.application.ingestion_service import ConfluenceIngestionService
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.contracts import AttachmentKind, ParsedInputRequest, SourceReference, SourceType
from threatmodeler.errors import ConfluenceClientError, DocumentParsingError
from threatmodeler.infrastructure.confluence.local_file_client import (
    LocalFileConfluenceClient,
)
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.infrastructure.parsing.confluence_page_parser import ConfluencePageParser
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer
from threatmodeler.shared.constants import LogLevel
from typer.testing import CliRunner


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


@pytest.fixture
def ingestion_service() -> ConfluenceIngestionService:
    """Compose local adapters for an ingestion test."""
    return ConfluenceIngestionService(
        confluence_client=LocalFileConfluenceClient(),
        document_parser=ConfluencePageParser(),
        artifact_renderer=JsonArtifactRenderer("parsed-document"),
        artifact_repository=LocalArtifactRepository(),
    )


class TestConfluenceIngestionPositive:
    """Verify supported inputs and successful behavior."""

    def test_html_parser_extracts_structured_architecture_content(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        html = """
        <html>
          <head><title>Payments Architecture</title></head>
          <body>
            <h1>System overview</h1>
            <p>The API processes customer payments.</p>
            <h2>Components</h2>
            <table>
              <tr><th>Component</th><th>Technology</th></tr>
              <tr><td>Payments API</td><td>Python</td></tr>
            </table>
            <img src="architecture-diagram.png" alt="Payments diagram" />
            <script>secretIgnoredText()</script>
          </body>
        </html>
        """

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert document.title == "Payments Architecture"
        assert [(heading.level, heading.text) for heading in document.headings] == [
            (1, "System overview"),
            (2, "Components"),
        ]
        assert document.paragraphs[0].text == "The API processes customer payments."
        assert document.tables[0].headers == ["Component", "Technology"]
        assert document.tables[0].rows == [["Payments API", "Python"]]
        assert document.image_references[0].source == "architecture-diagram.png"
        assert document.image_references[0].is_diagram is True
        assert "Payments API" in document.raw_text
        assert "secretIgnoredText" not in document.raw_text

    def test_html_parser_extracts_drawio_macro_labels(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        drawio_xml = (
            "<mxGraphModel><root>"
            '<mxCell id="1" value="Payments API" vertex="1"/>'
            '<mxCell id="2" value="Customer DB" vertex="1"/>'
            "</root></mxGraphModel>"
        )
        html = (
            "<html><body>"
            '<ac:structured-macro ac:name="drawio">'
            f"<ac:plain-text-body>{drawio_xml}</ac:plain-text-body>"
            "</ac:structured-macro>"
            "</body></html>"
        )

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert [paragraph.text for paragraph in document.paragraphs] == [
            "Diagram: Payments API",
            "Diagram: Customer DB",
        ]
        assert "Payments API" in document.raw_text

    def test_html_parser_extracts_labels_from_diagram_attachments(
        self,
        source_reference: SourceReference,
    ) -> None:
        import base64
        import hashlib

        from threatmodeler.contracts import AttachmentContent, AttachmentKind

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

        assert any("Auth Gateway" in paragraph.text for paragraph in document.paragraphs)
        assert "Auth Gateway" in document.raw_text

    def test_html_parser_extracts_ordered_and_unordered_lists(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        html = """
        <html><body>
          <ul><li>Public API</li><li>Database</li></ul>
          <ol><li>Authenticate</li><li>Authorize</li></ol>
        </body></html>
        """

        document = ConfluencePageParser().parse(parse_request_factory(html, "text/html"))

        assert [paragraph.text for paragraph in document.paragraphs] == [
            "- Public API",
            "- Database",
            "1. Authenticate",
            "2. Authorize",
        ]

    def test_markdown_parser_extracts_structured_architecture_content(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        markdown = """# Order Service Architecture

The service receives orders from the web application.

## Data flows

| Source | Destination | Protocol |
| --- | --- | --- |
| Web | API | HTTPS |

![Order flow diagram](order-flow.drawio.png "Runtime diagram")
"""

        document = ConfluencePageParser().parse(parse_request_factory(markdown, "text/markdown"))

        assert document.title == "Order Service Architecture"
        assert document.headings[1].text == "Data flows"
        assert document.paragraphs[0].text == (
            "The service receives orders from the web application."
        )
        assert document.tables[0].headers == ["Source", "Destination", "Protocol"]
        assert document.tables[0].rows == [["Web", "API", "HTTPS"]]
        assert document.image_references[0].alt_text == "Order flow diagram"
        assert document.image_references[0].is_diagram is True
        assert "Order Service Architecture" in document.raw_text

    def test_html_parser_recognizes_confluence_storage_attachment_tags(
        self,
        parse_request_factory: Callable[[str, str], ParsedInputRequest],
    ) -> None:
        storage_html = (
            "<h1>Architecture</h1><p>Runtime view.</p>"
            '<ac:image><ri:attachment ri:filename="runtime.drawio" /></ac:image>'
        )

        document = ConfluencePageParser().parse(parse_request_factory(storage_html, "text/html"))

        assert document.image_references[0].source == "runtime.drawio"
        assert document.image_references[0].is_diagram is True

    @pytest.mark.parametrize("suffix", [".html", ".md"])

    def test_local_file_client_reads_supported_exports(self, tmp_path: Path, suffix: str) -> None:
        export = tmp_path / f"sample{suffix}"
        export.write_text("# Architecture" if suffix == ".md" else "<h1>Architecture</h1>")

        page = LocalFileConfluenceClient().get_page(str(export))

        assert page.page_id == "sample"
        assert page.media_type == ("text/markdown" if suffix == ".md" else "text/html")
        assert page.source_type is SourceType.CONFLUENCE_ATTACHMENT
        assert page.url.scheme == "file"

    def test_local_client_loads_referenced_diagrams_and_documents(self, tmp_path: Path) -> None:
        diagram = tmp_path / "architecture.drawio.png"
        document = tmp_path / "security-notes.pdf"
        diagram.write_bytes(b"diagram-bytes")
        document.write_bytes(b"pdf-bytes")
        export = tmp_path / "sample.html"
        export.write_text(
            '<h1>Architecture</h1><img src="architecture.drawio.png">'
            '<a href="security-notes.pdf">Security notes</a>',
            encoding="utf-8",
        )

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert [attachment.filename for attachment in attachments] == [
            "architecture.drawio.png",
            "security-notes.pdf",
        ]
        assert attachments[0].kind is AttachmentKind.DIAGRAM
        assert attachments[0].decoded_content() == b"diagram-bytes"
        assert attachments[0].source_reference.source_type is SourceType.DIAGRAM
        assert attachments[1].kind is AttachmentKind.DOCUMENT

    def test_ingestion_persists_attachment_content_for_later_agents(
        self,
        tmp_path: Path,
        ingestion_service: ConfluenceIngestionService,
    ) -> None:
        diagram = tmp_path / "runtime-diagram.png"
        diagram.write_bytes(b"image-content")
        export = tmp_path / "sample.md"
        export.write_text(
            "# Architecture\n\n![Runtime diagram](runtime-diagram.png)",
            encoding="utf-8",
        )

        saved = ingestion_service.ingest(str(export), tmp_path / "out")

        payload = json.loads(saved.path.read_text())
        assert payload["attachments"][0]["filename"] == "runtime-diagram.png"
        assert payload["attachments"][0]["kind"] == "diagram"
        assert payload["attachments"][0]["content_base64"]
        assert payload["image_references"][0]["source"] == "runtime-diagram.png"

    def test_ingestion_service_writes_parsed_document_json(
        self, tmp_path: Path, ingestion_service: ConfluenceIngestionService
    ) -> None:
        export = tmp_path / "sample.html"
        output_dir = tmp_path / "out"
        export.write_text("<title>Sample</title><h1>Overview</h1><p>System details.</p>")

        saved = ingestion_service.ingest(str(export), output_dir)

        assert saved.path == output_dir.resolve() / "parsed-document.json"
        payload = json.loads(saved.path.read_text())
        assert payload["title"] == "Sample"
        assert payload["headings"] == [{"level": 1, "text": "Overview"}]
        assert payload["paragraphs"] == [{"text": "System details."}]

    def test_cli_ingest_command_writes_expected_artifact(
        self, tmp_path: Path, ingestion_service: ConfluenceIngestionService
    ) -> None:
        export = tmp_path / "sample.md"
        output_dir = tmp_path / "out"
        export.write_text("# CLI Architecture\n\nParsed through the CLI.")
        log_stream = StringIO()
        logger = StandardLoggerFactory(LogLevel.INFO, log_stream).create("test.ingest")

        ingestion_factory = Mock(return_value=ingestion_service)
        unused_extraction_factory = Mock(
            side_effect=AssertionError("Extraction should not run during ingestion")
        )
        unused_artifact_factory = Mock(
            side_effect=AssertionError("Artifact generation should not run during ingestion")
        )
        unused_rendering_factory = Mock(
            side_effect=AssertionError("Rendering should not run during ingestion")
        )
        unused_analysis_factory = Mock(
            side_effect=AssertionError("Analysis should not run during ingestion")
        )

        app = create_app(
            ingestion_factory,
            unused_extraction_factory,
            unused_artifact_factory,
            unused_rendering_factory,
            unused_analysis_factory,
            CliErrorHandler(logger),
        )

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(export), "--output", str(output_dir)],
        )

        assert result.exit_code == 0
        assert (output_dir / "parsed-document.json").is_file()
        assert "parsed-document.json" in result.stdout
        ingestion_factory.assert_called_once_with(str(export))
        unused_extraction_factory.assert_not_called()
        unused_artifact_factory.assert_not_called()
        unused_rendering_factory.assert_not_called()
        unused_analysis_factory.assert_not_called()


class TestConfluenceIngestionNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_parsed_document_rejects_schema_less_metadata(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        document = ConfluencePageParser().parse(
            parse_request_factory("<h1>Architecture</h1>", "text/html")
        )
        payload = document.model_dump(mode="json")
        payload["metadata"] = {"arbitrary": True}

        with pytest.raises(ValidationError, match="metadata"):
            type(document).model_validate(payload)

    def test_local_client_ignores_references_outside_export_directory(
        self,
        tmp_path: Path,
    ) -> None:
        export_dir = tmp_path / "export"
        export_dir.mkdir()
        outside = tmp_path / "outside.png"
        outside.write_bytes(b"outside")
        export = export_dir / "sample.md"
        export.write_text("# Architecture\n\n![Outside](../outside.png)", encoding="utf-8")

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert attachments == []


class TestConfluenceIngestionErrors:
    """Verify dependency and application failures remain controlled."""

    def test_parser_uses_document_parsing_error_for_unsupported_media(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        request = parse_request_factory("Architecture content", "application/pdf")

        with pytest.raises(DocumentParsingError) as captured:
            ConfluencePageParser().parse(request)

        assert captured.value.error_code == "DOCUMENT_MEDIA_TYPE_UNSUPPORTED"
        assert captured.value.retryable is False

    def test_parser_uses_document_parsing_error_for_empty_content(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        request = parse_request_factory("<script>ignored()</script>", "text/html")

        with pytest.raises(DocumentParsingError) as captured:
            ConfluencePageParser().parse(request)

        assert captured.value.error_code == "DOCUMENT_CONTENT_EMPTY"

    def test_malformed_markdown_table_is_translated_to_document_parsing_error(
        self, parse_request_factory: Callable[[str, str], ParsedInputRequest]
    ) -> None:
        malformed_markdown = """# Architecture

    | | Destination |
    | --- | --- |
    | API | Database |
    """

        with pytest.raises(DocumentParsingError) as captured:
            ConfluencePageParser().parse(parse_request_factory(malformed_markdown, "text/markdown"))

        assert captured.value.error_code == "DOCUMENT_PARSE_FAILED"
        assert captured.value.context == {
            "document_id": "payments-architecture",
            "media_type": "text/markdown",
        }

    def test_local_client_rejects_attachment_above_size_limit(self, tmp_path: Path) -> None:
        attachment = tmp_path / "large.png"
        attachment.write_bytes(b"too-large")
        export = tmp_path / "sample.html"
        export.write_text('<h1>Architecture</h1><img src="large.png">', encoding="utf-8")

        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient(max_attachment_bytes=3).get_attachments(str(export))

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_SIZE_INVALID"

    def test_local_client_rejects_zero_attachment_limit(self) -> None:
        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient(max_attachment_bytes=0)

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_LIMIT_INVALID"

    def test_local_client_rejects_unsupported_export_type(self, tmp_path: Path) -> None:
        export = tmp_path / "sample.txt"
        export.write_text("plain text", encoding="utf-8")

        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient().get_page(str(export))

        assert captured.value.error_code == "CONFLUENCE_LOCAL_UNSUPPORTED_TYPE"

    def test_local_client_reads_object_and_ri_attachment_references(self, tmp_path: Path) -> None:
        attachment = tmp_path / "runtime.drawio"
        attachment.write_bytes(b"diagram")
        export = tmp_path / "sample.html"
        export.write_text(
            '<object data="runtime.drawio"></object><ri:attachment ri:filename="runtime.drawio" />',
            encoding="utf-8",
        )

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert len(attachments) == 1
        assert attachments[0].filename == "runtime.drawio"

    def test_local_client_reports_unreadable_page(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.html"

        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient().get_page(str(missing))

        assert captured.value.error_code == "CONFLUENCE_LOCAL_READ_FAILED"

    def test_local_client_reports_unreadable_attachment(self, tmp_path: Path) -> None:
        export = tmp_path / "sample.html"
        export.write_text('<img src="missing.png">', encoding="utf-8")

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert attachments == []

    def test_local_client_other_attachment_kind(self, tmp_path: Path) -> None:
        attachment = tmp_path / "payload.bin"
        attachment.write_bytes(b"\x00\x01")
        export = tmp_path / "sample.html"
        export.write_text('<a href="payload.bin">Payload</a>', encoding="utf-8")

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert attachments[0].kind is AttachmentKind.OTHER

    def test_local_client_skips_remote_attachment_urls(self, tmp_path: Path) -> None:
        export = tmp_path / "sample.html"
        export.write_text('<a href="https://example.com/remote.png">Remote</a>', encoding="utf-8")

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert attachments == []

    def test_local_client_image_attachment_kind(self, tmp_path: Path) -> None:
        attachment = tmp_path / "photo.png"
        attachment.write_bytes(b"png")
        export = tmp_path / "sample.html"
        export.write_text('<img src="photo.png">', encoding="utf-8")

        attachments = LocalFileConfluenceClient().get_attachments(str(export))

        assert attachments[0].kind is AttachmentKind.IMAGE

    def test_local_client_reports_attachment_read_failure(
        self,
        tmp_path: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:
        export = tmp_path / "sample.html"
        export.write_text('<img src="photo.png">', encoding="utf-8")
        attachment = tmp_path / "photo.png"
        attachment.write_bytes(b"png")

        def broken_read_bytes(self: Path) -> bytes:
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "read_bytes", broken_read_bytes)

        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient().get_attachments(str(export))

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_READ_FAILED"

    def test_local_client_reports_attachment_load_failure(self, tmp_path: Path) -> None:
        export = tmp_path / "sample.html"
        export.write_bytes(b"\xff\xfe")

        with pytest.raises(ConfluenceClientError) as captured:
            LocalFileConfluenceClient().get_attachments(str(export))

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_READ_FAILED"
