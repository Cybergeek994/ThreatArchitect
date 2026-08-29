"""Tests for local parsed-document JSON loading."""

from pathlib import Path

import pytest
from threatmodeler.contracts import SourceReference, SourceType
from threatmodeler.contracts.integration import ParsedDocument, ParsedParagraph
from threatmodeler.errors import DocumentParsingError
from threatmodeler.infrastructure.local_parsed_document_loader import LocalParsedDocumentLoader


class TestLocalParsedDocumentLoaderPositive:
    """Verify supported inputs and successful behavior."""

    def test_load_returns_validated_parsed_document(self, tmp_path: Path) -> None:
        source_reference = SourceReference(
            source_type=SourceType.CONFLUENCE_PAGE,
            source_id="123",
            location="file:///page",
            excerpt="Page",
        )
        document = ParsedDocument(
            document_id="payments-architecture",
            title="Payments",
            headings=[],
            paragraphs=[ParsedParagraph(text="Overview")],
            tables=[],
            image_references=[],
            attachments=[],
            raw_text="Overview",
            source_reference=source_reference,
            media_type="text/html",
        )
        path = tmp_path / "parsed-document.json"
        path.write_text(document.model_dump_json(), encoding="utf-8")

        loaded = LocalParsedDocumentLoader().load(path)

        assert loaded.title == "Payments"


class TestLocalParsedDocumentLoaderErrors:
    """Verify dependency and application failures remain controlled."""

    def test_missing_file_raises_document_parsing_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.json"

        with pytest.raises(DocumentParsingError) as captured:
            LocalParsedDocumentLoader().load(missing)

        assert captured.value.error_code == "PARSED_DOCUMENT_LOAD_FAILED"
        context = captured.value.context
        assert context is not None
        assert context["path"] == str(missing)

    def test_invalid_json_raises_document_parsing_error(self, tmp_path: Path) -> None:
        path = tmp_path / "invalid.json"
        path.write_text('{"title": ""}', encoding="utf-8")

        with pytest.raises(DocumentParsingError) as captured:
            LocalParsedDocumentLoader().load(path)

        assert captured.value.error_code == "PARSED_DOCUMENT_LOAD_FAILED"
        context = captured.value.context
        assert context is not None
        assert "validation_errors" in context
