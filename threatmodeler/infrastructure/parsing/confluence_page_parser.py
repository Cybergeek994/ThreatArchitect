"""Confluence HTML and Markdown document parser."""

from threatmodeler.contracts.integration import ParsedDocument, ParsedInputRequest
from threatmodeler.errors.application import DocumentParsingError
from threatmodeler.infrastructure.parsing.confluence_document_assembler import (
    ConfluenceDocumentAssembler,
)
from threatmodeler.infrastructure.parsing.confluence_html_extractor import ConfluenceHtmlExtractor
from threatmodeler.infrastructure.parsing.confluence_markdown_extractor import (
    ConfluenceMarkdownExtractor,
)
from threatmodeler.infrastructure.parsing.confluence_text_utils import join_text_parts


class ConfluencePageParser:
    """Adapt Confluence HTML and Markdown to the parsed-document contract."""

    def __init__(
        self,
        *,
        markdown_extractor: ConfluenceMarkdownExtractor | None = None,
        document_assembler: ConfluenceDocumentAssembler | None = None,
    ) -> None:
        self._markdown_extractor = markdown_extractor or ConfluenceMarkdownExtractor()
        self._document_assembler = document_assembler or ConfluenceDocumentAssembler()

    def parse(self, input_document: ParsedInputRequest) -> ParsedDocument:
        """Parse a supported source document and normalize parser failures.

        Args:
            input_document: Source content, media type, identifier, and provenance.

        Returns:
            Validated document containing headings, paragraphs, tables, images, and text.

        Raises:
            DocumentParsingError: If the media type is unsupported or parsing fails.
        """
        try:
            if input_document.media_type in {"text/html", "application/xhtml+xml"}:
                return self._parse_html(input_document)
            if input_document.media_type in {"text/markdown", "text/x-markdown"}:
                return self._parse_markdown(input_document)
            raise DocumentParsingError(
                "Unsupported Confluence document media type",
                error_code="DOCUMENT_MEDIA_TYPE_UNSUPPORTED",
                retryable=False,
                context={"media_type": input_document.media_type},
            )
        except DocumentParsingError:
            raise
        except Exception as error:
            raise DocumentParsingError(
                "Unable to parse the Confluence document",
                error_code="DOCUMENT_PARSE_FAILED",
                retryable=False,
                context={
                    "document_id": input_document.document_id,
                    "media_type": input_document.media_type,
                },
            ) from error

    def _parse_html(self, request: ParsedInputRequest) -> ParsedDocument:
        parser = ConfluenceHtmlExtractor()
        parser.feed(request.content)
        parser.close()
        self._document_assembler.append_embedded_diagram_labels(request.content, parser.paragraphs)
        raw_text = join_text_parts(parser.raw_parts)
        title = join_text_parts(parser.title_parts)
        if not title and parser.headings:
            title = parser.headings[0].text
        return self._document_assembler.build(
            request=request,
            title=title or request.document_id,
            headings=parser.headings,
            paragraphs=parser.paragraphs,
            tables=parser.tables,
            image_references=parser.image_references,
            raw_text=raw_text,
        )

    def _parse_markdown(self, request: ParsedInputRequest) -> ParsedDocument:
        extracted = self._markdown_extractor.extract(
            request.content,
            fallback_title=request.document_id,
        )
        return self._document_assembler.build(
            request=request,
            title=extracted.title,
            headings=list(extracted.headings),
            paragraphs=list(extracted.paragraphs),
            tables=list(extracted.tables),
            image_references=list(extracted.image_references),
            raw_text=extracted.raw_text,
        )
