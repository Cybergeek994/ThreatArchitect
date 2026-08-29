"""Assemble parsed Confluence fragments into validated documents."""

from threatmodeler.contracts.integration import (
    AttachmentKind,
    DiagramTopologySnapshot,
    ImageReference,
    ParsedDocument,
    ParsedInputRequest,
    ParsedParagraph,
    ParsedHeading,
    ParsedTable,
)
from threatmodeler.errors.application import DocumentParsingError
from threatmodeler.infrastructure.parsing.diagram_content import (
    extract_diagram_labels,
    extract_diagram_topology,
)


class ConfluenceDocumentAssembler:
    """Merge extracted content, attachments, and diagram topology."""

    def build(
        self,
        request: ParsedInputRequest,
        title: str,
        headings: list[ParsedHeading],
        paragraphs: list[ParsedParagraph],
        tables: list[ParsedTable],
        image_references: list[ImageReference],
        raw_text: str,
    ) -> ParsedDocument:
        """Validate and assemble a parsed document from extracted fragments."""
        if not raw_text:
            raw_text = " ".join(paragraph.text for paragraph in paragraphs)
        if not raw_text:
            raise DocumentParsingError(
                "The Confluence document does not contain extractable text",
                error_code="DOCUMENT_CONTENT_EMPTY",
                retryable=False,
                context={"document_id": request.document_id},
            )
        references = self._merge_attachment_references(request, image_references)
        diagram_paragraphs = self._diagram_paragraphs_from_attachments(request)
        merged_paragraphs = [*paragraphs, *diagram_paragraphs]
        merged_raw_text = raw_text
        if diagram_paragraphs:
            merged_raw_text = " ".join(
                part
                for part in [raw_text, *(paragraph.text for paragraph in diagram_paragraphs)]
                if part
            )
        return ParsedDocument(
            document_id=request.document_id,
            title=title,
            headings=headings,
            paragraphs=merged_paragraphs,
            tables=tables,
            image_references=references,
            attachments=request.attachments,
            diagram_topology=self._diagram_topologies(request),
            raw_text=merged_raw_text,
            source_reference=request.source_reference,
            media_type=request.media_type,
        )

    def append_embedded_diagram_labels(
        self,
        content: str,
        paragraphs: list[ParsedParagraph],
    ) -> None:
        """Add diagram label paragraphs discovered in embedded markup."""
        existing = {paragraph.text for paragraph in paragraphs}
        for label in extract_diagram_labels(content):
            text = f"Diagram: {label}"
            if text not in existing:
                paragraphs.append(ParsedParagraph(text=text))
                existing.add(text)

    def _diagram_paragraphs_from_attachments(
        self,
        request: ParsedInputRequest,
    ) -> list[ParsedParagraph]:
        paragraphs: list[ParsedParagraph] = []
        seen: set[str] = set()
        for attachment in request.attachments:
            if attachment.kind is not AttachmentKind.DIAGRAM:
                continue
            content = attachment.decoded_content().decode("utf-8", errors="ignore")
            for label in extract_diagram_labels(content):
                text = f"Diagram ({attachment.filename}): {label}"
                if text in seen:
                    continue
                seen.add(text)
                paragraphs.append(ParsedParagraph(text=text))
        return paragraphs

    def _diagram_topologies(self, request: ParsedInputRequest) -> list[DiagramTopologySnapshot]:
        topologies: list[DiagramTopologySnapshot] = []
        embedded = extract_diagram_topology(request.content, "embedded")
        if embedded.nodes or embedded.edges:
            topologies.append(embedded)
        for attachment in request.attachments:
            if attachment.kind is not AttachmentKind.DIAGRAM:
                continue
            content = attachment.decoded_content().decode("utf-8", errors="ignore")
            snapshot = extract_diagram_topology(content, attachment.filename)
            if snapshot.nodes or snapshot.edges:
                topologies.append(snapshot)
        return topologies

    def _merge_attachment_references(
        self,
        request: ParsedInputRequest,
        image_references: list[ImageReference],
    ) -> list[ImageReference]:
        references = list(image_references)
        known_sources = {reference.source for reference in references}
        for attachment in request.attachments:
            if attachment.kind not in {AttachmentKind.DIAGRAM, AttachmentKind.IMAGE}:
                continue
            if attachment.filename in known_sources:
                continue
            references.append(
                ImageReference(
                    source=attachment.filename,
                    title=attachment.filename,
                    is_diagram=attachment.kind is AttachmentKind.DIAGRAM,
                )
            )
            known_sources.add(attachment.filename)
        return references
