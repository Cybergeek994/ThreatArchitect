"""Confluence ingestion application service."""

from pathlib import Path

from threatmodeler.contracts.integration import ParsedInputRequest, SavedArtifact
from threatmodeler.contracts.source import SourceReference
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.document_parser import DocumentParser


class ConfluenceIngestionService:
    """Ingest and persist a normalized Confluence document through injected ports.

    Acquisition may use a local export or remote adapter; parsing and persistence remain
    independent of that source choice.
    """

    def __init__(
        self,
        confluence_client: ConfluenceClient,
        document_parser: DocumentParser,
        artifact_renderer: ArtifactRenderer,
        artifact_repository: ArtifactRepository,
    ) -> None:
        self._confluence_client = confluence_client
        self._document_parser = document_parser
        self._artifact_renderer = artifact_renderer
        self._artifact_repository = artifact_repository

    def ingest(self, input_reference: str, output_dir: Path) -> SavedArtifact:
        """Ingest one Confluence source and persist its parsed representation.

        Args:
            input_reference: Local export path, Confluence page URL, or page identifier.
            output_dir: Directory in which the parsed-document artifact is persisted.

        Returns:
            Metadata for the saved parsed-document artifact.

        Examples:
            Ingest a local Confluence HTML export::

                saved = service.ingest("architecture.html", Path("out"))
        """
        page = self._confluence_client.get_page(input_reference)
        attachments = self._confluence_client.get_attachments(input_reference)
        source_reference = SourceReference(
            source_type=page.source_type,
            source_id=page.page_id,
            location=str(page.url),
            excerpt=page.content[:500].strip() or page.title,
        )
        parsed_document = self._document_parser.parse(
            ParsedInputRequest(
                document_id=page.page_id,
                content=page.content,
                media_type=page.media_type,
                source_reference=source_reference,
                attachments=attachments,
            )
        )
        rendered = self._artifact_renderer.render(parsed_document)
        return self._artifact_repository.save(rendered, output_dir)
