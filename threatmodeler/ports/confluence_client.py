"""Confluence client port."""

from typing import Protocol

from threatmodeler.contracts.integration import AttachmentContent, ConfluencePage


class ConfluenceClient(Protocol):
    """Define retrieval of architecture documents from Confluence sources."""

    def get_page(self, page_id_or_url: str) -> ConfluencePage:
        """Retrieve and return a page by identifier, URL, or local export path.

        Args:
            page_id_or_url: Adapter-supported page reference.

        Returns:
            Validated Confluence page contract.

        Raises:
            ConfluenceClientError: If the source cannot provide a valid page.
        """
        ...

    def get_attachments(self, page_id_or_url: str) -> list[AttachmentContent]:
        """Retrieve analyzable content attached to a page or local export.

        Args:
            page_id_or_url: Adapter-supported page reference.

        Returns:
            Validated attachments with content and source provenance.

        Raises:
            ConfluenceClientError: If referenced attachments cannot be retrieved safely.
        """
        ...
