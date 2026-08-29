"""Factory port for ingestion adapters."""

from typing import Protocol

from threatmodeler.config.settings import Settings
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.document_parser import DocumentParser


class IngestionDependencyFactory(Protocol):
    """Define construction of Confluence and document-parser adapters."""

    def create_confluence_client(self, settings: Settings) -> ConfluenceClient:
        """Create the configured Confluence adapter."""
        ...

    def create_document_parser(self, settings: Settings) -> DocumentParser:
        """Create the configured parser adapter."""
        ...
