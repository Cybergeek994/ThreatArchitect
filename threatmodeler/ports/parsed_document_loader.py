"""Parsed-document loading port."""

from pathlib import Path
from typing import Protocol

from threatmodeler.contracts.integration import ParsedDocument


class ParsedDocumentLoader(Protocol):
    """Define loading of parsed documents from delivery-specific sources."""

    def load(self, path: Path) -> ParsedDocument:
        """Load and return one validated parsed document.

        Args:
            path: Delivery-specific location of serialized parsed-document data.

        Returns:
            Validated parsed-document contract.

        Raises:
            DocumentParsingError: If the source cannot produce a valid document.
        """
        ...
