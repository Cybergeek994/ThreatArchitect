"""Architecture document parser port."""

from typing import Protocol

from threatmodeler.contracts.integration import ParsedDocument, ParsedInputRequest


class DocumentParser(Protocol):
    """Define parsing of source documents into a provider-neutral contract."""

    def parse(self, input_document: ParsedInputRequest) -> ParsedDocument:
        """Parse and return one normalized source document.

        Args:
            input_document: Validated source content and provenance.

        Returns:
            Provider-neutral parsed-document contract.

        Raises:
            DocumentParsingError: If the source format is unsupported or malformed.
        """
        ...
