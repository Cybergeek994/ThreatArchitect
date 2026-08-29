"""Local parsed-document JSON loader."""

from pathlib import Path

from pydantic import ValidationError

from threatmodeler.contracts.integration import ParsedDocument
from threatmodeler.errors.application import DocumentParsingError


class LocalParsedDocumentLoader:
    """Load and validate parsed-document contracts from local JSON storage."""

    def load(self, path: Path) -> ParsedDocument:
        """Read a parsed document and normalize I/O or schema failures.

        Args:
            path: Path to the parsed-document JSON artifact.

        Returns:
            Validated parsed-document contract.

        Raises:
            DocumentParsingError: If the file cannot be read or violates the schema.
        """
        try:
            return ParsedDocument.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValidationError) as error:
            context: dict[str, object] = {"path": str(path)}
            if isinstance(error, ValidationError):
                context["validation_errors"] = error.errors(
                    include_url=False,
                    include_input=False,
                )
            raise DocumentParsingError(
                "Unable to load parsed-document JSON",
                error_code="PARSED_DOCUMENT_LOAD_FAILED",
                retryable=False,
                context=context,
            ) from error
