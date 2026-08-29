"""Tests for provider-specific error subclasses."""

from threatmodeler.errors import AgentProviderError, ConfluenceClientError
from threatmodeler.errors.providers import DocumentNotFoundError, ProviderError


class TestProviderErrorsPositive:
    """Verify provider error subclasses inherit expected bases."""

    def test_provider_error_is_agent_provider_error(self) -> None:
        error = ProviderError("provider failed", error_code="PROVIDER_FAILED")

        assert isinstance(error, AgentProviderError)
        assert error.message == "provider failed"

    def test_document_not_found_error_is_confluence_client_error(self) -> None:
        error = DocumentNotFoundError("missing document", error_code="DOCUMENT_NOT_FOUND")

        assert isinstance(error, ConfluenceClientError)
        assert error.message == "missing document"
