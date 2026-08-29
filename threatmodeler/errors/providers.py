"""External provider exceptions."""

from threatmodeler.errors.application import AgentProviderError, ConfluenceClientError


class ProviderError(AgentProviderError):
    """Raised when an external provider operation fails."""


class DocumentNotFoundError(ConfluenceClientError):
    """Raised when an architecture document cannot be found."""
