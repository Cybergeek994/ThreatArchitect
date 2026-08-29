"""Specific expected application failures."""

from threatmodeler.errors.base import ThreatModelerError


class ConfigurationError(ThreatModelerError):
    """Raised when application configuration is invalid or incomplete."""


class ConfluenceClientError(ThreatModelerError):
    """Raised when a Confluence operation fails."""


class DocumentParsingError(ThreatModelerError):
    """Raised when an input document cannot be parsed."""


class AgentProviderError(ThreatModelerError):
    """Raised when an agent provider request fails."""


class AgentSchemaValidationError(ThreatModelerError):
    """Raised when agent output violates the required schema."""


class ArtifactRenderingError(ThreatModelerError):
    """Raised when an artifact cannot be rendered."""


class ArtifactStorageError(ThreatModelerError):
    """Raised when a rendered artifact cannot be persisted."""


class ArtifactValidationError(ThreatModelerError):
    """Raised when a generated artifact violates its Pydantic schema."""


class MissingInformationError(ThreatModelerError):
    """Raised when required architecture information is unavailable."""
