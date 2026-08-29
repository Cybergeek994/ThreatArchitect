"""Input-aware factory for Confluence client adapters."""

from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from threatmodeler.config.settings import Settings
from threatmodeler.errors.application import ConfigurationError
from threatmodeler.infrastructure.confluence.atlassian_client import (
    AtlassianConfluenceClient,
)
from threatmodeler.infrastructure.confluence.local_file_client import (
    LocalFileConfluenceClient,
)
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.http_transport import HttpTransport


class ConfluenceClientFactory:
    """Select local-export or Atlassian Cloud client adapters by input reference.

    The HTTP transport factory is injected and invoked only for remote inputs.
    """

    def __init__(
        self,
        settings: Settings,
        transport_factory: Callable[[], HttpTransport],
    ) -> None:
        self._settings = settings
        self._transport_factory = transport_factory

    def create(self, input_reference: str) -> ConfluenceClient:
        """Create the adapter appropriate for the supplied input reference.

        Args:
            input_reference: Local export path, Confluence URL, or numeric page identifier.

        Returns:
            Local-file adapter for exports or configured Atlassian Cloud adapter otherwise.

        Raises:
            ConfigurationError: If remote ingestion settings are incomplete.
        """
        parsed = urlparse(input_reference)
        suffix = Path(input_reference).suffix.lower()
        if parsed.scheme not in {"http", "https"} and suffix in {
            ".html",
            ".htm",
            ".md",
            ".markdown",
        }:
            return LocalFileConfluenceClient(
                max_attachment_bytes=self._settings.confluence_attachment_max_bytes
            )

        base_url = self._settings.confluence_base_url
        user_email = self._settings.confluence_user_email
        api_token = self._settings.confluence_api_key
        missing_fields: list[str] = []
        if base_url is None:
            missing_fields.append("confluence_base_url")
        if user_email is None:
            missing_fields.append("confluence_user_email")
        if api_token is None:
            missing_fields.append("confluence_api_key")
        if missing_fields:
            raise ConfigurationError(
                "Atlassian Confluence configuration is incomplete",
                error_code="CONFLUENCE_CONFIG_MISSING",
                retryable=False,
                context={"missing_fields": missing_fields},
            )

        assert base_url is not None
        assert user_email is not None
        assert api_token is not None
        return AtlassianConfluenceClient(
            base_url=base_url,
            user_email=user_email,
            api_token=api_token,
            transport=self._transport_factory(),
            max_attachment_bytes=self._settings.confluence_attachment_max_bytes,
            max_attachments=self._settings.confluence_attachment_max_count,
        )
