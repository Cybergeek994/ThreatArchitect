"""Production adapter factories for the application dependency container."""

from collections.abc import Callable

from threatmodeler.config.settings import Settings
from threatmodeler.infrastructure.agents.client_factory import SdkAgentClientFactory
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from threatmodeler.infrastructure.confluence.local_file_client import LocalFileConfluenceClient
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.infrastructure.parsing.confluence_page_parser import ConfluencePageParser
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.document_parser import DocumentParser
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer


class ProductionDependencyFactory:
    """Construct production infrastructure adapters for ``AppContainerFactory``."""

    def __init__(
        self,
        settings: Settings,
        agent_client_factory: SdkAgentClientFactory | None = None,
        agent_provider_factory: Callable[[], AgentProvider] | None = None,
    ) -> None:
        self._settings = settings
        self._agent_client_factory = agent_client_factory or SdkAgentClientFactory()
        self._agent_provider_factory = agent_provider_factory

    def create_confluence_client(self, settings: Settings) -> ConfluenceClient:
        """Create the default local-file Confluence adapter for container wiring."""
        return LocalFileConfluenceClient(
            max_attachment_bytes=settings.confluence_attachment_max_bytes,
        )

    def create_document_parser(self, settings: Settings) -> DocumentParser:
        """Create the Confluence HTML and Markdown parser."""
        del settings
        return ConfluencePageParser()

    def create_agent_provider(self, settings: Settings) -> AgentProvider:
        """Create the configured agent provider strategy."""
        if self._agent_provider_factory is not None:
            return self._agent_provider_factory()
        return AgentProviderFactory(settings, self._agent_client_factory).create()

    def create_artifact_renderer(self, settings: Settings) -> ArtifactRenderer:
        """Create the default JSON artifact renderer."""
        del settings
        return JsonArtifactRenderer("parsed-document")

    def create_artifact_repository(self, settings: Settings) -> ArtifactRepository:
        """Create the local filesystem artifact repository."""
        del settings
        return LocalArtifactRepository()
