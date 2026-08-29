"""Dependency container and settings-driven composition."""

from threatmodeler.config.settings import Settings
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.dependency_factory import DependencyFactory
from threatmodeler.ports.document_parser import DocumentParser


class AppContainer:
    """Hold one explicitly constructed application dependency graph."""

    def __init__(
        self,
        settings: Settings,
        confluence_client: ConfluenceClient,
        document_parser: DocumentParser,
        agent_provider: AgentProvider,
        artifact_renderer: ArtifactRenderer,
        artifact_repository: ArtifactRepository,
    ) -> None:
        self._settings = settings
        self._confluence_client = confluence_client
        self._document_parser = document_parser
        self._agent_provider = agent_provider
        self._artifact_renderer = artifact_renderer
        self._artifact_repository = artifact_repository

    @property
    def settings(self) -> Settings:
        """Return this graph's immutable settings.

        Returns:
            Settings instance used to construct the dependency graph.
        """
        return self._settings

    @property
    def confluence_client(self) -> ConfluenceClient:
        """Return the configured Confluence client.

        Returns:
            Client adapter owned by this dependency graph.
        """
        return self._confluence_client

    @property
    def document_parser(self) -> DocumentParser:
        """Return the configured document parser.

        Returns:
            Parser adapter owned by this dependency graph.
        """
        return self._document_parser

    @property
    def agent_provider(self) -> AgentProvider:
        """Return the configured agent provider.

        Returns:
            Provider strategy owned by this dependency graph.
        """
        return self._agent_provider

    @property
    def artifact_renderer(self) -> ArtifactRenderer:
        """Return the configured artifact renderer.

        Returns:
            Renderer strategy owned by this dependency graph.
        """
        return self._artifact_renderer

    @property
    def artifact_repository(self) -> ArtifactRepository:
        """Return the configured artifact repository.

        Returns:
            Repository adapter owned by this dependency graph.
        """
        return self._artifact_repository


class AppContainerFactory:
    """Compose an application dependency graph from settings and adapter factories."""

    def __init__(self, settings: Settings, dependency_factory: DependencyFactory) -> None:
        self._settings = settings
        self._dependency_factory = dependency_factory

    def create(self) -> AppContainer:
        """Create a fresh container without shared clients or provider instances.

        Returns:
            Independently constructed dependency graph for one application scope.
        """
        return AppContainer(
            settings=self._settings,
            confluence_client=self._dependency_factory.create_confluence_client(self._settings),
            document_parser=self._dependency_factory.create_document_parser(self._settings),
            agent_provider=self._dependency_factory.create_agent_provider(self._settings),
            artifact_renderer=self._dependency_factory.create_artifact_renderer(self._settings),
            artifact_repository=self._dependency_factory.create_artifact_repository(self._settings),
        )
