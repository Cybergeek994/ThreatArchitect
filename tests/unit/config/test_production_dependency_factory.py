"""Tests for production dependency factories."""

from unittest.mock import Mock, patch

import pytest
from threatmodeler.config.production_dependency_factory import ProductionDependencyFactory
from threatmodeler.config.settings import Settings
from threatmodeler.infrastructure.confluence.local_file_client import LocalFileConfluenceClient
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.infrastructure.parsing.confluence_page_parser import ConfluencePageParser
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer


class TestProductionDependencyFactoryPositive:
    """Verify production factories construct the expected adapters."""

    def test_factory_uses_injected_agent_provider_override(self) -> None:
        provider = Mock(spec=AgentProvider)
        factory = ProductionDependencyFactory(
            Settings(),
            agent_provider_factory=lambda: provider,
        )

        assert factory.create_agent_provider(Settings()) is provider

    def test_factory_uses_agent_provider_factory_when_no_override_is_injected(self) -> None:
        provider = Mock(spec=AgentProvider)
        factory = ProductionDependencyFactory(Settings())

        with patch(
            "threatmodeler.config.production_dependency_factory.AgentProviderFactory"
        ) as provider_factory_type:
            provider_factory_type.return_value.create.return_value = provider
            created = factory.create_agent_provider(Settings())

        assert created is provider
        provider_factory_type.assert_called_once()

    def test_confluence_client_uses_settings_attachment_byte_limit(self) -> None:
        settings = Settings(confluence_attachment_max_bytes=1234)
        factory = ProductionDependencyFactory(settings)

        client = factory.create_confluence_client(settings)

        assert isinstance(client, LocalFileConfluenceClient)
        assert client._max_attachment_bytes == 1234

    def test_artifact_renderer_uses_parsed_document_name(self) -> None:
        renderer = ProductionDependencyFactory(Settings()).create_artifact_renderer(Settings())

        assert isinstance(renderer, JsonArtifactRenderer)
        assert renderer._artifact_name == "parsed-document"

    @pytest.mark.parametrize(
        ("method_name", "expected_type"),
        [
            ("create_confluence_client", LocalFileConfluenceClient),
            ("create_document_parser", ConfluencePageParser),
            ("create_artifact_renderer", JsonArtifactRenderer),
            ("create_artifact_repository", LocalArtifactRepository),
        ],
    )

    def test_factory_creates_production_adapters(
        self,
        method_name: str,
        expected_type: type[object],
    ) -> None:
        factory = ProductionDependencyFactory(Settings())
        adapter = getattr(factory, method_name)(Settings())

        assert isinstance(adapter, expected_type)
