"""Tests for settings-driven dependency injection."""

from pathlib import Path
from unittest.mock import Mock, call

import pytest
from pydantic import AnyUrl
from threatmodeler.config.container import AppContainerFactory
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import (
    AgentRequest,
    AgentResponse,
    ConfluencePage,
    ParsedDocument,
    ParsedInputRequest,
    RenderedArtifact,
    SavedArtifact,
    SourceReference,
    SourceType,
)
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.confluence_client import ConfluenceClient
from threatmodeler.ports.dependency_factory import DependencyFactory
from threatmodeler.ports.document_parser import DocumentParser
from threatmodeler.shared.constants import LogLevel


@pytest.fixture
def source_reference() -> SourceReference:
    """Create source provenance for fake adapters."""
    return SourceReference(
        source_type=SourceType.CONFLUENCE_PAGE,
        source_id="42",
        location="Page body",
        excerpt="Architecture overview",
    )


@pytest.fixture
def dependency_factory() -> Mock:
    """Return a standard mock factory with mocks for every production port."""
    factory = Mock(spec=DependencyFactory)
    factory.create_confluence_client.return_value = Mock(spec=ConfluenceClient)
    factory.create_document_parser.return_value = Mock(spec=DocumentParser)
    factory.create_agent_provider.return_value = Mock(spec=AgentProvider)
    factory.create_artifact_renderer.return_value = Mock(spec=ArtifactRenderer)
    factory.create_artifact_repository.return_value = Mock(spec=ArtifactRepository)
    return factory


class TestDependencyContainerPositive:
    """Verify supported inputs and successful behavior."""

    def test_settings_load_values_and_secrets_from_environment(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("THREATMODELER_AGENT_PROVIDER_NAME", "anthropic")
        monkeypatch.setenv("THREATMODELER_OUTPUT_DIR", "build/threat-models")
        monkeypatch.setenv("THREATMODELER_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv(
            "THREATMODELER_CONFLUENCE_BASE_URL",
            "https://confluence.example.test",
        )
        monkeypatch.setenv("THREATMODELER_CONFLUENCE_API_KEY", "confluence-secret")
        monkeypatch.setenv("THREATMODELER_CONFLUENCE_USER_EMAIL", "architect@example.test")
        monkeypatch.setenv("THREATMODELER_AGENT_API_KEY", "agent-secret")

        settings = Settings()

        assert settings.agent_provider_name == "anthropic"
        assert settings.output_dir == Path("build/threat-models")
        assert settings.log_level is LogLevel.DEBUG
        assert str(settings.confluence_base_url) == "https://confluence.example.test/"
        assert settings.confluence_api_key is not None
        assert settings.confluence_api_key.get_secret_value() == "confluence-secret"
        assert settings.confluence_user_email == "architect@example.test"
        assert settings.agent_api_key is not None
        assert settings.agent_api_key.get_secret_value() == "agent-secret"

    def test_container_factory_injects_mocked_port_implementations(
        self,
        dependency_factory: Mock,
    ) -> None:
        settings = Settings()

        container = AppContainerFactory(settings, dependency_factory).create()

        assert container.settings is settings
        assert (
            container.confluence_client is dependency_factory.create_confluence_client.return_value
        )
        assert container.document_parser is dependency_factory.create_document_parser.return_value
        assert container.agent_provider is dependency_factory.create_agent_provider.return_value
        assert (
            container.artifact_renderer is dependency_factory.create_artifact_renderer.return_value
        )
        assert (
            container.artifact_repository
            is dependency_factory.create_artifact_repository.return_value
        )
        assert dependency_factory.mock_calls == [
            call.create_confluence_client(settings),
            call.create_document_parser(settings),
            call.create_agent_provider(settings),
            call.create_artifact_renderer(settings),
            call.create_artifact_repository(settings),
        ]

    def test_injected_mocks_support_a_port_only_pipeline(
        self,
        tmp_path: Path,
        dependency_factory: Mock,
        source_reference: SourceReference,
    ) -> None:
        page = ConfluencePage(
            page_id="42",
            title="Architecture Review",
            url=AnyUrl("https://confluence.example.test/pages/42"),
            content="Architecture overview",
            version=1,
        )
        parsed = ParsedDocument(
            document_id="42",
            title="Architecture Review",
            raw_text=page.content,
            source_reference=source_reference,
            media_type="text/html",
        )
        response = AgentResponse(
            output_payload={"content": parsed.raw_text},
            confidence=1.0,
            provider_name="mock",
            model_name="mock-model",
        )
        rendered = RenderedArtifact(
            name="artifact",
            content=response.model_dump_json(),
            media_type="application/json",
            file_extension=".json",
        )
        saved = SavedArtifact(
            path=tmp_path / "artifact.json",
            size_bytes=len(rendered.content.encode()),
            sha256="0" * 64,
        )
        dependency_factory.create_confluence_client.return_value.get_page.return_value = page
        dependency_factory.create_document_parser.return_value.parse.return_value = parsed
        dependency_factory.create_agent_provider.return_value.complete.return_value = response
        dependency_factory.create_artifact_renderer.return_value.render.return_value = rendered
        dependency_factory.create_artifact_repository.return_value.save.return_value = saved

        container = AppContainerFactory(Settings(output_dir=tmp_path), dependency_factory).create()
        page = container.confluence_client.get_page("42")
        parse_request = ParsedInputRequest(
            document_id=page.page_id,
            content=page.content,
            media_type="text/html",
            source_reference=source_reference,
        )
        parsed_result = container.document_parser.parse(parse_request)
        response_result = container.agent_provider.complete(
            AgentRequest(
                task_name="echo",
                instructions="Echo the parsed content.",
                input_payload={"content": parsed_result.raw_text},
                expected_schema_name="EchoOutput",
            )
        )
        rendered_result = container.artifact_renderer.render(response_result)

        saved_result = container.artifact_repository.save(
            rendered_result,
            container.settings.output_dir,
        )

        assert saved_result == saved
        dependency_factory.create_confluence_client.return_value.get_page.assert_called_once_with(
            "42"
        )
        dependency_factory.create_document_parser.return_value.parse.assert_called_once_with(
            parse_request
        )
