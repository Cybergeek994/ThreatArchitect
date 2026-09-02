"""Console-script composition root."""

from collections.abc import Callable
from typing import cast

import typer

from threatmodeler.application.agent_gateway import AgentProviderGateway
from threatmodeler.application.analysis_factory import AnalysisWorkflowFactory
from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.extraction_service import SystemModelExtractionService
from threatmodeler.application.ingestion_service import ConfluenceIngestionService
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.application.threat_modeling_factory import ThreatModelingServiceFactory
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.config.container import AppContainerFactory
from threatmodeler.config.production_dependency_factory import ProductionDependencyFactory
from threatmodeler.config.settings import Settings
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.missing_information_policy import MissingInformationPolicyFactory
from threatmodeler.infrastructure.agents.client_factory import SdkAgentClientFactory
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from threatmodeler.infrastructure.confluence.client_factory import ConfluenceClientFactory
from threatmodeler.infrastructure.http.urllib_transport import UrllibHttpTransport
from threatmodeler.infrastructure.journal.jsonl_construction_journal import (
    JsonlConstructionJournalFactory,
)
from threatmodeler.infrastructure.journal.null_construction_journal_factory import (
    NullConstructionJournalFactory,
)
from threatmodeler.infrastructure.local_artifact_bundle_loader import LocalArtifactBundleLoader
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.infrastructure.local_parsed_document_loader import LocalParsedDocumentLoader
from threatmodeler.infrastructure.local_system_model_loader import LocalSystemModelLoader
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.orchestration.extraction_orchestrator import ExtractionOrchestrator
from threatmodeler.orchestration.prompts import (
    BusinessRuleRepairPromptBuilder,
    CanonicalSystemModelPromptBuilder,
    SchemaRepairPromptBuilder,
    SecurePromptTemplate,
)
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.construction_journal_factory import ConstructionJournalFactory
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer
from threatmodeler.renderers.json_artifact_renderer_factory import (
    JsonArtifactRendererFactory,
)
from threatmodeler.renderers.renderer_factory import RendererFactory
from threatmodeler.shared.constants import LogLevel
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider
from threatmodeler.validation.schema_registry import PydanticOutputSchemaRegistry
from threatmodeler.validation.system_model_validator import (
    CanonicalSystemModelValidator,
    production_system_model_rules,
)


def build_app(
    settings: Settings,
    agent_provider_factory: Callable[[], AgentProvider] | None = None,
) -> typer.Typer:
    """Build a fully injected CLI application from immutable settings.

    Args:
        settings: Environment-backed settings used by production factories.
        agent_provider_factory: Optional provider factory override used by composition tests.

    Returns:
        Configured Typer application with all workflow dependencies wired.

    Examples:
        Build the CLI without executing a command::

            app = build_app(Settings())
    """
    logger = StandardLoggerFactory(settings.log_level).create("threatmodeler.cli")
    error_handler = CliErrorHandler(logger)
    runtime_settings: dict[str, Settings] = {"value": settings}

    def current_settings() -> Settings:
        return runtime_settings["value"]

    def apply_cli_settings(fail_on_missing_information: bool) -> None:
        if not fail_on_missing_information:
            return
        runtime_settings["value"] = settings.model_copy(
            update={"fail_on_missing_information": True}
        )

    dependency_factory = ProductionDependencyFactory(
        settings, agent_provider_factory=agent_provider_factory
    )
    container = AppContainerFactory(settings, dependency_factory).create()
    injected_agent_provider = (
        agent_provider_factory() if agent_provider_factory is not None else None
    )

    def create_agent_provider() -> AgentProvider:
        if injected_agent_provider is not None:
            return injected_agent_provider
        return container.agent_provider

    def create_tool_calling_provider(active: Settings) -> ToolCallingProvider:
        if injected_agent_provider is not None:
            return cast(ToolCallingProvider, injected_agent_provider)
        return AgentProviderFactory(active, SdkAgentClientFactory()).create_tool_calling_provider()

    def create_journal_factory(active: Settings) -> ConstructionJournalFactory:
        if not active.agent_journal_enabled:
            return NullConstructionJournalFactory()
        return JsonlConstructionJournalFactory(
            low_confidence_threshold=active.agent_low_confidence_threshold
        )

    confluence_client_factory = ConfluenceClientFactory(settings, UrllibHttpTransport)
    schema_provider = PydanticSchemaProvider()
    secure_prompt_template = SecurePromptTemplate()
    repair_prompt_builder = SchemaRepairPromptBuilder(secure_prompt_template)
    business_repair_prompt_builder = BusinessRuleRepairPromptBuilder(secure_prompt_template)

    def create_ingestion_service(input_reference: str) -> ConfluenceIngestionService:
        return ConfluenceIngestionService(
            confluence_client=confluence_client_factory.create(input_reference),
            document_parser=container.document_parser,
            artifact_renderer=JsonArtifactRenderer("parsed-document"),
            artifact_repository=LocalArtifactRepository(),
        )

    def create_extraction_service() -> SystemModelExtractionService:
        active = current_settings()
        provider = AgentProviderGateway(
            provider=create_agent_provider(),
            schema_registry=PydanticOutputSchemaRegistry(
                {"CanonicalSystemModel": CanonicalSystemModel}
            ),
            repair_prompt_builder=repair_prompt_builder,
            schema_provider=schema_provider,
            max_attempts=active.agent_provider_max_attempts,
            max_schema_repair_attempts=active.agent_schema_repair_attempts,
        )
        validator = CanonicalSystemModelValidator(production_system_model_rules())
        orchestrator = ExtractionOrchestrator(
            agent_provider=provider,
            schema_validator=validator,
            prompt_builder=CanonicalSystemModelPromptBuilder(
                secure_prompt_template,
                schema_provider,
            ),
            schema_provider=schema_provider,
            business_repair_prompt_builder=business_repair_prompt_builder,
            max_business_repair_attempts=1,
            tool_calling_provider=create_tool_calling_provider(active),
            max_attempts=active.agent_provider_max_attempts,
        )
        return SystemModelExtractionService(
            document_loader=LocalParsedDocumentLoader(),
            orchestrator=orchestrator,
            artifact_renderer=JsonArtifactRenderer("system-model"),
            artifact_repository=LocalArtifactRepository(),
            missing_information_policy=MissingInformationPolicyFactory.create(
                fail_on_missing_information=active.fail_on_missing_information,
            ),
            journal_factory=create_journal_factory(active),
            journal_enabled=True,
        )

    def create_artifact_generation_service() -> ArtifactGenerationService:
        active = current_settings()
        modeling_service = ThreatModelingServiceFactory(
            active,
            schema_provider,
            secure_prompt_template,
            repair_prompt_builder,
            tool_calling_provider=create_tool_calling_provider(active),
            agent_provider=create_agent_provider(),
        ).create()
        return ArtifactGenerationService(
            system_model_loader=LocalSystemModelLoader(),
            threat_modeling_service=modeling_service,
            renderer_factory=JsonArtifactRendererFactory(),
            artifact_repository=LocalArtifactRepository(),
            journal_factory=create_journal_factory(active),
            journal_enabled=True,
        )

    def create_rendering_service() -> RenderingService:
        return RenderingService(
            bundle_loader=LocalArtifactBundleLoader(),
            renderer_factory=RendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

    analysis_factory = AnalysisWorkflowFactory(
        ingestion_factory=create_ingestion_service,
        extraction_factory=create_extraction_service,
        artifact_generation_factory=create_artifact_generation_service,
        rendering_factory=create_rendering_service,
        system_model_loader=LocalSystemModelLoader(),
        artifact_bundle_loader=LocalArtifactBundleLoader(),
    )

    return create_app(
        create_ingestion_service,
        create_extraction_service,
        create_artifact_generation_service,
        create_rendering_service,
        analysis_factory.create,
        error_handler,
        debug=settings.log_level is LogLevel.DEBUG,
        default_output_dir=settings.output_dir,
        apply_cli_settings=apply_cli_settings,
    )


def main() -> None:
    """Build production dependencies and execute the Typer CLI."""
    build_app(Settings())()
