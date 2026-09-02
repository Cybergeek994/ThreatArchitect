"""Application factory for constructing the threat-modeling application facade."""

from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.config.settings import Settings
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.control_catalogs.control_mapping_candidate_service import (
    ControlMappingCandidateService,
)
from threatmodeler.domain.control_catalogs.llm_asvs_semantic_ranker import LlmAsvsSemanticRanker
from threatmodeler.domain.downstream_artifact_generation import (
    AgentDownstreamArtifactGenerationStrategy,
    DownstreamArtifactGenerationStrategy,
)
from threatmodeler.domain.inventory_generation import InventoryGenerationService
from threatmodeler.domain.missing_information_policy import MissingInformationPolicyFactory
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.infrastructure.control_catalogs.asvs_control_registry_factory import (
    AsvsControlRegistryFactory,
)
from threatmodeler.orchestration.prompts import (
    SchemaRepairPromptBuilder,
    SecurePromptTemplate,
    StrideThreatPromptBuilder,
)
from threatmodeler.orchestration.prompts.registry import ArtifactPromptBuilderFactory
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator


class ThreatModelingServiceFactory:
    """Wire the threat-modeling facade from injected factories and settings."""

    def __init__(
        self,
        settings: Settings,
        schema_provider: SchemaProvider,
        secure_prompt_template: SecurePromptTemplate,
        repair_prompt_builder: SchemaRepairPromptBuilder,
        tool_calling_provider: ToolCallingProvider,
        agent_provider: AgentProvider,
        artifact_validator: ArtifactValidator | None = None,
        candidate_service: ControlMappingCandidateService | None = None,
    ) -> None:
        self._settings = settings
        self._schema_provider = schema_provider
        self._secure_prompt_template = secure_prompt_template
        self._repair_prompt_builder = repair_prompt_builder
        self._tool_calling_provider = tool_calling_provider
        self._agent_provider = agent_provider
        self._artifact_validator = artifact_validator
        self._candidate_service = candidate_service

    def create(self) -> ThreatModelingService:
        """Create a fully composed threat-modeling facade.

        Returns:
            Threat-modeling service with agent-backed downstream generation.
        """
        metadata = ArtifactMetadataService()
        stride_service = self._create_stride_service(metadata)
        report_service = ReportGenerationService(metadata)
        completeness_service = ThreatModelCompletenessService(metadata)
        return ThreatModelingService(
            inventory_service=InventoryGenerationService(metadata),
            stride_service=stride_service,
            downstream_strategy=self._create_downstream_strategy(),
            report_service=report_service,
            completeness_service=completeness_service,
            artifact_validator=self._artifact_validator or PydanticArtifactValidator(),
            metadata=metadata,
            missing_information_policy=MissingInformationPolicyFactory.create(
                fail_on_missing_information=self._settings.fail_on_missing_information,
            ),
        )

    def _create_stride_service(
        self,
        metadata: ArtifactMetadataService,
    ) -> StrideThreatGenerationService:
        return StrideThreatGenerationService(
            strategy=AgentStrideThreatGenerationStrategy(
                self._tool_calling_provider,
                StrideThreatPromptBuilder(self._secure_prompt_template, self._schema_provider),
                self._schema_provider,
                max_attempts=self._settings.agent_provider_max_attempts,
            ),
            metadata=metadata,
        )

    def _create_downstream_strategy(self) -> DownstreamArtifactGenerationStrategy:
        registry_factory = AsvsControlRegistryFactory.from_settings(self._settings)
        registry = registry_factory.create()
        candidate_service = self._candidate_service or ControlMappingCandidateService(
            registry,
            LlmAsvsSemanticRanker(
                self._agent_provider,
                registry,
                max_attempts=self._settings.agent_provider_max_attempts,
            ),
        )
        return AgentDownstreamArtifactGenerationStrategy(
            tool_calling_provider=self._tool_calling_provider,
            prompt_registry=ArtifactPromptBuilderFactory(
                self._secure_prompt_template,
                self._schema_provider,
            ).create(),
            schema_provider=self._schema_provider,
            candidate_service=candidate_service,
            control_registry=registry,
            max_attempts=self._settings.agent_provider_max_attempts,
        )
