"""Production registry and factory for schema-bound artifact prompt builders."""

from threatmodeler.orchestration.prompts.artifact_builders import (
    ArchitectureGraphPromptBuilder,
    AbuseCasePromptBuilder,
    AttackTreePromptBuilder,
    ControlMappingPromptBuilder,
    DfdPromptBuilder,
    ExecutiveSummaryPromptBuilder,
    MissingInformationPromptBuilder,
    MitigationPlanPromptBuilder,
    RiskRegisterPromptBuilder,
    SecurityRequirementsPromptBuilder,
    TechnicalReportPromptBuilder,
)
from threatmodeler.orchestration.prompts.secure_template import SecurePromptTemplate
from threatmodeler.ports.artifact_prompt_builder_registry import ArtifactPromptBuilderRegistry
from threatmodeler.ports.schema_provider import SchemaProvider


class ArtifactPromptBuilderFactory:
    """Create schema-bound prompt builder registries for agent artifact generation."""

    def __init__(
        self,
        secure_template: SecurePromptTemplate,
        schema_provider: SchemaProvider,
    ) -> None:
        self._secure_template = secure_template
        self._schema_provider = schema_provider

    def create(self) -> ArtifactPromptBuilderRegistry:
        """Build the production prompt-builder registry.

        Returns:
            Immutable registry containing one builder per downstream artifact task.
        """
        return ArtifactPromptBuilderRegistry(
            missing_information=MissingInformationPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            dfd=DfdPromptBuilder(self._secure_template, self._schema_provider),
            architecture_graph=ArchitectureGraphPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            attack_tree=AttackTreePromptBuilder(self._secure_template, self._schema_provider),
            abuse_cases=AbuseCasePromptBuilder(self._secure_template, self._schema_provider),
            risk_register=RiskRegisterPromptBuilder(self._secure_template, self._schema_provider),
            mitigation_plan=MitigationPlanPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            security_requirements=SecurityRequirementsPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            control_mapping=ControlMappingPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            executive_summary=ExecutiveSummaryPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
            technical_report=TechnicalReportPromptBuilder(
                self._secure_template,
                self._schema_provider,
            ),
        )
