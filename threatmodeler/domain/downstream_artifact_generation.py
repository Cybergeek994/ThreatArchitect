"""Strategy-based generation for downstream threat-model artifacts."""

from typing import Protocol

from pydantic import BaseModel, JsonValue

from threatmodeler.contracts.artifacts import (
    AbuseMisuseCases,
    AttackTree,
    ControlMapping,
    DataFlowDiagramModel,
    ExecutiveSummary,
    MissingInformationReport,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideThreatRegister,
    TechnicalThreatModelReport,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.agent_schema_bound_generator import AgentSchemaBoundArtifactGenerator
from threatmodeler.domain.attack_tree_generation import AttackTreeGenerationService
from threatmodeler.domain.control_catalogs.control_mapping_candidate_service import (
    ControlMappingCandidateService,
)
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.domain.control_mapping import ControlMappingService
from threatmodeler.domain.dfd_generation import DfdGenerationService
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import StrideThreatGenerationService
from threatmodeler.ports.artifact_prompt_builder_registry import ArtifactPromptBuilderRegistry
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.shared.constants import ControlFrameworkName
from threatmodeler.ports.artifact_construction_session_factory import ItemValidator
from threatmodeler.validation.control_mapping_candidate_validator import (
    build_candidate_membership_validator,
)
from threatmodeler.validation.control_mapping_validator import ControlMappingCatalogRule


class DownstreamArtifactGenerationStrategy(Protocol):
    """Define interchangeable strategies for downstream artifact generation."""

    def generate_dfd(self, model: CanonicalSystemModel) -> DataFlowDiagramModel:
        """Generate a machine-readable data-flow diagram."""
        ...

    def generate_attack_tree(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AttackTree:
        """Generate an attack tree from validated threats."""
        ...

    def generate_abuse_cases(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AbuseMisuseCases:
        """Generate abuse and misuse cases from validated threats."""
        ...

    def generate_risk_register(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> RiskRegister:
        """Generate a risk register from validated threats."""
        ...

    def generate_mitigation_plan(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        threat_register: StrideThreatRegister,
    ) -> MitigationPlan:
        """Generate a mitigation plan from validated risks and threats."""
        ...

    def generate_security_requirements(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> SecurityRequirements:
        """Generate security requirements from validated threats and risks."""
        ...

    def generate_missing_information(self, model: CanonicalSystemModel) -> MissingInformationReport:
        """Generate a missing-information report."""
        ...

    def generate_control_mapping(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
        security_requirements: SecurityRequirements,
        threat_register: StrideThreatRegister,
    ) -> ControlMapping:
        """Generate control mappings from validated downstream artifacts."""
        ...

    def generate_executive_summary(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
    ) -> ExecutiveSummary:
        """Generate an executive summary from validated artifacts."""
        ...

    def generate_technical_report(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> TechnicalThreatModelReport:
        """Generate a technical report from validated artifacts."""
        ...


class DeterministicDownstreamArtifactGenerationStrategy:
    """Generate downstream artifacts through deterministic domain services."""

    def __init__(
        self,
        dfd_service: DfdGenerationService,
        attack_tree_service: AttackTreeGenerationService,
        stride_service: StrideThreatGenerationService,
        risk_service: RiskScoringService,
        mitigation_service: MitigationGenerationService,
        control_mapping_service: ControlMappingService,
        report_service: ReportGenerationService,
    ) -> None:
        self._dfd_service = dfd_service
        self._attack_tree_service = attack_tree_service
        self._stride_service = stride_service
        self._risk_service = risk_service
        self._mitigation_service = mitigation_service
        self._control_mapping_service = control_mapping_service
        self._report_service = report_service

    def generate_dfd(self, model: CanonicalSystemModel) -> DataFlowDiagramModel:
        """Generate a machine-readable data-flow diagram."""
        return self._dfd_service.generate(model)

    def generate_attack_tree(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AttackTree:
        """Generate an attack tree from validated threats."""
        return self._attack_tree_service.generate(model, threat_register)

    def generate_abuse_cases(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AbuseMisuseCases:
        """Generate abuse and misuse cases from validated threats."""
        return self._stride_service.generate_abuse_cases(model, threat_register)

    def generate_risk_register(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> RiskRegister:
        """Generate a risk register from validated threats."""
        return self._risk_service.generate(model, threat_register)

    def generate_mitigation_plan(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        threat_register: StrideThreatRegister,
    ) -> MitigationPlan:
        """Generate a mitigation plan from validated risks and threats."""
        return self._mitigation_service.generate_plan(model, risk_register)

    def generate_security_requirements(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> SecurityRequirements:
        """Generate security requirements from validated threats and risks."""
        return self._mitigation_service.generate_requirements(
            model,
            threat_register,
            risk_register,
        )

    def generate_missing_information(self, model: CanonicalSystemModel) -> MissingInformationReport:
        """Generate a missing-information report."""
        return self._report_service.generate_missing_information(model)

    def generate_control_mapping(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
        security_requirements: SecurityRequirements,
        threat_register: StrideThreatRegister,
    ) -> ControlMapping:
        """Generate control mappings from validated downstream artifacts."""
        return self._control_mapping_service.generate(
            model,
            risk_register,
            mitigation_plan,
            security_requirements,
        )

    def generate_executive_summary(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
    ) -> ExecutiveSummary:
        """Generate an executive summary from validated artifacts."""
        return self._report_service.generate_executive_summary(
            model,
            threat_register,
            risk_register,
            mitigation_plan,
        )

    def generate_technical_report(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> TechnicalThreatModelReport:
        """Generate a technical report from validated artifacts."""
        return self._report_service.generate_technical_report(
            model,
            threat_register,
            risk_register,
        )


class AgentDownstreamArtifactGenerationStrategy:
    """Generate downstream artifacts through schema-bound agent prompts."""

    def __init__(
        self,
        tool_calling_provider: ToolCallingProvider,
        prompt_registry: ArtifactPromptBuilderRegistry,
        schema_provider: SchemaProvider,
        candidate_service: ControlMappingCandidateService,
        control_registry: AsvsControlRegistry,
        max_attempts: int = 1,
    ) -> None:
        self._generator = AgentSchemaBoundArtifactGenerator(
            tool_calling_provider,
            schema_provider,
            max_attempts=max_attempts,
        )
        self._prompt_registry = prompt_registry
        self._candidate_service = candidate_service
        self._control_mapping_rule = ControlMappingCatalogRule(control_registry)

    def bind_journal(self, journal: ConstructionJournal | None) -> None:
        """Bind the per-run construction journal onto the shared generator."""
        self._generator.bind_journal(journal)

    def generate_dfd(self, model: CanonicalSystemModel) -> DataFlowDiagramModel:
        """Generate a machine-readable data-flow diagram through the agent provider."""
        return self._generate(
            task_name="generate_dfd",
            output_model=DataFlowDiagramModel,
            prompt_builder=self._prompt_registry.dfd,
            input_payload={"system_model": self._generator.serialize(model)},
        )

    def generate_attack_tree(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AttackTree:
        """Generate an attack tree from validated threats through the agent provider."""
        return self._generate(
            task_name="generate_attack_tree",
            output_model=AttackTree,
            prompt_builder=self._prompt_registry.attack_tree,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
            },
        )

    def generate_abuse_cases(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AbuseMisuseCases:
        """Generate abuse and misuse cases from validated threats through the agent provider."""
        return self._generate(
            task_name="generate_abuse_cases",
            output_model=AbuseMisuseCases,
            prompt_builder=self._prompt_registry.abuse_cases,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
            },
        )

    def generate_risk_register(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> RiskRegister:
        """Generate a risk register from validated threats through the agent provider."""
        return self._generate(
            task_name="generate_risk_register",
            output_model=RiskRegister,
            prompt_builder=self._prompt_registry.risk_register,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
            },
        )

    def generate_mitigation_plan(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        threat_register: StrideThreatRegister,
    ) -> MitigationPlan:
        """Generate a mitigation plan from validated risks and threats."""
        return self._generate(
            task_name="generate_mitigation_plan",
            output_model=MitigationPlan,
            prompt_builder=self._prompt_registry.mitigation_plan,
            input_payload={
                "system_model": self._generator.serialize(model),
                "risk_register": self._generator.serialize(risk_register),
                "stride_threat_register": self._generator.serialize(threat_register),
            },
        )

    def generate_security_requirements(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> SecurityRequirements:
        """Generate security requirements from validated threats and risks."""
        return self._generate(
            task_name="generate_security_requirements",
            output_model=SecurityRequirements,
            prompt_builder=self._prompt_registry.security_requirements,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
                "risk_register": self._generator.serialize(risk_register),
            },
        )

    def generate_missing_information(self, model: CanonicalSystemModel) -> MissingInformationReport:
        """Generate a missing-information report through the agent provider."""
        return self._generate(
            task_name="generate_missing_information",
            output_model=MissingInformationReport,
            prompt_builder=self._prompt_registry.missing_information,
            input_payload={"system_model": self._generator.serialize(model)},
        )

    def generate_control_mapping(
        self,
        model: CanonicalSystemModel,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
        security_requirements: SecurityRequirements,
        threat_register: StrideThreatRegister,
    ) -> ControlMapping:
        """Generate control mappings from validated downstream artifacts."""
        ranked_candidates, catalog_provenance, allowed_ids = self._candidate_service.rank_all(
            model,
            security_requirements,
            risk_register,
            mitigation_plan,
            threat_register,
        )
        mapping = self._generate(
            task_name="generate_control_mapping",
            output_model=ControlMapping,
            prompt_builder=self._prompt_registry.control_mapping,
            input_payload={
                "system_model": self._generator.serialize(model),
                "risk_register": self._generator.serialize(risk_register),
                "mitigation_plan": self._generator.serialize(mitigation_plan),
                "security_requirements": self._generator.serialize(security_requirements),
                "stride_threat_register": self._generator.serialize(threat_register),
                "ranked_candidates_by_requirement": ranked_candidates,
                "catalog_provenance": catalog_provenance,
                "control_framework": ControlFrameworkName.OWASP_ASVS,
            },
            item_validator=build_candidate_membership_validator(allowed_ids),
        )
        return self._control_mapping_rule.validate(mapping)

    def generate_executive_summary(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
        mitigation_plan: MitigationPlan,
    ) -> ExecutiveSummary:
        """Generate an executive summary from validated artifacts through the agent provider."""
        return self._generate(
            task_name="generate_executive_summary",
            output_model=ExecutiveSummary,
            prompt_builder=self._prompt_registry.executive_summary,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
                "risk_register": self._generator.serialize(risk_register),
                "mitigation_plan": self._generator.serialize(mitigation_plan),
            },
        )

    def generate_technical_report(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
        risk_register: RiskRegister,
    ) -> TechnicalThreatModelReport:
        """Generate a technical report from validated artifacts through the agent provider."""
        return self._generate(
            task_name="generate_technical_report",
            output_model=TechnicalThreatModelReport,
            prompt_builder=self._prompt_registry.technical_report,
            input_payload={
                "system_model": self._generator.serialize(model),
                "stride_threat_register": self._generator.serialize(threat_register),
                "risk_register": self._generator.serialize(risk_register),
            },
        )

    def _generate[T: BaseModel](
        self,
        task_name: str,
        output_model: type[T],
        prompt_builder: PromptBuilder,
        input_payload: dict[str, JsonValue],
        item_validator: ItemValidator | None = None,
    ) -> T:
        return self._generator.generate(
            task_name=task_name,
            output_model=output_model,
            prompt_builder=prompt_builder,
            input_payload=input_payload,
            item_validator=item_validator,
        )
