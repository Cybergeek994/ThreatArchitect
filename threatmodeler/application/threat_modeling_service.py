"""Facade for generating the complete MVP1 threat-model artifact bundle."""

from threatmodeler.contracts.artifacts import ArtifactBundle, ArtifactModel
from threatmodeler.contracts.artifacts.stride_context import PreStrideArtifacts, StrideUpstreamContext
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.downstream_artifact_generation import DownstreamArtifactGenerationStrategy
from threatmodeler.domain.inventory_generation import InventoryGenerationService
from threatmodeler.domain.missing_information_policy import MissingInformationPolicy
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService
from threatmodeler.domain.stride_generation import StrideThreatGenerationService
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.construction_journal_receiver import ConstructionJournalReceiver


class ThreatModelingService:
    """Generate and validate all MVP1 artifacts from one canonical model.

    This facade coordinates focused domain services and revalidates each result through
    the injected artifact-validation port before downstream use.
    """

    def __init__(
        self,
        inventory_service: InventoryGenerationService,
        stride_service: StrideThreatGenerationService,
        downstream_strategy: DownstreamArtifactGenerationStrategy,
        report_service: ReportGenerationService,
        completeness_service: ThreatModelCompletenessService,
        artifact_validator: ArtifactValidator,
        metadata: ArtifactMetadataService,
        missing_information_policy: MissingInformationPolicy,
    ) -> None:
        self._inventory_service = inventory_service
        self._stride_service = stride_service
        self._downstream_strategy = downstream_strategy
        self._report_service = report_service
        self._completeness_service = completeness_service
        self._artifact_validator = artifact_validator
        self._metadata = metadata
        self._missing_information_policy = missing_information_policy

    def generate(
        self,
        model: CanonicalSystemModel,
        journal: ConstructionJournal | None = None,
    ) -> ArtifactBundle:
        """Generate the complete validated artifact graph.

        Args:
            model: Validated canonical architecture model used by all domain services.
            journal: Optional construction journal for the current generation run.

        Returns:
            Validated bundle containing every generated MVP1 artifact.

        Raises:
            ArtifactValidationError: If any generated artifact fails boundary validation.

        Examples:
            Generate all artifacts from an already validated model::

                bundle = service.generate(system_model)
        """
        self._bind_journal(journal)
        try:
            return self._generate_bundle(model)
        finally:
            self._bind_journal(None)

    def _bind_journal(self, journal: ConstructionJournal | None) -> None:
        for collaborator in (self._stride_service, self._downstream_strategy):
            if isinstance(collaborator, ConstructionJournalReceiver):
                collaborator.bind_journal(journal)

    def _generate_bundle(self, model: CanonicalSystemModel) -> ArtifactBundle:
        self._missing_information_policy.enforce(model)
        component_inventory = self._inventory_service.generate_component_inventory(model)
        asset_inventory = self._inventory_service.generate_asset_inventory(model)
        actor_model = self._inventory_service.generate_actor_model(model)
        data_flow_diagram = self._downstream_strategy.generate_dfd(model)
        trust_boundary_map = self._inventory_service.generate_trust_boundary_map(model)
        entry_point_inventory = self._inventory_service.generate_entry_point_inventory(model)
        authentication_model = self._inventory_service.generate_authentication_authorization_model(
            model
        )
        deployment_model = self._inventory_service.generate_deployment_model(model)
        pre_stride = PreStrideArtifacts(
            system_model=model,
            component_inventory=component_inventory,
            asset_inventory=asset_inventory,
            actor_model=actor_model,
            data_flow_diagram=data_flow_diagram,
            trust_boundary_map=trust_boundary_map,
            entry_point_inventory=entry_point_inventory,
            authentication_authorization_model=authentication_model,
            deployment_model=deployment_model,
        )
        architecture_graph = self._downstream_strategy.generate_architecture_graph(pre_stride)
        self._validate(architecture_graph)
        stride_context = StrideUpstreamContext(
            **pre_stride.model_dump(),
            architecture_graph=architecture_graph,
        )
        stride_threats = self._stride_service.generate(stride_context)
        self._validate(stride_threats)
        attack_tree = self._downstream_strategy.generate_attack_tree(model, stride_threats)
        abuse_cases = self._downstream_strategy.generate_abuse_cases(model, stride_threats)
        risk_register = self._downstream_strategy.generate_risk_register(model, stride_threats)
        mitigation_plan = self._downstream_strategy.generate_mitigation_plan(
            model,
            risk_register,
            stride_threats,
        )
        security_requirements = self._downstream_strategy.generate_security_requirements(
            model,
            stride_threats,
            risk_register,
        )
        assumptions = self._report_service.generate_assumptions(model)
        missing_information = self._downstream_strategy.generate_missing_information(model)
        control_mapping = self._downstream_strategy.generate_control_mapping(
            model,
            risk_register,
            mitigation_plan,
            security_requirements,
            stride_threats,
        )
        executive_summary = self._downstream_strategy.generate_executive_summary(
            model,
            stride_threats,
            risk_register,
            mitigation_plan,
        )
        technical_report = self._downstream_strategy.generate_technical_report(
            model,
            stride_threats,
            risk_register,
        )
        completeness_report = self._completeness_service.assess(
            model,
            stride_threats,
            mitigation_plan,
            data_flow_diagram,
            missing_information,
            architecture_graph,
        )
        technical_report = self._report_service.with_completeness_section(
            technical_report,
            model,
            completeness_report,
        )
        artifacts: list[ArtifactModel] = [
            component_inventory,
            asset_inventory,
            actor_model,
            data_flow_diagram,
            trust_boundary_map,
            entry_point_inventory,
            authentication_model,
            deployment_model,
            architecture_graph,
            attack_tree,
            abuse_cases,
            risk_register,
            mitigation_plan,
            security_requirements,
            assumptions,
            missing_information,
            control_mapping,
            executive_summary,
            technical_report,
            completeness_report,
        ]
        for artifact in artifacts:
            self._validate(artifact)
        bundle = ArtifactBundle(
            **self._metadata.artifact_fields(
                "artifact-bundle",
                "Machine-readable Threat Model Artifact Bundle",
                "Complete set of validated MVP1 threat-modeling artifacts.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    artifacts, when_empty=model.application.confidence
                ),
            ).model_dump(),
            component_inventory=component_inventory,
            asset_inventory=asset_inventory,
            actor_model=actor_model,
            data_flow_diagram=data_flow_diagram,
            trust_boundary_map=trust_boundary_map,
            entry_point_inventory=entry_point_inventory,
            authentication_authorization_model=authentication_model,
            deployment_model=deployment_model,
            architecture_graph=architecture_graph,
            stride_threat_register=stride_threats,
            attack_tree=attack_tree,
            abuse_misuse_cases=abuse_cases,
            risk_register=risk_register,
            mitigation_plan=mitigation_plan,
            security_requirements=security_requirements,
            assumptions_register=assumptions,
            missing_information_report=missing_information,
            control_mapping=control_mapping,
            executive_summary=executive_summary,
            technical_report=technical_report,
            completeness_report=completeness_report,
        )
        self._validate(bundle)
        return bundle

    def _validate(self, artifact: ArtifactModel) -> None:
        self._artifact_validator.validate(artifact)
