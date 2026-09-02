"""File-oriented artifact generation workflow."""

from pathlib import Path

from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.contracts.artifacts import ArtifactBundle, ArtifactModel
from threatmodeler.contracts.workflow import ArtifactGenerationResult
from threatmodeler.ports.artifact_renderer_factory import ArtifactRendererFactory
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.construction_journal_factory import ConstructionJournalFactory
from threatmodeler.ports.system_model_loader import SystemModelLoader
from threatmodeler.shared.constants import DefaultPathName


class ArtifactGenerationService:
    """Generate and persist the fixed artifact set for one canonical model.

    Model loading, domain generation, rendering, and storage are supplied as injected
    collaborators, keeping this file-oriented use case infrastructure-neutral.
    """

    def __init__(
        self,
        system_model_loader: SystemModelLoader,
        threat_modeling_service: ThreatModelingService,
        renderer_factory: ArtifactRendererFactory,
        artifact_repository: ArtifactRepository,
        journal_factory: ConstructionJournalFactory | None = None,
        journal_enabled: bool = False,
    ) -> None:
        self._system_model_loader = system_model_loader
        self._threat_modeling_service = threat_modeling_service
        self._renderer_factory = renderer_factory
        self._artifact_repository = artifact_repository
        self._journal_factory = journal_factory
        self._journal_enabled = journal_enabled

    def generate(self, input_path: Path, output_dir: Path) -> ArtifactGenerationResult:
        """Generate and save the fixed MVP1 artifact set.

        Args:
            input_path: Path to a validated canonical-system-model JSON document.
            output_dir: Directory beneath which JSON artifacts are persisted.

        Returns:
            Saved artifact metadata, including the canonical machine-readable bundle.

        Examples:
            Generate the artifact set from a persisted canonical model::

                result = service.generate(Path("system-model.json"), Path("out"))
        """
        model = self._system_model_loader.load(input_path)
        journal = None
        if self._journal_factory is not None and self._journal_enabled:
            journal = self._journal_factory.open(output_dir / DefaultPathName.JOURNAL_DIR)
        try:
            bundle = self._threat_modeling_service.generate(model, journal=journal)
        finally:
            if journal is not None:
                journal.close()
        named_artifacts = self._named_artifacts(bundle)
        saved_artifacts = [
            self._artifact_repository.save(
                self._renderer_factory.create(name).render(artifact),
                output_dir,
            )
            for name, artifact in named_artifacts
        ]
        return ArtifactGenerationResult(
            artifacts=tuple(saved_artifacts),
            bundle=saved_artifacts[-1],
        )

    def _named_artifacts(self, bundle: ArtifactBundle) -> list[tuple[str, ArtifactModel]]:
        return [
            ("component-inventory", bundle.component_inventory),
            ("asset-inventory", bundle.asset_inventory),
            ("actor-model", bundle.actor_model),
            ("dfd", bundle.data_flow_diagram),
            ("trust-boundary-map", bundle.trust_boundary_map),
            ("entry-points", bundle.entry_point_inventory),
            ("authz-model", bundle.authentication_authorization_model),
            ("deployment-model", bundle.deployment_model),
            ("architecture-graph", bundle.architecture_graph),
            ("stride-threats", bundle.stride_threat_register),
            ("attack-tree", bundle.attack_tree),
            ("abuse-cases", bundle.abuse_misuse_cases),
            ("risk-register", bundle.risk_register),
            ("mitigation-plan", bundle.mitigation_plan),
            ("security-requirements", bundle.security_requirements),
            ("assumptions", bundle.assumptions_register),
            ("missing-information", bundle.missing_information_report),
            ("control-mapping", bundle.control_mapping),
            ("executive-summary", bundle.executive_summary),
            ("technical-report", bundle.technical_report),
            ("completeness-report", bundle.completeness_report),
            ("artifact-bundle", bundle),
        ]
