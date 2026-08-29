"""End-to-end architecture threat analysis workflow."""

from pathlib import Path

from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.extraction_service import SystemModelExtractionService
from threatmodeler.application.ingestion_service import ConfluenceIngestionService
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.contracts.workflow import AnalysisSummary
from threatmodeler.ports.artifact_bundle_loader import ArtifactBundleLoader
from threatmodeler.ports.system_model_loader import SystemModelLoader


class AnalysisWorkflowService:
    """Coordinate the complete validated MVP analysis use case.

    Stage services and validated artifact loaders are injected so orchestration remains
    independent of CLI and infrastructure details.
    """

    def __init__(
        self,
        ingestion_service: ConfluenceIngestionService,
        extraction_service: SystemModelExtractionService,
        artifact_generation_service: ArtifactGenerationService,
        rendering_service: RenderingService,
        system_model_loader: SystemModelLoader,
        artifact_bundle_loader: ArtifactBundleLoader,
    ) -> None:
        self._ingestion_service = ingestion_service
        self._extraction_service = extraction_service
        self._artifact_generation_service = artifact_generation_service
        self._rendering_service = rendering_service
        self._system_model_loader = system_model_loader
        self._artifact_bundle_loader = artifact_bundle_loader

    def analyze(
        self,
        input_reference: str,
        output_dir: Path,
        formats: list[str],
    ) -> AnalysisSummary:
        """Run ingestion through rendering and summarize the validated outputs.

        Args:
            input_reference: Local export path, Confluence page URL, or page identifier.
            output_dir: Directory in which workflow artifacts are persisted.
            formats: Deterministic output formats requested for final rendering.

        Returns:
            Counts and application metadata from the persisted system model and bundle.

        Examples:
            Run all workflow stages and request JSON plus Markdown renderings::

                summary = workflow.analyze(
                    "architecture.html",
                    Path("out"),
                    ["json", "markdown"],
                )
        """
        parsed_document = self._ingestion_service.ingest(input_reference, output_dir)
        system_model_artifact = self._extraction_service.extract(
            parsed_document.path,
            output_dir,
        )
        generation_result = self._artifact_generation_service.generate(
            system_model_artifact.path,
            output_dir,
        )
        self._rendering_service.render(
            generation_result.bundle.path,
            formats,
            output_dir / "rendered",
        )
        system_model = self._system_model_loader.load(system_model_artifact.path)
        bundle = self._artifact_bundle_loader.load(generation_result.bundle.path)
        return AnalysisSummary(
            application_name=system_model.application.name,
            component_count=len(system_model.components),
            data_flow_count=len(system_model.data_flows),
            threat_count=len(bundle.stride_threat_register.threats),
            missing_information_count=len(bundle.missing_information_report.items),
            output_directory=output_dir.expanduser().resolve(),
        )
