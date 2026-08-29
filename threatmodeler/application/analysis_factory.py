"""Dependency-injected factory for end-to-end analysis workflows."""

from collections.abc import Callable

from threatmodeler.application.analysis_workflow import AnalysisWorkflowService
from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.extraction_service import SystemModelExtractionService
from threatmodeler.application.ingestion_service import ConfluenceIngestionService
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.ports.artifact_bundle_loader import ArtifactBundleLoader
from threatmodeler.ports.system_model_loader import SystemModelLoader


class AnalysisWorkflowFactory:
    """Wire fresh end-to-end workflows from injected stage factories and loaders.

    The factory is the application-level composition boundary for the analysis use case;
    it does not create infrastructure clients itself.
    """

    def __init__(
        self,
        ingestion_factory: Callable[[str], ConfluenceIngestionService],
        extraction_factory: Callable[[], SystemModelExtractionService],
        artifact_generation_factory: Callable[[], ArtifactGenerationService],
        rendering_factory: Callable[[], RenderingService],
        system_model_loader: SystemModelLoader,
        artifact_bundle_loader: ArtifactBundleLoader,
    ) -> None:
        self._ingestion_factory = ingestion_factory
        self._extraction_factory = extraction_factory
        self._artifact_generation_factory = artifact_generation_factory
        self._rendering_factory = rendering_factory
        self._system_model_loader = system_model_loader
        self._artifact_bundle_loader = artifact_bundle_loader

    def create(self, input_reference: str) -> AnalysisWorkflowService:
        """Create a workflow scoped to one input mode and dependency graph.

        Args:
            input_reference: Local export path, Confluence page URL, or page identifier.

        Returns:
            Fully composed analysis service with fresh stage services.
        """
        return AnalysisWorkflowService(
            ingestion_service=self._ingestion_factory(input_reference),
            extraction_service=self._extraction_factory(),
            artifact_generation_service=self._artifact_generation_factory(),
            rendering_service=self._rendering_factory(),
            system_model_loader=self._system_model_loader,
            artifact_bundle_loader=self._artifact_bundle_loader,
        )
