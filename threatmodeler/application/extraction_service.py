"""File-oriented canonical extraction application service."""

from pathlib import Path

from threatmodeler.contracts.integration import SavedArtifact
from threatmodeler.domain.missing_information_policy import (
    MissingInformationPolicy,
    PermissiveMissingInformationPolicy,
)
from threatmodeler.orchestration.extraction_orchestrator import ExtractionOrchestrator
from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.construction_journal_factory import ConstructionJournalFactory
from threatmodeler.ports.parsed_document_loader import ParsedDocumentLoader
from threatmodeler.shared.constants import DefaultPathName


class SystemModelExtractionService:
    """Extract and persist a canonical system model from a parsed document.

    The use case delegates loading, agent orchestration, rendering, and persistence to
    constructor-injected collaborators.
    """

    def __init__(
        self,
        document_loader: ParsedDocumentLoader,
        orchestrator: ExtractionOrchestrator,
        artifact_renderer: ArtifactRenderer,
        artifact_repository: ArtifactRepository,
        missing_information_policy: MissingInformationPolicy | None = None,
        journal_factory: ConstructionJournalFactory | None = None,
        journal_enabled: bool = False,
    ) -> None:
        self._document_loader = document_loader
        self._orchestrator = orchestrator
        self._artifact_renderer = artifact_renderer
        self._artifact_repository = artifact_repository
        self._missing_information_policy = (
            missing_information_policy or PermissiveMissingInformationPolicy()
        )
        self._journal_factory = journal_factory
        self._journal_enabled = journal_enabled

    def extract(self, input_path: Path, output_dir: Path) -> SavedArtifact:
        """Extract and persist one canonical system model.

        Args:
            input_path: Path to a validated parsed-document JSON artifact.
            output_dir: Directory in which the system model is persisted.

        Returns:
            Metadata for the saved system-model artifact.

        Examples:
            Extract a model from a previously ingested document::

                saved = service.extract(Path("parsed-document.json"), Path("out"))
        """
        document = self._document_loader.load(input_path)
        journal = None
        if self._journal_factory is not None and self._journal_enabled:
            journal = self._journal_factory.open(output_dir / DefaultPathName.JOURNAL_DIR)
        try:
            model = self._orchestrator.extract(document, journal=journal)
        finally:
            if journal is not None:
                journal.close()
        self._missing_information_policy.enforce(model)
        rendered = self._artifact_renderer.render(model)
        return self._artifact_repository.save(rendered, output_dir)
