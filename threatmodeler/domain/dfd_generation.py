"""Deterministic data-flow-diagram generation."""

from threatmodeler.contracts.artifacts import DataFlowDiagramModel
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class DfdGenerationService:
    """Generate a machine-readable DFD from canonical entities."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate(self, model: CanonicalSystemModel) -> DataFlowDiagramModel:
        """Generate the validated DFD artifact.

        Args:
            model: Canonical model containing components, stores, and flows.

        Returns:
            Machine-readable data flow diagram artifact.
        """
        return DataFlowDiagramModel(
            **self._metadata.artifact_fields(
                "data-flow-diagram",
                "Data Flow Diagram",
                "Components, data stores, and directional canonical data flows.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    [*model.components, *model.data_stores, *model.data_flows],
                    when_empty=model.application.confidence,
                ),
            ).model_dump(),
            components=model.components,
            data_stores=model.data_stores,
            data_flows=model.data_flows,
        )
