"""Pydantic contracts for end-to-end workflow results."""

from pathlib import Path
from typing import Annotated

from pydantic import Field, model_validator

from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.integration import SavedArtifact


class ArtifactGenerationResult(ContractModel):
    """Typed result of persisting the complete MVP1 artifact set."""

    artifacts: Annotated[tuple[SavedArtifact, ...], Field(min_length=1)]
    bundle: SavedArtifact

    @model_validator(mode="after")
    def validate_bundle_membership(self) -> "ArtifactGenerationResult":
        """Require one unique, explicitly identified machine-readable bundle.

        Returns:
            Validated generation result with canonical bundle membership.

        Raises:
            ValueError: If paths repeat or the canonical bundle is missing or misnamed.
        """
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("Generated artifact paths must be unique")
        if self.bundle.path.name != "artifact-bundle.json":
            raise ValueError("The artifact bundle must use the canonical artifact-bundle.json name")
        if self.bundle not in self.artifacts:
            raise ValueError("The artifact bundle must be included in generated artifacts")
        return self


class AnalysisSummary(ContractModel):
    """Concise summary of a completed end-to-end analysis."""

    application_name: Annotated[str, Field(strict=True, min_length=1)]
    component_count: Annotated[int, Field(strict=True, ge=0)]
    data_flow_count: Annotated[int, Field(strict=True, ge=0)]
    threat_count: Annotated[int, Field(strict=True, ge=0)]
    missing_information_count: Annotated[int, Field(strict=True, ge=0)]
    output_directory: Path
