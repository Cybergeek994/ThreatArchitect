"""Consistent metadata construction for generated artifacts and records."""

from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threatmodeler.contracts.source import Evidence


class ArtifactFields(BaseModel):
    """Common fields for an artifact Pydantic model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(strict=True, min_length=1)
    title: str = Field(strict=True, min_length=1)
    description: str = Field(strict=True, min_length=1)
    confidence: float
    assumptions: list[str] = Field(min_length=0)


class ArtifactItemFields(BaseModel):
    """Common fields for an artifact item Pydantic model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(strict=True, min_length=1)
    name: str = Field(strict=True, min_length=1)
    description: str = Field(strict=True, min_length=1)
    evidence: list[Evidence]
    confidence: float
    assumptions: list[str] = Field(min_length=0)


class ArtifactMetadataService:
    """Build metadata dictionaries consumed immediately by Pydantic models."""

    def compute_confidence(self, items: Sequence[Any], *, when_empty: float) -> float:
        """Compute artifact confidence as the minimum of item confidences.

        Uses minimum because the artifact is only as reliable as its least
        confident item. When no items expose a confidence value, the caller
        must supply ``when_empty`` from a real source (for example
        ``model.application.confidence``).

        Args:
            items: Source records that expose a ``confidence`` attribute.
            when_empty: Confidence inherited from a real source when ``items``
                is empty or yields no confidence values.

        Returns:
            Minimum confidence across items, or ``when_empty`` when none exist.
        """
        confidences = [
            float(confidence)
            for item in items
            if (confidence := getattr(item, "confidence", None)) is not None
            and isinstance(confidence, int | float)
        ]
        if not confidences:
            return when_empty
        return min(confidences)

    def artifact_fields(
        self,
        artifact_id: str,
        title: str,
        description: str,
        assumptions: list[str],
        *,
        confidence: float,
    ) -> ArtifactFields:
        """Build common top-level artifact fields.

        Args:
            artifact_id: Stable identifier for the generated artifact.
            title: Human-readable artifact title.
            description: Concise explanation of artifact contents.
            assumptions: Assumptions inherited from the canonical model.
            confidence: Artifact confidence inherited from source items.

        Returns:
            Validated fields accepted by top-level artifact Pydantic models.
        """
        return ArtifactFields(
            artifact_id=artifact_id,
            title=title,
            description=description,
            confidence=confidence,
            assumptions=list(assumptions),
        )

    def item_fields(
        self,
        item_id: str,
        name: str,
        description: str,
        evidence: list[Evidence],
        confidence: float,
        assumptions: list[str],
    ) -> ArtifactItemFields:
        """Build common generated record fields.

        Args:
            item_id: Stable identifier for the generated record.
            name: Human-readable record name.
            description: Concise explanation of the record.
            evidence: Validated source evidence supporting the record.
            confidence: Confidence assigned to the record.
            assumptions: Assumptions affecting the record.

        Returns:
            Validated fields accepted by artifact-item Pydantic models.
        """
        return ArtifactItemFields(
            id=item_id,
            name=name,
            description=description,
            evidence=list(evidence),
            confidence=confidence,
            assumptions=list(assumptions),
        )
