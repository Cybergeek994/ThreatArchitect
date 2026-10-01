"""Shared MVP1 artifact contracts."""

from typing import Annotated

from pydantic import Field, model_validator

from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.source import Evidence


class ArtifactModel(ContractModel):
    """Metadata shared by every generated threat-modeling artifact."""

    artifact_id: Annotated[str, Field(strict=True, min_length=1)]
    title: Annotated[str, Field(strict=True, min_length=1)]
    description: Annotated[str, Field(strict=True, min_length=1)]
    confidence: Annotated[
        float,
        Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False),
    ]
    assumptions: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )


class ArtifactItem(ContractModel):
    """Metadata shared by generated artifact records.

    Unlike ``ExtractedItem`` (which requires evidence because extraction must be
    source-grounded), artifact items may derive from upstream artifacts rather than
    raw source text. Evidence is optional when architecture linkage via ``*_id`` /
    ``*_ids`` fields provides traceability.
    """

    id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Stable, human-readable slug describing the item. "
                "Use lowercase kebab-case derived from the item meaning. "
                "Never use generic sequential ids. Must be unique."
            ),
        ),
    ]
    name: Annotated[str, Field(strict=True, min_length=1)]
    description: Annotated[str, Field(strict=True, min_length=1)]
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Annotated[
        float,
        Field(
            strict=True,
            ge=0.0,
            le=1.0,
            allow_inf_nan=False,
            description=(
                "Confidence based on evidence quality: "
                "1.0 = explicit in source; "
                "0.8-0.9 = strongly supported; "
                "0.6-0.7 = inferred from patterns; "
                "0.4-0.5 = speculative."
            ),
        ),
    ]
    assumptions: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )


class ThreatLinkedItem(ArtifactItem):
    """A threat-related record linked to architecture or source evidence."""

    component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Primary architecture component id from the input payload. "
                "Must match an id field on an input item."
            ),
        ),
    ] | None = None
    data_flow_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Primary data-flow id from the input payload. "
                "Must match an id field on an input item."
            ),
        ),
    ] | None = None
    asset_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Primary asset id from the input payload. "
                "Must match an id field on an input item."
            ),
        ),
    ] | None = None
    component_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description="Additional component ids from the input payload.",
            ),
        ]
    ] = Field(default_factory=list)
    data_flow_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description="Additional data-flow ids from the input payload.",
            ),
        ]
    ] = Field(default_factory=list)
    asset_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description="Additional asset ids from the input payload.",
            ),
        ]
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_traceability(self) -> "ThreatLinkedItem":
        """Require an architecture identifier or evidence for threat traceability.

        Returns:
            Validated item when at least one traceability field is populated.

        Raises:
            ValueError: If the item has no architecture identifier or evidence.
        """
        if not (
            self.component_id
            or self.data_flow_id
            or self.asset_id
            or self.component_ids
            or self.data_flow_ids
            or self.asset_ids
            or self.evidence
        ):
            raise ValueError(
                "A threat-related item must link to a component, data flow, asset, or evidence"
            )
        return self
