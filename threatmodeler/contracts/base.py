"""Shared Pydantic contracts for extracted architecture items."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from threatmodeler.contracts.source import Evidence, SourceReference


class ContractModel(BaseModel):
    """Base contract with immutable values and closed object shapes."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


class ExtractedItem(ContractModel):
    """Provenance and confidence shared by every extracted item.

    Evidence is required (min length 1) because extracted items must be
    source-grounded. Downstream ``ArtifactItem`` records may omit evidence when
    ``*_id`` / ``*_ids`` linkage provides traceability to upstream artifacts.
    """

    id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Stable, human-readable slug derived from the entity name. "
                "Use lowercase kebab-case, e.g., 'api-gateway', 'user-database', "
                "'admin-user'. For data flows use '{source}-to-{destination}', "
                "e.g., 'web-app-to-api-gateway'. Never use generic sequential "
                "ids like 'component1'. Must be unique across the artifact."
            ),
        ),
    ]
    name: Annotated[str, Field(strict=True, min_length=1)]
    description: Annotated[str, Field(strict=True, min_length=1)]
    evidence: Annotated[list[Evidence], Field(min_length=1)]
    confidence: Annotated[
        float,
        Field(
            strict=True,
            ge=0.0,
            le=1.0,
            allow_inf_nan=False,
            description=(
                "Confidence based on evidence quality: "
                "1.0 = verbatim explicit statement; "
                "0.8-0.9 = clear with minor inference; "
                "0.6-0.7 = moderate inference from context; "
                "0.4-0.5 = significant inference or ambiguous; "
                "below 0.4 = speculative."
            ),
        ),
    ]
    source_reference: SourceReference
