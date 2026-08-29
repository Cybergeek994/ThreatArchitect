"""Source provenance and evidence contracts."""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class SourceType(StrEnum):
    """Supported origins for extracted architecture information."""

    CONFLUENCE_PAGE = "confluence_page"
    CONFLUENCE_ATTACHMENT = "confluence_attachment"
    DIAGRAM = "diagram"
    TABLE = "table"
    MANUAL_INPUT = "manual_input"


class SourceReference(BaseModel):
    """A precise pointer to source material used during extraction."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    source_type: SourceType
    source_id: Annotated[str, Field(strict=True, min_length=1)]
    location: Annotated[str, Field(strict=True, min_length=1)]
    excerpt: Annotated[str, Field(strict=True, min_length=1)]


class Evidence(BaseModel):
    """A supported extraction claim and the sources that establish it."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    summary: Annotated[str, Field(strict=True, min_length=1)]
    source_references: Annotated[list[SourceReference], Field(min_length=1)]
