"""Contracts exchanged across external-system ports."""

import base64
import binascii
import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from pydantic import AnyUrl, Field, JsonValue, StrictBool, model_validator

from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.prompts import PromptMessage
from threatmodeler.contracts.source import SourceReference, SourceType


class AttachmentKind(StrEnum):
    """Classify attachment content for provider capability selection."""

    DIAGRAM = "diagram"
    IMAGE = "image"
    DOCUMENT = "document"
    OTHER = "other"


class AttachmentContent(ContractModel):
    """Carry validated attachment content across ingestion and agent boundaries.

    Content is base64 encoded so parsed documents remain portable JSON artifacts. The
    size and digest checks prevent corrupted content from silently reaching an agent.
    """

    attachment_id: Annotated[str, Field(strict=True, min_length=1)]
    filename: Annotated[str, Field(strict=True, min_length=1)]
    media_type: Annotated[str, Field(strict=True, min_length=1)]
    kind: AttachmentKind
    content_base64: Annotated[str, Field(strict=True, min_length=1)]
    size_bytes: Annotated[int, Field(strict=True, ge=1)]
    sha256: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
    source_reference: SourceReference

    @model_validator(mode="after")
    def validate_content_integrity(self) -> "AttachmentContent":
        """Verify that encoded content matches its declared size and digest.

        Returns:
            Attachment after successful integrity validation.

        Raises:
            ValueError: If content is invalid base64 or fails an integrity check.
        """
        try:
            content = base64.b64decode(self.content_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("Attachment content must be valid base64") from error
        if len(content) != self.size_bytes:
            raise ValueError("Attachment size does not match decoded content")
        if hashlib.sha256(content).hexdigest() != self.sha256:
            raise ValueError("Attachment digest does not match decoded content")
        return self

    def decoded_content(self) -> bytes:
        """Decode and return the integrity-checked attachment bytes.

        Returns:
            Original attachment bytes.

        Examples:
            Decode content before translating it to a provider SDK input::

                raw_content = attachment.decoded_content()
        """
        return base64.b64decode(self.content_base64, validate=True)


class ConfluencePage(ContractModel):
    """Confluence page content returned by a client adapter."""

    page_id: Annotated[str, Field(strict=True, min_length=1)]
    title: Annotated[str, Field(strict=True, min_length=1)]
    url: AnyUrl
    content: Annotated[str, Field(strict=True, min_length=1)]
    version: Annotated[int, Field(strict=True, ge=1)]
    media_type: Annotated[str, Field(strict=True, min_length=1)] = "text/html"
    source_type: SourceType = SourceType.CONFLUENCE_PAGE


class ParsedInputRequest(ContractModel):
    """Source document supplied to a parser strategy."""

    document_id: Annotated[str, Field(strict=True, min_length=1)]
    content: Annotated[str, Field(strict=True, min_length=1)]
    media_type: Annotated[str, Field(strict=True, min_length=1)]
    source_reference: SourceReference
    attachments: list[AttachmentContent] = Field(default_factory=list)


class ParsedHeading(ContractModel):
    """A heading extracted from a source document."""

    level: Annotated[int, Field(strict=True, ge=1, le=6)]
    text: Annotated[str, Field(strict=True, min_length=1)]


class ParsedParagraph(ContractModel):
    """A paragraph extracted from a source document."""

    text: Annotated[str, Field(strict=True, min_length=1)]


class ParsedTable(ContractModel):
    """A table extracted from a source document."""

    headers: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)


class ImageReference(ContractModel):
    """An image or diagram reference extracted from a source document."""

    source: Annotated[str, Field(strict=True, min_length=1)]
    alt_text: str | None = None
    title: str | None = None
    is_diagram: StrictBool = False


class DiagramNode(ContractModel):
    """A labeled node extracted from a diagram payload."""

    node_id: Annotated[str, Field(strict=True, min_length=1)]
    label: Annotated[str, Field(strict=True, min_length=1)]


class DiagramEdge(ContractModel):
    """A directed edge extracted from a diagram payload."""

    source_id: Annotated[str, Field(strict=True, min_length=1)]
    target_id: Annotated[str, Field(strict=True, min_length=1)]
    label: Annotated[str, Field(strict=True, min_length=1)] | None = None


class DiagramTopologySnapshot(ContractModel):
    """Nodes and edges extracted from one diagram source."""

    source_filename: Annotated[str, Field(strict=True, min_length=1)]
    nodes: list[DiagramNode] = Field(default_factory=list)
    edges: list[DiagramEdge] = Field(default_factory=list)


class ParsedDocument(ContractModel):
    """Structured parser-neutral representation of an architecture document."""

    document_id: Annotated[str, Field(strict=True, min_length=1)]
    title: Annotated[str, Field(strict=True, min_length=1)]
    headings: list[ParsedHeading] = Field(default_factory=list)
    paragraphs: list[ParsedParagraph] = Field(default_factory=list)
    tables: list[ParsedTable] = Field(default_factory=list)
    image_references: list[ImageReference] = Field(default_factory=list)
    attachments: list[AttachmentContent] = Field(default_factory=list)
    diagram_topology: list[DiagramTopologySnapshot] = Field(default_factory=list)
    raw_text: Annotated[str, Field(strict=True, min_length=1)]
    source_reference: SourceReference
    media_type: Annotated[str, Field(strict=True, min_length=1)]


class AgentRequest(ContractModel):
    """Provider-neutral request for an agent completion."""

    task_name: Annotated[str, Field(strict=True, min_length=1)]
    instructions: Annotated[str, Field(strict=True, min_length=1)]
    input_payload: dict[str, JsonValue]
    attachments: list[AttachmentContent] = Field(default_factory=list)
    expected_schema_name: Annotated[str, Field(strict=True, min_length=1)]
    messages: list[PromptMessage] = Field(default_factory=list)
    temperature: Annotated[
        float,
        Field(strict=True, ge=0.0, le=2.0, allow_inf_nan=False),
    ] = 0.0
    max_output_tokens: Annotated[int, Field(strict=True, gt=0)] = 2_000


class AgentResponse(ContractModel):
    """Provider-neutral response from an agent completion."""

    output_payload: dict[str, JsonValue] | str
    confidence: Annotated[
        float,
        Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False),
    ]
    raw_response: str | None = None
    provider_name: Annotated[str, Field(strict=True, min_length=1)]
    model_name: Annotated[str, Field(strict=True, min_length=1)]


class RenderedArtifact(ContractModel):
    """An in-memory artifact ready for persistence."""

    name: Annotated[str, Field(strict=True, min_length=1)]
    content: Annotated[str, Field(strict=True, min_length=1)]
    media_type: Annotated[str, Field(strict=True, min_length=1)]
    file_extension: Annotated[
        str,
        Field(strict=True, min_length=1, pattern=r"^\.[A-Za-z0-9]+$"),
    ]


class SavedArtifact(ContractModel):
    """Metadata describing a persisted artifact."""

    path: Path
    size_bytes: Annotated[int, Field(strict=True, ge=0)]
    sha256: Annotated[str, Field(strict=True, pattern=r"^[a-fA-F0-9]{64}$")]
