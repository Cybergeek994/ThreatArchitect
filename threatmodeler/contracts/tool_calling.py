"""Contracts for incremental artifact construction through agent tools."""

from typing import Annotated

from pydantic import Field, JsonValue

from threatmodeler.contracts.base import ContractModel
from threatmodeler.shared.constants import JournalEventType


class ToolDefinition(ContractModel):
    """Describe one host-defined construction tool exposed to an agent provider."""

    name: Annotated[str, Field(strict=True, min_length=1)]
    description: Annotated[str, Field(strict=True, min_length=1)]
    parameters_schema: dict[str, JsonValue]
    is_terminal: bool = False


class ToolApplicationResult(ContractModel):
    """Report whether a construction-tool invocation was accepted into builder state."""

    accepted: bool
    message: Annotated[str, Field(strict=True, min_length=1)]
    finished: bool = False
    evidence_grounded: bool | None = None
    item_id: Annotated[str, Field(strict=True, min_length=1)] | None = None
    confidence: Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)] | None = None


class JournalEvent(ContractModel):
    """One durable construction-journal record for a tool-calling run."""

    event_type: JournalEventType
    task_name: Annotated[str, Field(strict=True, min_length=1)]
    tool_name: Annotated[str, Field(strict=True, min_length=1)] | None = None
    accepted: bool | None = None
    message: str | None = None
    evidence_grounded: bool | None = None
    item_id: Annotated[str, Field(strict=True, min_length=1)] | None = None
    confidence: Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)] | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
