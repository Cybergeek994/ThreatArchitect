"""Strict contracts for schema-bound agent prompts."""

from enum import StrEnum
from typing import Annotated

from pydantic import Field, JsonValue, model_validator

from threatmodeler.contracts.base import ContractModel


class PromptRole(StrEnum):
    """Identify the supported authority levels for prompt messages."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"


class PromptMessage(ContractModel):
    """Represent one immutable message in a rendered prompt contract."""

    role: PromptRole
    content: Annotated[str, Field(strict=True, min_length=1)]


class PromptBuildRequest(ContractModel):
    """Supply trusted task metadata and untrusted input to a prompt builder."""

    task_name: Annotated[str, Field(strict=True, min_length=1)]
    input_payload: dict[str, JsonValue]
    output_schema_name: Annotated[str, Field(strict=True, min_length=1)]
    output_schema: Annotated[dict[str, JsonValue], Field(min_length=1)]
    additional_context: dict[str, JsonValue] | None = None


class PromptBuildResult(ContractModel):
    """Return an ordered, schema-bound prompt ready for provider invocation."""

    task_name: Annotated[str, Field(strict=True, min_length=1)]
    messages: Annotated[list[PromptMessage], Field(min_length=3, max_length=3)]
    expected_schema_name: Annotated[str, Field(strict=True, min_length=1)]
    expected_schema: Annotated[dict[str, JsonValue], Field(min_length=1)]

    @model_validator(mode="after")
    def require_authority_order(self) -> "PromptBuildResult":
        """Require exactly one system, developer, and user message in authority order.

        Returns:
            Validated prompt result with a stable authority hierarchy.

        Raises:
            ValueError: If the message roles are missing, duplicated, or reordered.
        """
        roles = [message.role for message in self.messages]
        expected_roles = [PromptRole.SYSTEM, PromptRole.DEVELOPER, PromptRole.USER]
        if roles != expected_roles:
            raise ValueError("Prompt messages must use system, developer, user order")
        return self

    def render_instructions(self) -> str:
        """Render messages for provider clients that accept one instruction string.

        Returns:
            Stable text preserving message roles and authority order.
        """
        return "\n\n".join(
            f"{message.role.value.upper()} MESSAGE:\n{message.content}" for message in self.messages
        )
