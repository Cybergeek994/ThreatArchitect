"""Schema-bound prompt construction port."""

from typing import Protocol

from threatmodeler.contracts.prompts import PromptBuildRequest, PromptBuildResult


class PromptBuilder(Protocol):
    """Define deterministic construction of secure, schema-bound prompts."""

    def build(self, request: PromptBuildRequest) -> PromptBuildResult:
        """Build a prompt without invoking an agent provider.

        Args:
            request: Validated task, input payload, and expected-schema metadata.

        Returns:
            Ordered system, developer, and user messages bound to the output schema.
        """
        ...
