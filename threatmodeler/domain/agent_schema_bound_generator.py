"""Template for schema-bound artifact completion through construction tools."""

from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

from threatmodeler.contracts import AgentRequest, PromptBuildRequest
from threatmodeler.domain.tool_calling.completer import SchemaBoundToolCallingCompleter
from threatmodeler.domain.tool_calling.completion import source_text_from_payload
from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.ports.artifact_construction_session_factory import (
    ArtifactConstructionSessionFactory,
    ItemValidator,
)
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.validation.reference_ids import KnownIdReferenceChecker, collect_known_ids


def _chain_item_validators(
    *validators: ItemValidator | None,
) -> ItemValidator | None:
    active = [validator for validator in validators if validator is not None]
    if not active:
        return None
    if len(active) == 1:
        return active[0]

    def validate(
        list_field: str,
        payload: dict[str, JsonValue],
        lists: dict[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        violations: list[str] = []
        for validator in active:
            violations.extend(validator(list_field, payload, lists))
        return violations

    return validate


class AgentSchemaBoundArtifactGenerator:
    """Complete and validate one schema-bound artifact through tool-calling."""

    def __init__(
        self,
        tool_calling_provider: ToolCallingProvider,
        schema_provider: SchemaProvider,
        max_attempts: int = 1,
    ) -> None:
        self._completer = SchemaBoundToolCallingCompleter(
            tool_calling_provider,
            max_attempts=max(1, max_attempts),
        )
        self._schema_provider = schema_provider
        self._journal: ConstructionJournal | None = None

    def bind_journal(self, journal: ConstructionJournal | None) -> None:
        """Bind the per-run construction journal."""
        self._journal = journal

    def generate[T: BaseModel](
        self,
        task_name: str,
        output_model: type[T],
        prompt_builder: PromptBuilder,
        input_payload: dict[str, JsonValue],
        additional_context: dict[str, JsonValue] | None = None,
        session_factory: ArtifactConstructionSessionFactory | None = None,
        item_validator: ItemValidator | None = None,
    ) -> T:
        """Request, validate, and return one schema-bound artifact.

        Args:
            task_name: Stable agent task identifier.
            output_model: Expected Pydantic output contract.
            prompt_builder: Schema-bound prompt builder for the task.
            input_payload: Untrusted serialized upstream artifacts.
            additional_context: Optional extra prompt-builder context.
            session_factory: Optional construction-session factory override.
            item_validator: Optional extra per-item validator chained after id checks.

        Returns:
            Schema-valid artifact assembled through construction tools.

        Raises:
            AgentSchemaValidationError: If provider output violates the contract.
        """
        prompt = prompt_builder.build(
            PromptBuildRequest(
                task_name=task_name,
                input_payload=input_payload,
                output_schema_name=output_model.__name__,
                output_schema=self._schema_provider.get_schema(output_model),
                additional_context=additional_context,
            )
        )
        request = AgentRequest(
            task_name=task_name,
            instructions=prompt.render_instructions(),
            messages=prompt.messages,
            input_payload=input_payload,
            expected_schema_name=prompt.expected_schema_name,
            temperature=0.0,
            max_output_tokens=8_000,
        )
        response = self._completer.complete(
            request,
            output_model,
            self._journal or DiscardingConstructionJournal(),
            source_text=source_text_from_payload(input_payload),
            item_validator=_chain_item_validators(
                KnownIdReferenceChecker(collect_known_ids(input_payload)),
                item_validator,
            ),
            session_factory=session_factory,
        )
        try:
            return output_model.model_validate(response.output_payload)
        except ValidationError as error:
            raise AgentSchemaValidationError(
                f"Agent output does not match {output_model.__name__}",
                error_code="AGENT_ARTIFACT_SCHEMA_INVALID",
                retryable=False,
                context={
                    "task_name": task_name,
                    "expected_schema_name": output_model.__name__,
                    "validation_errors": error.errors(
                        include_url=False,
                        include_input=False,
                    ),
                },
            ) from error

    def serialize(self, value: BaseModel) -> dict[str, JsonValue]:
        """Serialize a validated artifact into an agent input payload fragment."""
        return TypeAdapter(dict[str, JsonValue]).validate_json(value.model_dump_json())
