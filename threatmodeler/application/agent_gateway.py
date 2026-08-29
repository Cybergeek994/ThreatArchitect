"""Agent provider gateway with retries, repair, and output-schema validation."""

import json
from typing import cast

from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.contracts.prompts import PromptBuildRequest
from threatmodeler.errors.application import (
    AgentProviderError,
    AgentSchemaValidationError,
    ConfigurationError,
)
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.schema_registry import OutputSchemaRegistry


class _OutputValidationFailure(Exception):
    def __init__(self, invalid_output: JsonValue, errors: list[JsonValue]) -> None:
        super().__init__("Agent output validation failed")
        self.invalid_output = invalid_output
        self.errors = errors


class AgentProviderGateway:
    """Apply retry and schema-validation policy around an agent provider.

    Provider, schema, and repair strategies are injected, keeping retry and repair policy
    independent of provider SDKs and concrete Pydantic models.
    """

    def __init__(
        self,
        provider: AgentProvider,
        schema_registry: OutputSchemaRegistry,
        repair_prompt_builder: PromptBuilder,
        schema_provider: SchemaProvider,
        max_attempts: int = 3,
        max_schema_repair_attempts: int = 1,
    ) -> None:
        if max_attempts < 1:
            raise ConfigurationError(
                "Agent gateway max_attempts must be at least one",
                error_code="AGENT_MAX_ATTEMPTS_INVALID",
                retryable=False,
                context={"max_attempts": max_attempts},
            )
        if max_schema_repair_attempts < 0:
            raise ConfigurationError(
                "Agent gateway max_schema_repair_attempts cannot be negative",
                error_code="AGENT_SCHEMA_REPAIR_ATTEMPTS_INVALID",
                retryable=False,
                context={"max_schema_repair_attempts": max_schema_repair_attempts},
            )
        self._provider = provider
        self._schema_registry = schema_registry
        self._repair_prompt_builder = repair_prompt_builder
        self._schema_provider = schema_provider
        self._max_attempts = max_attempts
        self._max_schema_repair_attempts = max_schema_repair_attempts

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Complete a request, retry transient failures, and validate its output.

        Args:
            request: Provider-neutral completion request naming the expected output schema.

        Returns:
            Provider response with output normalized by the requested Pydantic schema.

        Raises:
            AgentProviderError: If the provider exhausts retry attempts or fails permanently.
            AgentSchemaValidationError: If the schema is unknown or the response is invalid.
        """
        schema = self._schema_registry.get(request.expected_schema_name)
        response = self._complete_with_retry(request)
        try:
            return self._validate_response(response, schema)
        except _OutputValidationFailure as failure:
            latest_failure = failure

        for repair_attempt in range(1, self._max_schema_repair_attempts + 1):
            repair_request = self._build_repair_request(
                original_request=request,
                failure=latest_failure,
                schema=schema,
                repair_attempt=repair_attempt,
            )
            repaired_response = self._complete_with_retry(repair_request)
            try:
                return self._validate_response(repaired_response, schema)
            except _OutputValidationFailure as failure:
                latest_failure = failure

        raise AgentSchemaValidationError(
            "Agent response does not match the requested output schema after repair",
            error_code="AGENT_RESPONSE_SCHEMA_INVALID",
            retryable=False,
            context={
                "task_name": request.task_name,
                "expected_schema_name": request.expected_schema_name,
                "schema_repair_attempts": self._max_schema_repair_attempts,
                "validation_errors": latest_failure.errors,
            },
        )

    def _complete_with_retry(self, request: AgentRequest) -> AgentResponse:
        for attempt in range(1, self._max_attempts + 1):
            try:
                return self._provider.complete(request)
            except AgentProviderError as error:
                if error.retryable is not True or attempt == self._max_attempts:
                    raise
        raise AssertionError("Agent retry loop completed without a response")

    def _validate_response(
        self,
        response: AgentResponse,
        schema: type[BaseModel],
    ) -> AgentResponse:
        payload = self._parse_payload(response.output_payload)
        try:
            validated_output = schema.model_validate(payload)
        except ValidationError as error:
            errors = self._json_safe_errors(
                error.errors(
                    include_url=False,
                    include_input=False,
                )
            )
            raise _OutputValidationFailure(payload, errors) from error
        return response.model_copy(
            update={"output_payload": validated_output.model_dump(mode="json")}
        )

    def _parse_payload(self, output_payload: dict[str, JsonValue] | str) -> dict[str, JsonValue]:
        if isinstance(output_payload, dict):
            return output_payload
        try:
            parsed = json.loads(output_payload)
        except json.JSONDecodeError as error:
            raise _OutputValidationFailure(
                output_payload,
                [
                    {
                        "type": "json_invalid",
                        "message": str(error),
                    }
                ],
            ) from error
        if not isinstance(parsed, dict):
            raise _OutputValidationFailure(
                cast(JsonValue, parsed),
                [
                    {
                        "type": "json_object_required",
                        "message": "Agent output must be a JSON object",
                    }
                ],
            )
        return cast(dict[str, JsonValue], parsed)

    def _build_repair_request(
        self,
        original_request: AgentRequest,
        failure: _OutputValidationFailure,
        schema: type[BaseModel],
        repair_attempt: int,
    ) -> AgentRequest:
        output_schema = self._schema_provider.get_schema(schema)
        prompt = self._repair_prompt_builder.build(
            PromptBuildRequest(
                task_name=f"repair_{original_request.task_name}",
                input_payload={},
                output_schema_name=original_request.expected_schema_name,
                output_schema=output_schema,
                additional_context={
                    "original_task_name": original_request.task_name,
                    "invalid_output": failure.invalid_output,
                    "validation_errors": failure.errors,
                },
            )
        )
        return AgentRequest(
            task_name=prompt.task_name,
            instructions=prompt.render_instructions(),
            messages=prompt.messages,
            input_payload={
                "invalid_output": failure.invalid_output,
                "validation_errors": failure.errors,
                "repair_attempt": repair_attempt,
            },
            expected_schema_name=prompt.expected_schema_name,
            temperature=0.0,
            max_output_tokens=original_request.max_output_tokens,
        )

    def _json_safe_errors(self, errors: object) -> list[JsonValue]:
        serialized = json.loads(json.dumps(errors, default=str))
        return TypeAdapter(list[JsonValue]).validate_python(serialized)
