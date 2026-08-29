"""Canonical system model extraction orchestration."""

from typing import cast

from pydantic import JsonValue, ValidationError

from threatmodeler.contracts.integration import AgentRequest, ParsedDocument
from threatmodeler.contracts.prompts import PromptBuildRequest
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.tool_calling.completer import SchemaBoundToolCallingCompleter
from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal
from threatmodeler.errors.application import AgentSchemaValidationError
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.schema_validator import SchemaValidator
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.validation.system_model_validator import CanonicalSystemModelReferenceChecker


class ExtractionOrchestrator:
    """Extract and validate a canonical system model from a parsed document.

    Prompt construction, agent completion, and business validation are injected so the
    orchestrator depends only on stable application ports.
    """

    def __init__(
        self,
        agent_provider: AgentProvider,
        schema_validator: SchemaValidator,
        prompt_builder: PromptBuilder,
        schema_provider: SchemaProvider,
        tool_calling_provider: ToolCallingProvider,
        business_repair_prompt_builder: PromptBuilder | None = None,
        max_business_repair_attempts: int = 1,
        max_attempts: int = 1,
    ) -> None:
        self._agent_provider = agent_provider
        self._schema_validator = schema_validator
        self._prompt_builder = prompt_builder
        self._schema_provider = schema_provider
        self._business_repair_prompt_builder = business_repair_prompt_builder
        self._max_business_repair_attempts = max(0, max_business_repair_attempts)
        self._completer = SchemaBoundToolCallingCompleter(
            tool_calling_provider,
            max_attempts=max(1, max_attempts),
        )
        self._reference_checker = CanonicalSystemModelReferenceChecker()

    def extract(
        self,
        document: ParsedDocument,
        journal: ConstructionJournal | None = None,
    ) -> CanonicalSystemModel:
        """Produce a validated canonical model from one parsed document.

        Args:
            document: Parser-neutral architecture document supplied to the agent provider.
            journal: Optional construction journal for the current extraction run.

        Returns:
            Schema-valid model that has passed all configured business rules.

        Raises:
            AgentSchemaValidationError: If agent output or business references are invalid.
        """
        input_payload = document.model_dump(mode="json", exclude={"attachments"})
        input_payload["attachment_manifest"] = [
            attachment.model_dump(mode="json", exclude={"content_base64"})
            for attachment in document.attachments
        ]
        prompt = self._prompt_builder.build(
            PromptBuildRequest(
                task_name="extract_canonical_system_model",
                input_payload=input_payload,
                output_schema_name=CanonicalSystemModel.__name__,
                output_schema=self._schema_provider.get_schema(CanonicalSystemModel),
            )
        )
        request = AgentRequest(
            task_name="extract_canonical_system_model",
            instructions=prompt.render_instructions(),
            messages=prompt.messages,
            input_payload=input_payload,
            attachments=document.attachments,
            expected_schema_name=prompt.expected_schema_name,
            temperature=0.0,
            max_output_tokens=16_000,
        )
        response = self._completer.complete(
            request,
            CanonicalSystemModel,
            journal or DiscardingConstructionJournal(),
            source_text=document.raw_text,
            finish_validator=self._finish_validator,
            item_validator=self._reference_checker,
        )
        model = self._parse_model(response.output_payload, document.document_id)
        model = model.model_copy(update={"diagram_topology": list(document.diagram_topology)})
        try:
            return self._schema_validator.validate(model)
        except AgentSchemaValidationError as error:
            if (
                error.error_code != "CANONICAL_SYSTEM_MODEL_BUSINESS_INVALID"
                or self._business_repair_prompt_builder is None
                or self._max_business_repair_attempts < 1
            ):
                raise
            return self._repair_business_rules(
                document=document,
                input_payload=input_payload,
                invalid_model=model,
                error=error,
            )

    def _repair_business_rules(
        self,
        *,
        document: ParsedDocument,
        input_payload: dict[str, JsonValue],
        invalid_model: CanonicalSystemModel,
        error: AgentSchemaValidationError,
    ) -> CanonicalSystemModel:
        assert self._business_repair_prompt_builder is not None
        violations = _violation_strings(error)
        latest_error = error
        candidate = invalid_model
        for _attempt in range(1, self._max_business_repair_attempts + 1):
            repair_prompt = self._business_repair_prompt_builder.build(
                PromptBuildRequest(
                    task_name="repair_canonical_system_model_business_rules",
                    input_payload=input_payload,
                    output_schema_name=CanonicalSystemModel.__name__,
                    output_schema=self._schema_provider.get_schema(CanonicalSystemModel),
                    additional_context={
                        "original_task_name": "extract_canonical_system_model",
                        "invalid_output": candidate.model_dump(mode="json"),
                        "business_violations": cast(list[JsonValue], violations),
                        "source_context": {
                            "document_id": document.document_id,
                            "attachment_manifest": input_payload.get("attachment_manifest"),
                        },
                    },
                )
            )
            repair_request = AgentRequest(
                task_name="repair_canonical_system_model_business_rules",
                instructions=repair_prompt.render_instructions(),
                messages=repair_prompt.messages,
                input_payload=input_payload,
                attachments=document.attachments,
                expected_schema_name=repair_prompt.expected_schema_name,
                temperature=0.0,
                max_output_tokens=16_000,
            )
            repaired_response = self._agent_provider.complete(repair_request)
            candidate = self._parse_model(
                repaired_response.output_payload,
                document.document_id,
            )
            candidate = candidate.model_copy(
                update={"diagram_topology": list(document.diagram_topology)}
            )
            try:
                return self._schema_validator.validate(candidate)
            except AgentSchemaValidationError as repair_error:
                latest_error = repair_error
                if repair_error.error_code != "CANONICAL_SYSTEM_MODEL_BUSINESS_INVALID":
                    raise
                violations = _violation_strings(repair_error)
        raise latest_error

    def _parse_model(
        self,
        output_payload: object,
        document_id: str,
    ) -> CanonicalSystemModel:
        try:
            return CanonicalSystemModel.model_validate(output_payload)
        except ValidationError as error:
            raise AgentSchemaValidationError(
                "Extracted architecture does not match CanonicalSystemModel",
                error_code="CANONICAL_SYSTEM_MODEL_INVALID",
                retryable=False,
                context={
                    "document_id": document_id,
                    "validation_errors": error.errors(
                        include_url=False,
                        include_input=False,
                    ),
                },
            ) from error

    def _finish_validator(self, payload: dict[str, JsonValue]) -> list[str]:
        try:
            model = CanonicalSystemModel.model_validate(payload)
            self._schema_validator.validate(model)
        except ValidationError as error:
            return [
                f"{'.'.join(str(part) for part in item.get('loc', ()))}: {item.get('msg')}"
                for item in error.errors(include_url=False, include_input=False)
            ]
        except AgentSchemaValidationError as error:
            return _violation_strings(error)
        return []


def _violation_strings(error: AgentSchemaValidationError) -> list[str]:
    context = error.context or {}
    raw = context.get("violations", [])
    if not isinstance(raw, list):
        return [error.message]
    return [str(item) for item in cast(list[object], raw)]
