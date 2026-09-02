"""Strategy-based STRIDE and abuse-case generation."""

from typing import Protocol

from pydantic import JsonValue, ValidationError

from threatmodeler.contracts import AgentRequest, PromptBuildRequest
from threatmodeler.contracts.artifacts import (
    AbuseMisuseCase,
    AbuseMisuseCases,
    StrideThreatRegister,
)
from threatmodeler.contracts.artifacts.stride_context import StrideUpstreamContext
from threatmodeler.contracts.system_model import ActorType, CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.stride_input_payload_builder import StrideInputPayloadBuilder
from threatmodeler.domain.tool_calling.completer import SchemaBoundToolCallingCompleter
from threatmodeler.domain.tool_calling.completion import source_text_from_payload
from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.ports.construction_journal_receiver import ConstructionJournalReceiver
from threatmodeler.ports.prompt_builder import PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.validation.composite_item_validator import CompositeItemValidator
from threatmodeler.validation.reference_ids import KnownIdReferenceChecker, collect_known_ids
from threatmodeler.validation.threat_provenance_validator import (
    ThreatProvenanceValidatorFactory,
)


class StrideThreatGenerationStrategy(Protocol):
    """Define the interchangeable strategy for producing STRIDE registers."""

    def generate(self, context: StrideUpstreamContext) -> StrideThreatRegister:
        """Generate a validated STRIDE threat register from upstream artifacts.

        Args:
            context: Validated upstream artifacts including architecture graph.

        Returns:
            Strategy-specific but schema-valid STRIDE threat register.
        """
        ...


class AgentStrideThreatGenerationStrategy:
    """Generate STRIDE threats through the injected tool-calling strategy."""

    def __init__(
        self,
        tool_calling_provider: ToolCallingProvider,
        prompt_builder: PromptBuilder,
        schema_provider: SchemaProvider,
        payload_builder: StrideInputPayloadBuilder | None = None,
        max_attempts: int = 1,
    ) -> None:
        self._completer = SchemaBoundToolCallingCompleter(
            tool_calling_provider,
            max_attempts=max(1, max_attempts),
        )
        self._prompt_builder = prompt_builder
        self._schema_provider = schema_provider
        self._payload_builder = payload_builder or StrideInputPayloadBuilder()
        self._journal: ConstructionJournal | None = None

    def bind_journal(self, journal: ConstructionJournal | None) -> None:
        """Bind the per-run construction journal."""
        self._journal = journal

    def generate(self, context: StrideUpstreamContext) -> StrideThreatRegister:
        """Request and validate a structured STRIDE threat register.

        Args:
            context: Validated upstream artifacts serialized into the provider request.

        Returns:
            Schema-valid STRIDE threat register produced by the provider.

        Raises:
            AgentSchemaValidationError: If provider output violates the register schema.
        """
        input_payload = self._payload_builder.build(context)
        prompt = self._prompt_builder.build(
            PromptBuildRequest(
                task_name="generate_stride_threats",
                input_payload=input_payload,
                output_schema_name=StrideThreatRegister.__name__,
                output_schema=self._schema_provider.get_schema(StrideThreatRegister),
            )
        )
        request = AgentRequest(
            task_name="generate_stride_threats",
            instructions=prompt.render_instructions(),
            messages=prompt.messages,
            input_payload=input_payload,
            expected_schema_name=prompt.expected_schema_name,
            temperature=0.0,
            max_output_tokens=8_000,
        )
        response = self._completer.complete(
            request,
            StrideThreatRegister,
            self._journal or DiscardingConstructionJournal(),
            source_text=source_text_from_payload(input_payload),
            item_validator=CompositeItemValidator.of(
                KnownIdReferenceChecker(collect_known_ids(input_payload)),
                ThreatProvenanceValidatorFactory.from_input_payload(input_payload).build(),
            ),
        )
        try:
            return StrideThreatRegister.model_validate(response.output_payload)
        except ValidationError as error:
            raise AgentSchemaValidationError(
                "Agent output does not match StrideThreatRegister",
                error_code="STRIDE_THREAT_REGISTER_INVALID",
                retryable=False,
                context={
                    "validation_errors": error.errors(
                        include_url=False,
                        include_input=False,
                    )
                },
            ) from error


class StrideThreatGenerationService:
    """Expose STRIDE and abuse-case generation over an injected strategy."""

    def __init__(
        self,
        strategy: StrideThreatGenerationStrategy,
        metadata: ArtifactMetadataService,
    ) -> None:
        self._strategy = strategy
        self._metadata = metadata

    def bind_journal(self, journal: ConstructionJournal | None) -> None:
        """Forward the per-run journal to a journal-aware strategy."""
        if isinstance(self._strategy, ConstructionJournalReceiver):
            self._strategy.bind_journal(journal)

    def generate(self, context: StrideUpstreamContext) -> StrideThreatRegister:
        """Generate STRIDE threats using the selected strategy.

        Args:
            context: Validated upstream artifacts including architecture graph.

        Returns:
            Validated STRIDE threat register returned by the strategy.
        """
        return self._strategy.generate(context)

    def generate_abuse_cases(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AbuseMisuseCases:
        """Derive validated abuse cases only from validated STRIDE threats.

        Args:
            model: Canonical model supplying assumptions and architecture context.
            threat_register: Validated threats from which abuse cases are derived.

        Returns:
            Abuse and misuse cases traceable to the supplied threat register.
        """
        external_actor_ids = [
            actor.id for actor in model.actors if actor.actor_type is ActorType.HUMAN_USER
        ]
        cases = [
            AbuseMisuseCase(
                **self._metadata.item_fields(
                    f"abuse-{threat.id}",
                    f"Abuse case for {threat.name}",
                    threat.description,
                    threat.evidence,
                    threat.confidence,
                    [*model.assumptions, *threat.assumptions],
                ).model_dump(),
                actor_ids=external_actor_ids,
                component_id=threat.component_id,
                data_flow_id=threat.data_flow_id,
                asset_id=threat.asset_id,
                component_ids=threat.component_ids,
                data_flow_ids=threat.data_flow_ids,
                asset_ids=threat.asset_ids,
                preconditions=threat.attack_preconditions
                or ["The referenced architecture element is reachable."],
                steps=[
                    f"Identify a reachable path to {threat.name}.",
                    "Attempt to realize the modeled threat scenario.",
                    f"Observe impact: {threat.impact}",
                ],
                impact=threat.impact,
            )
            for threat in threat_register.threats
        ]
        return AbuseMisuseCases(
            **self._metadata.artifact_fields(
                "abuse-misuse-cases",
                "Abuse and Misuse Cases",
                "Abuse cases derived from the validated STRIDE threat register.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    cases, when_empty=threat_register.confidence
                ),
            ).model_dump(),
            cases=cases,
        )
