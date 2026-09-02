"""Batch LLM semantic ranking of security requirements to ASVS controls."""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field, JsonValue, ValidationError

from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.contracts.control_catalog import (
    AsvsCompactControlRef,
    BatchControlMappingRankResult,
    RankedControlCandidate,
    RequirementMappingNeed,
    RequirementRankedCandidates,
)
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.ports.agent_provider import AgentProvider


class _LlmRankedMapping(ContractModel):
    """One requirement mapping returned by the batch ranker LLM."""

    requirement_id: Annotated[str, Field(strict=True, min_length=1)]
    control_id: Annotated[str, Field(strict=True, min_length=1)]
    alternates: tuple[str, ...] = ()
    confidence: Annotated[str, Field(strict=True, min_length=1)]
    rationale: Annotated[str, Field(strict=True, min_length=1)]


class _LlmBatchRankResponse(ContractModel):
    """Batch ranker LLM response envelope."""

    mappings: tuple[_LlmRankedMapping, ...]


class LlmAsvsSemanticRanker:
    """Map every requirement to ASVS controls through one inner LLM call."""

    TASK_NAME = "rank_asvs_control_candidates"

    def __init__(
        self,
        agent_provider: AgentProvider,
        registry: AsvsControlRegistry,
        *,
        max_attempts: int = 2,
    ) -> None:
        self._agent_provider = agent_provider
        self._registry = registry
        self._max_attempts = max(1, max_attempts)

    def rank_all(
        self,
        requirements: tuple[RequirementMappingNeed, ...],
        compact_index: tuple[AsvsCompactControlRef, ...],
        *,
        alternates_per_requirement: int = 2,
    ) -> BatchControlMappingRankResult:
        """Rank all requirements against the compact ASVS index."""
        if not requirements:
            return BatchControlMappingRankResult(mappings=())
        last_error: AgentProviderError | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = self._agent_provider.complete(
                    AgentRequest(
                        task_name=self.TASK_NAME,
                        instructions=_build_instructions(alternates_per_requirement),
                        messages=[],
                        input_payload={
                            "security_requirements": [
                                requirement.model_dump(mode="json") for requirement in requirements
                            ],
                            "control_index": [
                                control.model_dump(mode="json") for control in compact_index
                            ],
                        },
                        expected_schema_name=_LlmBatchRankResponse.__name__,
                        temperature=0.0,
                        max_output_tokens=8_000,
                    )
                )
                return self._validate_response(
                    response.output_payload,
                    requirements=requirements,
                    alternates_per_requirement=alternates_per_requirement,
                )
            except AgentProviderError as error:
                last_error = error
                if attempt >= self._max_attempts:
                    raise
        raise last_error  # pragma: no cover

    def _validate_response(
        self,
        output_payload: dict[str, JsonValue] | str,
        *,
        requirements: tuple[RequirementMappingNeed, ...],
        alternates_per_requirement: int,
    ) -> BatchControlMappingRankResult:
        if isinstance(output_payload, str):
            try:
                parsed_payload = json.loads(output_payload)
            except json.JSONDecodeError as error:
                raise AgentProviderError(
                    "Batch ASVS ranker returned non-JSON text",
                    error_code="ASVS_BATCH_RANK_INVALID_JSON",
                    retryable=True,
                    context={},
                ) from error
            if not isinstance(parsed_payload, dict):
                raise AgentProviderError(
                    "Batch ASVS ranker JSON root must be an object",
                    error_code="ASVS_BATCH_RANK_INVALID_JSON",
                    retryable=True,
                    context={},
                )
            output_payload = parsed_payload
        try:
            parsed = _LlmBatchRankResponse.model_validate(output_payload)
        except ValidationError as error:
            raise AgentProviderError(
                "Batch ASVS ranker output failed schema validation",
                error_code="ASVS_BATCH_RANK_SCHEMA_INVALID",
                retryable=True,
                context={"validation_errors": error.errors(include_url=False, include_input=False)},
            ) from error
        expected_ids = {requirement.requirement_id for requirement in requirements}
        actual_ids = {mapping.requirement_id for mapping in parsed.mappings}
        if expected_ids != actual_ids:
            raise AgentProviderError(
                "Batch ASVS ranker omitted or duplicated requirement ids",
                error_code="ASVS_BATCH_RANK_REQUIREMENT_MISMATCH",
                retryable=True,
                context={
                    "expected": sorted(expected_ids),
                    "actual": sorted(actual_ids),
                },
            )
        needs_by_id = {requirement.requirement_id: requirement for requirement in requirements}
        ranked: list[RequirementRankedCandidates] = []
        for mapping in parsed.mappings:
            need = needs_by_id[mapping.requirement_id]
            candidate_ids = [mapping.control_id, *mapping.alternates[:alternates_per_requirement]]
            candidates: list[RankedControlCandidate] = []
            for rank, control_id in enumerate(candidate_ids, start=1):
                canonical_id = self._registry.resolve_id(control_id)
                if canonical_id is None:
                    raise AgentProviderError(
                        "Batch ASVS ranker returned unknown control id",
                        error_code="ASVS_BATCH_RANK_UNKNOWN_CONTROL",
                        retryable=True,
                        context={"control_id": control_id, "requirement_id": mapping.requirement_id},
                    )
                record = self._registry.get(canonical_id)
                assert record is not None
                candidates.append(
                    RankedControlCandidate(
                        id=record.id,
                        short_id=record.short_id,
                        rank=rank,
                        confidence=mapping.confidence if rank == 1 else "alternate",
                        rationale=mapping.rationale,
                    )
                )
            ranked.append(
                RequirementRankedCandidates(
                    requirement_id=need.requirement_id,
                    implementation_need=need.implementation_need,
                    candidates=tuple(candidates),
                )
            )
        return BatchControlMappingRankResult(mappings=tuple(ranked))


def _build_instructions(alternates_per_requirement: int) -> str:
    return (
        "Map each SECURITY_REQUIREMENT in the input payload to the best ASVS 5.0 control "
        "from CONTROL_INDEX. Return one primary control_id per requirement_id and up to "
        f"{alternates_per_requirement} alternates. Use semantic understanding. "
        "Use ONLY ids from CONTROL_INDEX."
    )
