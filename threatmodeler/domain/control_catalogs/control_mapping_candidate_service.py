"""Prepare pre-ranked ASVS control candidates for control-mapping generation."""

from __future__ import annotations

from pydantic import JsonValue

from threatmodeler.contracts.artifacts import (
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideThreatRegister,
)
from threatmodeler.contracts.control_catalog import (
    AsvsCompactControlRef,
    CatalogProvenancePayload,
    RequirementMappingNeed,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.control_catalogs.asvs_compact_index import AsvsCompactIndexBuilder
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.ports.asvs_semantic_ranker import AsvsSemanticRanker
from threatmodeler.shared.constants import ControlFrameworkName


class ControlMappingCandidateService:
    """Batch-rank ASVS controls before the control-mapping agent runs."""

    def __init__(
        self,
        registry: AsvsControlRegistry,
        ranker: AsvsSemanticRanker,
        *,
        compact_index_builder: AsvsCompactIndexBuilder | None = None,
        alternates_per_requirement: int = 2,
    ) -> None:
        self._registry = registry
        self._ranker = ranker
        self._compact_index_builder = compact_index_builder or AsvsCompactIndexBuilder()
        self._compact_index = self._compact_index_builder.build(registry.snapshot)
        self._alternates_per_requirement = alternates_per_requirement

    @property
    def registry(self) -> AsvsControlRegistry:
        """Return the ASVS registry backing candidate validation."""
        return self._registry

    @property
    def compact_index(self) -> tuple[AsvsCompactControlRef, ...]:
        """Return the compact control index used for batch ranking."""
        return self._compact_index

    def rank_all(
        self,
        model: CanonicalSystemModel,
        requirements: SecurityRequirements,
        risks: RiskRegister,
        mitigations: MitigationPlan,
        threat_register: StrideThreatRegister,
    ) -> tuple[dict[str, JsonValue], dict[str, JsonValue], dict[str, set[str]]]:
        """Rank controls for every security requirement.

        Returns:
            Tuple of prompt payload fragments: ranked candidates by requirement id,
            catalog provenance, and allowed control ids keyed by requirement id.
        """
        del model, risks, mitigations, threat_register
        needs = self._build_needs(requirements)
        batch = self._ranker.rank_all(
            needs,
            self._compact_index,
            alternates_per_requirement=self._alternates_per_requirement,
        )
        ranked_by_requirement = {
            mapping.requirement_id: mapping.model_dump(mode="json")
            for mapping in batch.mappings
        }
        allowed_ids = {
            mapping.requirement_id: {candidate.id for candidate in mapping.candidates}
            for mapping in batch.mappings
        }
        provenance = CatalogProvenancePayload.from_snapshot(
            self._registry.snapshot,
            framework=ControlFrameworkName.OWASP_ASVS,
        ).model_dump(mode="json")
        return ranked_by_requirement, provenance, allowed_ids

    def _build_needs(
        self,
        requirements: SecurityRequirements,
    ) -> tuple[RequirementMappingNeed, ...]:
        return tuple(
            RequirementMappingNeed(
                requirement_id=requirement.id,
                implementation_need=" ".join(
                    part
                    for part in (
                        requirement.name,
                        requirement.statement,
                        requirement.description,
                    )
                    if part
                ),
                category=requirement.category.value,
            )
            for requirement in requirements.requirements
        )
