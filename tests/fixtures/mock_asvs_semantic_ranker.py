"""Test double for batch ASVS semantic ranking."""

from __future__ import annotations

from threatmodeler.contracts.control_catalog import (
    AsvsCompactControlRef,
    BatchControlMappingRankResult,
    RankedControlCandidate,
    RequirementMappingNeed,
    RequirementRankedCandidates,
)
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.domain.control_mapping import ControlMappingService
from threatmodeler.infrastructure.control_catalogs.asvs_control_registry_factory import (
    AsvsControlRegistryFactory,
)


class MockAsvsSemanticRanker:
    """Return fixed primary candidates for each requirement in local tests."""

    def __init__(
        self,
        registry: AsvsControlRegistry,
        *,
        primary_control_id: str | None = None,
    ) -> None:
        self._registry = registry
        default_control = registry.all_controls()[0]
        self._primary_control_id = primary_control_id or default_control.id

    def rank_all(
        self,
        requirements: tuple[RequirementMappingNeed, ...],
        compact_index: tuple[AsvsCompactControlRef, ...],
        *,
        alternates_per_requirement: int = 2,
    ) -> BatchControlMappingRankResult:
        del compact_index, alternates_per_requirement
        mappings: list[RequirementRankedCandidates] = []
        record = self._registry.get(self._primary_control_id)
        if record is None:
            record = self._registry.all_controls()[0]
        for requirement in requirements:
            mappings.append(
                RequirementRankedCandidates(
                    requirement_id=requirement.requirement_id,
                    implementation_need=requirement.implementation_need,
                    candidates=(
                        RankedControlCandidate(
                            id=record.id,
                            short_id=record.short_id,
                            rank=1,
                            confidence="high",
                            rationale="Mock ASVS ranker selected a primary candidate.",
                        ),
                    ),
                )
            )
        return BatchControlMappingRankResult(mappings=tuple(mappings))


def create_mock_control_mapping_service(metadata: ArtifactMetadataService) -> ControlMappingService:
    """Build a control-mapping service backed by the test ASVS ranker double."""
    registry = AsvsControlRegistryFactory.packaged().create()
    return ControlMappingService(
        metadata,
        MockAsvsSemanticRanker(registry),
        registry=registry,
    )
