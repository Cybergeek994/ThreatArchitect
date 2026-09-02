"""Port for batch LLM semantic ranking of requirements to ASVS controls."""

from typing import Protocol

from threatmodeler.contracts.control_catalog import (
    AsvsCompactControlRef,
    BatchControlMappingRankResult,
    RequirementMappingNeed,
)


class AsvsSemanticRanker(Protocol):
    """Rank security requirements against an ASVS compact control index."""

    def rank_all(
        self,
        requirements: tuple[RequirementMappingNeed, ...],
        compact_index: tuple[AsvsCompactControlRef, ...],
        *,
        alternates_per_requirement: int = 2,
    ) -> BatchControlMappingRankResult:
        """Map every requirement to ranked ASVS controls in one batch call."""
        ...
