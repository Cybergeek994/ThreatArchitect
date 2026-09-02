"""Pydantic contracts for OWASP ASVS control catalog snapshots."""

from typing import Annotated

from pydantic import AliasChoices, Field, JsonValue

from threatmodeler.contracts.base import ContractModel


class AsvsFlatRequirement(ContractModel):
    """One requirement row from the official ASVS flat JSON export."""

    chapter_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_name: Annotated[str, Field(strict=True, min_length=1)]
    section_id: Annotated[str, Field(strict=True, min_length=1)]
    section_name: Annotated[str, Field(strict=True, min_length=1)]
    req_id: Annotated[str, Field(strict=True, min_length=1)]
    req_description: Annotated[str, Field(strict=True, min_length=1)]
    level: Annotated[str, Field(strict=True, min_length=1, validation_alias=AliasChoices("L", "level"))]


class AsvsFlatDocument(ContractModel):
    """Root document for the official ASVS flat JSON export."""

    requirements: tuple[AsvsFlatRequirement, ...]


class ControlRecord(ContractModel):
    """Normalized ASVS control used for retrieval, prompts, and validation."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    short_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_name: Annotated[str, Field(strict=True, min_length=1)]
    section_id: Annotated[str, Field(strict=True, min_length=1)]
    section_name: Annotated[str, Field(strict=True, min_length=1)]
    level: Annotated[int, Field(strict=True, ge=1, le=3)]
    requirement_text: Annotated[str, Field(strict=True, min_length=1)]


class CatalogProvenance(ContractModel):
    """Describes where a loaded control catalog snapshot originated."""

    framework_version: Annotated[str, Field(strict=True, min_length=1)]
    source_uri: Annotated[str, Field(strict=True, min_length=1)]
    fetched_at: Annotated[str, Field(strict=True, min_length=1)]
    control_count: Annotated[int, Field(strict=True, ge=1)]


class AsvsControlCatalogSnapshot(ContractModel):
    """Immutable OWASP ASVS catalog snapshot with provenance metadata."""

    provenance: CatalogProvenance
    controls: tuple[ControlRecord, ...]


class ControlCandidatePayload(ContractModel):
    """Prompt-safe representation of one catalog control candidate."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    short_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_name: Annotated[str, Field(strict=True, min_length=1)]
    level: Annotated[int, Field(strict=True, ge=1, le=3)]
    requirement_text: Annotated[str, Field(strict=True, min_length=1)]

    @classmethod
    def from_record(cls, record: ControlRecord) -> ControlCandidatePayload:
        """Build a candidate payload from a normalized control record."""
        return cls(
            id=record.id,
            short_id=record.short_id,
            chapter_id=record.chapter_id,
            chapter_name=record.chapter_name,
            level=record.level,
            requirement_text=record.requirement_text,
        )


class CatalogProvenancePayload(ContractModel):
    """Agent-input provenance block for control-mapping generation."""

    framework: Annotated[str, Field(strict=True, min_length=1)]
    version: Annotated[str, Field(strict=True, min_length=1)]
    source_uri: Annotated[str, Field(strict=True, min_length=1)]
    fetched_at: Annotated[str, Field(strict=True, min_length=1)]
    control_count: Annotated[int, Field(strict=True, ge=1)]

    @classmethod
    def from_snapshot(cls, snapshot: AsvsControlCatalogSnapshot, *, framework: str) -> CatalogProvenancePayload:
        """Build an agent payload block from catalog provenance."""
        provenance = snapshot.provenance
        return cls(
            framework=framework,
            version=provenance.framework_version,
            source_uri=provenance.source_uri,
            fetched_at=provenance.fetched_at,
            control_count=provenance.control_count,
        )


def control_record_to_json(record: ControlRecord) -> dict[str, JsonValue]:
    """Serialize one control record for agent payloads."""
    return record.model_dump(mode="json")


class AsvsCompactControlRef(ContractModel):
    """Compact catalog row for LLM batch ranking prompts."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    short_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_id: Annotated[str, Field(strict=True, min_length=1)]
    chapter_name: Annotated[str, Field(strict=True, min_length=1)]
    section_id: Annotated[str, Field(strict=True, min_length=1)]
    section_name: Annotated[str, Field(strict=True, min_length=1)]
    level: Annotated[int, Field(strict=True, ge=1, le=3)]
    summary: Annotated[str, Field(strict=True, min_length=1)]


class RequirementMappingNeed(ContractModel):
    """One security requirement prepared for batch ASVS ranking."""

    requirement_id: Annotated[str, Field(strict=True, min_length=1)]
    implementation_need: Annotated[str, Field(strict=True, min_length=1)]
    category: Annotated[str, Field(strict=True, min_length=1)]


class RankedControlCandidate(ContractModel):
    """One ranked ASVS control candidate for a requirement."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    short_id: Annotated[str, Field(strict=True, min_length=1)]
    rank: Annotated[int, Field(strict=True, ge=1)]
    confidence: Annotated[str, Field(strict=True, min_length=1)]
    rationale: Annotated[str, Field(strict=True, min_length=1)]


class RequirementRankedCandidates(ContractModel):
    """Pre-ranked ASVS controls for one security requirement."""

    requirement_id: Annotated[str, Field(strict=True, min_length=1)]
    implementation_need: Annotated[str, Field(strict=True, min_length=1)]
    candidates: tuple[RankedControlCandidate, ...]


class BatchControlMappingRankResult(ContractModel):
    """Batch ranking output mapping requirements to ASVS controls."""

    mappings: tuple[RequirementRankedCandidates, ...]
