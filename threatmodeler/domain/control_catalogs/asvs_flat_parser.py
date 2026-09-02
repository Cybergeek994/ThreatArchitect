"""Parse OWASP ASVS flat JSON into normalized control records."""

from __future__ import annotations

from datetime import UTC, datetime

from threatmodeler.contracts.control_catalog import (
    AsvsControlCatalogSnapshot,
    AsvsFlatDocument,
    CatalogProvenance,
    ControlRecord,
)
from threatmodeler.errors import ConfigurationError
from threatmodeler.shared.constants import AsvsFrameworkVersion


def normalize_req_id(req_id: str) -> str:
    """Strip a leading ``V`` prefix from a flat requirement identifier."""
    trimmed = req_id.strip()
    if trimmed.upper().startswith("V") and len(trimmed) > 1:
        return trimmed[1:]
    return trimmed


def canonical_control_id(req_id: str, *, framework_version: str) -> str:
    """Build the canonical catalog identifier for one flat requirement row."""
    return f"v{framework_version}-{normalize_req_id(req_id)}"


def parse_flat_document(
    document: AsvsFlatDocument,
    *,
    framework_version: str = AsvsFrameworkVersion.V5_0_0,
    source_uri: str,
) -> AsvsControlCatalogSnapshot:
    """Normalize a flat ASVS export into an immutable catalog snapshot.

    Args:
        document: Parsed flat JSON document.
        framework_version: ASVS release version embedded in control ids.
        source_uri: Provenance URI describing where the flat export originated.

    Returns:
        Snapshot with provenance and normalized control records.

    Raises:
        ConfigurationError: If the document contains no requirements.
    """
    controls: list[ControlRecord] = []
    for row in document.requirements:
        short_id = normalize_req_id(row.req_id)
        try:
            level = int(row.level)
        except ValueError as error:
            raise ConfigurationError(
                f"Invalid ASVS level for requirement {row.req_id}",
                error_code="ASVS_FLAT_LEVEL_INVALID",
                retryable=False,
                context={"req_id": row.req_id, "level": row.level},
            ) from error
        controls.append(
            ControlRecord(
                id=canonical_control_id(row.req_id, framework_version=framework_version),
                short_id=short_id,
                chapter_id=row.chapter_id,
                chapter_name=row.chapter_name,
                section_id=row.section_id,
                section_name=row.section_name,
                level=level,
                requirement_text=row.req_description,
            )
        )
    if not controls:
        raise ConfigurationError(
            "ASVS flat document must contain at least one requirement",
            error_code="ASVS_FLAT_EMPTY",
            retryable=False,
            context={},
        )
    return AsvsControlCatalogSnapshot(
        provenance=CatalogProvenance(
            framework_version=framework_version,
            source_uri=source_uri,
            fetched_at=datetime.now(tz=UTC).isoformat(),
            control_count=len(controls),
        ),
        controls=tuple(controls),
    )
