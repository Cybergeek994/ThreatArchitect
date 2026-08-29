"""Harvest and validate cross-artifact identifier references."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, JsonValue

from threatmodeler.contracts.artifacts import (
    AbuseMisuseCases,
    AttackTree,
    ControlMapping,
    ExecutiveSummary,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideThreatRegister,
    TechnicalThreatModelReport,
)
from threatmodeler.contracts.artifacts.architecture import TrustBoundaryMap
from threatmodeler.contracts.artifacts.base import ThreatLinkedItem
from threatmodeler.contracts.artifacts.inventories import ActorModel, AssetInventory
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.contracts.schema_introspection import reference_fields_for_models

_REFERENCE_MODELS: tuple[type[BaseModel], ...] = (
    CanonicalSystemModel,
    ThreatLinkedItem,
    StrideThreatRegister,
    AttackTree,
    AbuseMisuseCases,
    RiskRegister,
    MitigationPlan,
    SecurityRequirements,
    ControlMapping,
    ExecutiveSummary,
    TechnicalThreatModelReport,
    TrustBoundaryMap,
    ActorModel,
    AssetInventory,
)

_REFERENCE_FIELDS = reference_fields_for_models(*_REFERENCE_MODELS)


def collect_known_ids(payload: JsonValue) -> set[str]:
    """Collect every string value stored under an ``id`` key in ``payload``.

    Args:
        payload: Nested JSON-compatible structure (typically an agent input payload).

    Returns:
        Set of non-empty string ids discovered at any depth.
    """
    found: set[str] = set()
    _walk(payload, found)
    return found


def _walk(value: JsonValue, found: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "id" and isinstance(child, str) and child:
                found.add(child)
            else:
                _walk(child, found)
        return
    if isinstance(value, list):
        for child in value:
            _walk(child, found)


class KnownIdReferenceChecker:
    """Validate that item reference fields point at known upstream or session ids."""

    def __init__(self, known_ids: set[str]) -> None:
        self._known_ids = set(known_ids)

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        existing_lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        """Return violations for unknown reference field values.

        Args:
            list_field: Target list field for the add_* tool.
            payload: Parsed item payload about to be appended or replaced.
            existing_lists: Accumulated list payloads accepted so far in this session.

        Returns:
            Human-readable violations. An empty list means the item may be accepted.
        """
        del list_field
        allowed = set(self._known_ids)
        for items in existing_lists.values():
            for item in items:
                item_id = item.get("id")
                if isinstance(item_id, str) and item_id:
                    allowed.add(item_id)
        known_label = _format_known(allowed)
        item_id = payload.get("id")
        item_label = item_id if isinstance(item_id, str) else "item"
        violations: list[str] = []
        for field_name, raw_value in payload.items():
            if field_name not in _REFERENCE_FIELDS:
                continue
            values = _as_id_values(raw_value)
            for referenced in values:
                if referenced not in allowed:
                    violations.append(
                        f"{item_label} references unknown {field_name} '{referenced}'. "
                        f"Known ids: {known_label}."
                    )
        return violations


def discovered_reference_fields() -> frozenset[str]:
    """Return the schema-discovered set of reference field names."""
    return _REFERENCE_FIELDS


def _as_id_values(raw_value: JsonValue) -> list[str]:
    if isinstance(raw_value, str) and raw_value:
        return [raw_value]
    if isinstance(raw_value, list):
        return [item for item in raw_value if isinstance(item, str) and item]
    return []


def _format_known(ids: set[str], *, limit: int = 12) -> str:
    if not ids:
        return "(none yet)"
    ordered = sorted(ids)
    if len(ordered) <= limit:
        return ", ".join(ordered)
    visible = ", ".join(ordered[:limit])
    return f"{visible}, ... ({len(ordered)} total)"
