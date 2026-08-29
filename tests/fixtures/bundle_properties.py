"""Cross-artifact property checks for artifact bundles in tests."""

from __future__ import annotations

from pydantic import JsonValue

from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.validation.reference_ids import _as_id_values, collect_known_ids

_BUNDLE_ENTITY_REFERENCE_FIELDS = frozenset(
    {
        "actor_id",
        "actor_ids",
        "affected_component_ids",
        "asset_id",
        "asset_ids",
        "component_id",
        "component_ids",
        "control_ids",
        "data_flow_id",
        "data_flow_ids",
        "data_store_ids",
        "destination_component_id",
        "related_component_ids",
        "related_entry_point_id",
        "requirement_ids",
        "risk_ids",
        "source_component_id",
        "threat_ids",
        "top_risk_ids",
        "trust_level_ids",
        "unassigned_component_ids",
    }
)
_ARTIFACT_REFERENCE_FIELD = "referenced_artifact_ids"
_COMPONENT_PLACEMENTS_FIELD = "component_placements"
_SKIPPED_REFERENCE_FIELDS = frozenset({"artifact_id", "source_id", "framework_control_id"})


def collect_bundle_known_ids(
    bundle: ArtifactBundle,
    *,
    system_model: CanonicalSystemModel | None = None,
) -> set[str]:
    """Collect entity ids referenced during bundle property validation."""
    known = collect_known_ids(bundle.model_dump(mode="json"))
    if system_model is not None:
        known.update(collect_known_ids(system_model.model_dump(mode="json")))
    return known


def collect_bundle_artifact_ids(bundle: ArtifactBundle) -> set[str]:
    """Collect every ``artifact_id`` declared on bundle members."""
    ids: set[str] = set()
    if bundle.artifact_id:
        ids.add(bundle.artifact_id)
    for field_name in ArtifactBundle.model_fields:
        nested = getattr(bundle, field_name)
        artifact_id = getattr(nested, "artifact_id", None)
        if isinstance(artifact_id, str) and artifact_id:
            ids.add(artifact_id)
    return ids


def bundle_property_violations(
    bundle: ArtifactBundle,
    *,
    system_model: CanonicalSystemModel | None = None,
) -> list[str]:
    """Return human-readable violations for broken cross-artifact properties."""
    violations: list[str] = []
    violations.extend(_linkage_property_violations(bundle))
    violations.extend(_reference_integrity_violations(bundle, system_model=system_model))
    return violations


def assert_bundle_integrity(
    bundle: ArtifactBundle,
    *,
    system_model: CanonicalSystemModel | None = None,
) -> None:
    """Assert cross-artifact linkage and reference properties hold for ``bundle``."""
    violations = bundle_property_violations(bundle, system_model=system_model)
    assert not violations, "Bundle integrity violations:\n" + "\n".join(violations)


def _linkage_property_violations(bundle: ArtifactBundle) -> list[str]:
    violations: list[str] = []
    for risk in bundle.risk_register.risks:
        if not risk.threat_ids:
            violations.append(f"Risk {risk.id} must reference at least one threat_id")
    for mitigation in bundle.mitigation_plan.mitigations:
        if not mitigation.risk_ids and not mitigation.threat_ids:
            violations.append(
                f"Mitigation {mitigation.id} must reference risk_ids and/or threat_ids"
            )
    for requirement in bundle.security_requirements.requirements:
        if not requirement.component_ids and not requirement.threat_ids:
            violations.append(
                f"Security requirement {requirement.id} must reference "
                "component_ids and/or threat_ids"
            )
    for control in bundle.control_mapping.controls:
        if not control.threat_ids and not control.risk_ids and not control.requirement_ids:
            violations.append(
                f"Control mapping {control.id} must reference threat_ids, "
                "risk_ids, and/or requirement_ids"
            )
    return violations


def _reference_integrity_violations(
    bundle: ArtifactBundle,
    *,
    system_model: CanonicalSystemModel | None,
) -> list[str]:
    known_ids = collect_bundle_known_ids(bundle, system_model=system_model)
    artifact_ids = collect_bundle_artifact_ids(bundle)
    violations: list[str] = []
    _walk_reference_values(
        bundle.model_dump(mode="json"),
        known_ids,
        artifact_ids,
        violations,
        context="bundle",
    )
    return violations


def _walk_reference_values(
    value: JsonValue,
    known_ids: set[str],
    artifact_ids: set[str],
    violations: list[str],
    *,
    context: str,
) -> None:
    if isinstance(value, dict):
        for field_name, raw_value in value.items():
            if field_name in _SKIPPED_REFERENCE_FIELDS:
                _walk_reference_values(
                    raw_value,
                    known_ids,
                    artifact_ids,
                    violations,
                    context=context,
                )
                continue
            if field_name == _COMPONENT_PLACEMENTS_FIELD and isinstance(raw_value, dict):
                for component_id in raw_value:
                    if isinstance(component_id, str) and component_id not in known_ids:
                        violations.append(
                            f"{context} references unknown component_placements key "
                            f"'{component_id}'"
                        )
            elif field_name == _ARTIFACT_REFERENCE_FIELD:
                for referenced in _as_id_values(raw_value):
                    if referenced not in artifact_ids:
                        violations.append(
                            f"{context} references unknown referenced_artifact_id "
                            f"'{referenced}'"
                        )
            elif field_name in _BUNDLE_ENTITY_REFERENCE_FIELDS:
                for referenced in _as_id_values(raw_value):
                    if referenced not in known_ids:
                        violations.append(
                            f"{context} references unknown {field_name} '{referenced}'"
                        )
            _walk_reference_values(
                raw_value,
                known_ids,
                artifact_ids,
                violations,
                context=context,
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_reference_values(
                item,
                known_ids,
                artifact_ids,
                violations,
                context=f"{context}[{index}]",
            )
