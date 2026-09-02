"""Validate control-mapping items against pre-ranked ASVS candidates."""

from __future__ import annotations

from pydantic import JsonValue

from threatmodeler.ports.artifact_construction_session_factory import ItemValidator


class ControlMappingCandidateMembershipValidator:
    """Reject controls whose framework id was not pre-ranked for linked requirements."""

    def __init__(
        self,
        allowed_control_ids_by_requirement: dict[str, set[str]],
    ) -> None:
        self._allowed_control_ids_by_requirement = allowed_control_ids_by_requirement

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: dict[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        del lists
        if list_field != "controls":
            return []
        framework_control_id = payload.get("framework_control_id")
        requirement_ids = payload.get("requirement_ids")
        if not isinstance(framework_control_id, str):
            return ["framework_control_id must be a string"]
        if not isinstance(requirement_ids, list) or not requirement_ids:
            return ["requirement_ids must list at least one linked requirement"]
        violations: list[str] = []
        for requirement_id in requirement_ids:
            if not isinstance(requirement_id, str):
                violations.append("requirement_ids must contain strings")
                continue
            allowed = self._allowed_control_ids_by_requirement.get(requirement_id)
            if allowed is None:
                violations.append(
                    f"Requirement {requirement_id} was not included in pre-ranked candidates"
                )
                continue
            if framework_control_id not in allowed:
                violations.append(
                    "framework_control_id "
                    f"{framework_control_id} is not an allowed candidate for {requirement_id}"
                )
        return violations


def build_candidate_membership_validator(
    allowed_control_ids_by_requirement: dict[str, set[str]],
) -> ItemValidator:
    """Build a candidate-membership validator for construction sessions."""
    return ControlMappingCandidateMembershipValidator(allowed_control_ids_by_requirement)
