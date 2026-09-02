"""Tests for control-mapping candidate membership validation."""

from threatmodeler.validation.control_mapping_candidate_validator import (
    ControlMappingCandidateMembershipValidator,
    build_candidate_membership_validator,
)


class TestCandidateMembershipValidator:
    """Verify per-item candidate membership checks."""

    def test_ignores_non_control_lists(self) -> None:
        validator = build_candidate_membership_validator({})
        assert validator("requirements", {}, {}) == []

    def test_requires_string_framework_control_id(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator("controls", {"requirement_ids": ["req-1"]}, {})
        assert "framework_control_id must be a string" in violations

    def test_requires_linked_requirement_ids(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator(
            "controls",
            {"framework_control_id": "v5.0.0-2.2.1", "requirement_ids": []},
            {},
        )
        assert "requirement_ids must list at least one linked requirement" in violations

    def test_rejects_non_string_requirement_ids(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator(
            "controls",
            {"framework_control_id": "v5.0.0-2.2.1", "requirement_ids": [1]},
            {},
        )
        assert "requirement_ids must contain strings" in violations

    def test_class_validator_matches_factory(self) -> None:
        allowed = {"req-1": {"v5.0.0-2.2.1"}}
        factory_validator = build_candidate_membership_validator(allowed)
        class_validator = ControlMappingCandidateMembershipValidator(allowed)
        payload = {"framework_control_id": "v5.0.0-2.2.1", "requirement_ids": ["req-1"]}

        assert factory_validator("controls", payload, {}) == class_validator("controls", payload, {})

    def test_rejects_requirement_missing_from_pre_ranked_set(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator(
            "controls",
            {"framework_control_id": "v5.0.0-2.2.1", "requirement_ids": ["req-2"]},
            {},
        )
        assert any("was not included in pre-ranked candidates" in item for item in violations)
