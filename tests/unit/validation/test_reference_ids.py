"""Tests for cross-artifact known-id reference validation."""

from pydantic import JsonValue
from threatmodeler.validation.reference_ids import (
    KnownIdReferenceChecker,
    _format_known,
    collect_known_ids,
    discovered_reference_fields,
)


class TestCollectKnownIdsPositive:
    """Verify recursive id harvesting from nested payloads."""

    def test_collects_nested_ids(self) -> None:
        payload: dict[str, JsonValue] = {
            "system_model": {
                "application": {"id": "app-1"},
                "components": [{"id": "c1"}, {"id": "c2"}],
            },
            "stride_threat_register": {"threats": [{"id": "t1", "component_id": "c1"}]},
        }
        assert collect_known_ids(payload) == {"app-1", "c1", "c2", "t1"}


class TestKnownIdReferenceCheckerPositive:
    """Verify known references are accepted."""

    def test_known_component_id_passes(self) -> None:
        checker = KnownIdReferenceChecker({"c1"})
        assert checker("threats", {"id": "t1", "component_id": "c1"}, {"threats": []}) == []


class TestKnownIdReferenceCheckerNegative:
    """Verify unknown references are rejected."""

    def test_unknown_component_id_is_rejected(self) -> None:
        checker = KnownIdReferenceChecker({"c1"})
        violations = checker(
            "threats",
            {"id": "t1", "component_id": "missing"},
            {"threats": []},
        )
        assert any("unknown component_id" in violation for violation in violations)

    def test_session_ids_are_also_allowed(self) -> None:
        checker = KnownIdReferenceChecker(set())
        assert (
            checker(
                "threats",
                {"id": "t2", "component_id": "c-local"},
                {"threats": [{"id": "c-local"}]},
            )
            == []
        )

    def test_discovered_fields_include_report_and_flow_refs(self) -> None:
        fields = discovered_reference_fields()

        assert "top_risk_ids" in fields
        assert "source_component_id" in fields
        assert "referenced_artifact_ids" in fields
        assert "actor_id" in fields
        assert "threat_ids" in fields

    def test_framework_control_id_is_not_validated_as_artifact_reference(self) -> None:
        checker = KnownIdReferenceChecker({"req-auth"})
        violations = checker(
            "controls",
            {
                "id": "control-1",
                "framework_control_id": "v5.0.0-10.3.5",
                "requirement_ids": ["req-auth"],
            },
            {"controls": []},
        )

        assert violations == []

    def test_unknown_top_risk_id_is_rejected(self) -> None:
        checker = KnownIdReferenceChecker({"risk-1"})
        violations = checker(
            "summaries",
            {"id": "sum-1", "top_risk_ids": ["missing-risk"]},
            {"summaries": []},
        )
        assert any("unknown top_risk_ids" in violation for violation in violations)


    def test_reference_ids_formatting_and_list_values(self) -> None:
        assert _format_known(set()) == "(none yet)"
        many = {f"id-{index}" for index in range(15)}
        assert "... (15 total)" in _format_known(many)
        checker = KnownIdReferenceChecker(set())
        assert checker("items", {"tags": ["a", 1, ""]}, {"items": []}) == []

    def test_reference_ids_list_coercion(self) -> None:
        from threatmodeler.validation.reference_ids import _as_id_values

        assert _as_id_values(["a", 1, None]) == ["a"]
        checker = KnownIdReferenceChecker({"known"})
        assert (
            checker(
                "items",
                {"id": "item-1", "related_ids": ["known"]},
                {"items": [{"id": "known"}]},
            )
            == []
        )

    def test_reference_ids_as_id_values_list_branch(self) -> None:
        from threatmodeler.validation.reference_ids import _as_id_values

        assert _as_id_values(["a", "", 1, "b"]) == ["a", "b"]
        assert _as_id_values(123) == []

    def test_known_id_checker_skips_non_string_session_ids(self) -> None:
        checker = KnownIdReferenceChecker(set())
        assert (
            checker(
                "items",
                {"component_id": "known"},
                {"items": [{"id": 123}, {"id": "known"}]},
            )
            == []
        )
