"""Tests for canonical system model business validation rules."""

import pytest
from pydantic import BaseModel, JsonValue
from threatmodeler.contracts.system_model import (
    CanonicalSystemModel,
    ExposureType,
    TrustBoundaryType,
)
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.validation.system_model_validator import (
    BoundaryCrossingFlowRule,
    CanonicalSystemModelReferenceChecker,
    CanonicalSystemModelValidator,
    ExternalEntryPointAuthRule,
    ExternalEntryPointBoundaryRule,
    ExternalExposureCoverageRule,
    ReferenceIntegrityRule,
    TrustBoundaryCrossingConsistencyRule,
    TrustBoundaryMembershipRule,
    UniqueEntityIdsRule,
    UnreferencedExtractedItemRule,
    _check_actor_ids,
    _check_flow_endpoint,
    _external_entry_point_auth_violations,
    _format_known_ids,
    _id_cited_in_gap_text,
    production_system_model_rules,
)


class TestSystemModelValidatorPositive:
    """Verify valid models pass business validation."""

    def test_validator_returns_model_when_rules_pass(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        validator = CanonicalSystemModelValidator([UniqueEntityIdsRule(), ReferenceIntegrityRule()])

        validated = validator.validate(canonical_system_model)

        assert validated is canonical_system_model


class TestCanonicalSystemModelReferenceChecker:
    """Verify incremental reference checks during add_* tool calls."""

    def test_data_flow_rejects_unknown_source(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "data_flows",
            {
                "id": "df1",
                "source_component_id": "missing",
                "destination_component_id": "store-1",
            },
            {
                "components": [{"id": "api-1"}],
                "data_stores": [{"id": "store-1"}],
            },
        )
        assert any("unknown source missing" in violation for violation in violations)

    def test_data_flow_rejects_unknown_destination(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "data_flows",
            {
                "id": "df1",
                "source_component_id": "api-1",
                "destination_component_id": "missing",
            },
            {
                "components": [{"id": "api-1"}],
                "data_stores": [{"id": "store-1"}],
            },
        )
        assert any("unknown destination missing" in violation for violation in violations)

    def test_trust_boundary_rejects_unknown_member(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "trust_boundaries",
            {"id": "tb1", "component_ids": ["missing"]},
            {"components": [{"id": "api-1"}]},
        )
        assert any("contains unknown member missing" in violation for violation in violations)

    def test_entry_point_rejects_unknown_component(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "entry_points",
            {"id": "ep1", "component_id": "missing"},
            {"components": [{"id": "api-1"}]},
        )
        assert any("targets unknown component missing" in violation for violation in violations)

    def test_known_references_pass(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        existing: dict[str, list[dict[str, JsonValue]]] = {
            "components": [{"id": "api-1"}],
            "data_stores": [{"id": "store-1"}],
        }
        assert (
            checker(
                "data_flows",
                {
                    "id": "df1",
                    "source_component_id": "api-1",
                    "destination_component_id": "store-1",
                },
                existing,
            )
            == []
        )
        assert (
            checker("trust_boundaries", {"id": "tb1", "component_ids": ["store-1"]}, existing) == []
        )
        assert checker("entry_points", {"id": "ep1", "component_id": "api-1"}, existing) == []

    def test_external_entry_point_with_placeholder_auth_is_rejected(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "entry_points",
            {
                "id": "ep1",
                "component_id": "api-1",
                "exposure": "external",
                "authentication_method": "unknown",
            },
            {"components": [{"id": "api-1"}]},
        )
        assert any("placeholder authentication" in violation for violation in violations)

    def test_entry_point_rejects_unknown_actor_id(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "entry_points",
            {
                "id": "ep1",
                "component_id": "api-1",
                "actor_id": "missing-actor",
                "exposure": "external",
                "authentication_method": "OAuth 2.0",
            },
            {
                "components": [{"id": "api-1"}],
                "actors": [{"id": "actor-1"}],
            },
        )
        assert any("unknown actor missing-actor" in violation for violation in violations)

    def test_data_flow_rejects_unknown_actor_ids(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        violations = checker(
            "data_flows",
            {
                "id": "df1",
                "source_component_id": "api-1",
                "destination_component_id": "store-1",
                "actor_ids": ["missing-sa"],
            },
            {
                "components": [{"id": "api-1"}],
                "data_stores": [{"id": "store-1"}],
                "actors": [{"id": "actor-1"}],
            },
        )
        assert any("unknown actor missing-sa" in violation for violation in violations)


class TestSystemModelValidatorErrors:
    """Verify business rule violations raise schema validation errors."""

    def test_duplicate_entity_ids_are_reported(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        duplicate_component = canonical_system_model.components[0].model_copy(
            update={"id": canonical_system_model.application.id}
        )
        invalid = canonical_system_model.model_copy(
            update={"components": [duplicate_component, *canonical_system_model.components]}
        )

        with pytest.raises(AgentSchemaValidationError) as captured:
            CanonicalSystemModelValidator([UniqueEntityIdsRule()]).validate(invalid)

        assert captured.value.error_code == "CANONICAL_SYSTEM_MODEL_BUSINESS_INVALID"
        context = captured.value.context
        assert context is not None
        violations = context["violations"]
        assert isinstance(violations, list)
        assert "Duplicate entity id" in violations[0]

    def test_reference_integrity_rule_reports_unknown_flow_source(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_flow = canonical_system_model.data_flows[0].model_copy(
            update={"source_component_id": "missing-component"}
        )
        invalid = canonical_system_model.model_copy(update={"data_flows": [broken_flow]})

        violations = ReferenceIntegrityRule().validate(invalid)

        assert any("unknown source" in violation for violation in violations)

    def test_reference_integrity_rule_reports_unknown_flow_destination(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_flow = canonical_system_model.data_flows[0].model_copy(
            update={"destination_component_id": "missing-store"}
        )
        invalid = canonical_system_model.model_copy(update={"data_flows": [broken_flow]})

        violations = ReferenceIntegrityRule().validate(invalid)

        assert any("unknown destination" in violation for violation in violations)

    def test_reference_integrity_rule_reports_unknown_boundary_component(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_boundary = canonical_system_model.trust_boundaries[0].model_copy(
            update={"component_ids": ["missing-component"]}
        )
        invalid = canonical_system_model.model_copy(update={"trust_boundaries": [broken_boundary]})

        violations = ReferenceIntegrityRule().validate(invalid)

        assert any("contains unknown member" in violation for violation in violations)

    def test_reference_integrity_rule_allows_data_store_boundary_members(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        store_id = canonical_system_model.data_stores[0].id
        boundary = canonical_system_model.trust_boundaries[0].model_copy(
            update={
                "component_ids": [
                    *canonical_system_model.trust_boundaries[0].component_ids,
                    store_id,
                ]
            }
        )
        model = canonical_system_model.model_copy(update={"trust_boundaries": [boundary]})

        violations = ReferenceIntegrityRule().validate(model)

        assert violations == []

    def test_reference_integrity_rule_reports_unknown_entry_point_component(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_entry = canonical_system_model.entry_points[0].model_copy(
            update={"component_id": "missing-component"}
        )
        invalid = canonical_system_model.model_copy(update={"entry_points": [broken_entry]})

        violations = ReferenceIntegrityRule().validate(invalid)

        assert any("targets unknown component" in violation for violation in violations)

    def test_external_entry_point_auth_rule_rejects_placeholder(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_entry = canonical_system_model.entry_points[0].model_copy(
            update={"authentication_method": "unknown"}
        )
        invalid = canonical_system_model.model_copy(update={"entry_points": [broken_entry]})

        violations = ExternalEntryPointAuthRule().validate(invalid)

        assert any("placeholder authentication" in violation for violation in violations)

    def test_trust_boundary_membership_rule_requires_external_components(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        invalid = canonical_system_model.model_copy(update={"trust_boundaries": []})

        violations = TrustBoundaryMembershipRule().validate(invalid)

        assert any(
            "Externally exposed component" in violation
            and "not a member of any trust boundary" in violation
            for violation in violations
        )

    def test_trust_boundary_membership_rule_allows_unplaced_internal_components(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        internal_entries = [
            entry.model_copy(update={"exposure": ExposureType.INTERNAL})
            for entry in canonical_system_model.entry_points
        ]
        model = canonical_system_model.model_copy(
            update={"trust_boundaries": [], "entry_points": internal_entries}
        )

        violations = TrustBoundaryMembershipRule().validate(model)

        assert violations == []

    def test_unreferenced_extracted_item_rule_requires_actor_linkage_or_gap(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        unlinked_entries = [
            entry.model_copy(update={"actor_id": None})
            for entry in canonical_system_model.entry_points
        ]
        invalid = canonical_system_model.model_copy(
            update={
                "entry_points": unlinked_entries,
                "data_flows": [
                    flow.model_copy(update={"actor_ids": []})
                    for flow in canonical_system_model.data_flows
                ],
                "missing_information": [],
            }
        )

        violations = UnreferencedExtractedItemRule().validate(invalid)

        assert any(
            "actors" in violation and "missing_information" in violation
            for violation in violations
        )

    def test_unreferenced_extracted_item_rule_accepts_gap_citing_actor_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        actor_ids = [actor.id for actor in canonical_system_model.actors]
        unlinked_entries = [
            entry.model_copy(update={"actor_id": None})
            for entry in canonical_system_model.entry_points
        ]
        gaps = [
            f"No documented entry_points.actor_id or data_flows.actor_ids for `{actor_id}`."
            for actor_id in actor_ids
        ]
        model = canonical_system_model.model_copy(
            update={
                "entry_points": unlinked_entries,
                "data_flows": [
                    flow.model_copy(update={"actor_ids": []})
                    for flow in canonical_system_model.data_flows
                ],
                "missing_information": gaps,
            }
        )

        violations = UnreferencedExtractedItemRule().validate(model)

        assert not any(
            "actors" in violation and "not referenced" in violation for violation in violations
        )

    def test_reference_integrity_rule_rejects_unknown_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken = [
            entry.model_copy(update={"actor_id": "missing-actor"})
            for entry in canonical_system_model.entry_points
        ]
        invalid = canonical_system_model.model_copy(update={"entry_points": broken})

        violations = ReferenceIntegrityRule().validate(invalid)

        assert any("unknown actor missing-actor" in violation for violation in violations)

    def test_boundary_crossing_flow_rule_requires_encryption(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_flow = canonical_system_model.data_flows[0].model_copy(
            update={"encrypted_in_transit": False, "trust_boundary_crossed": True}
        )
        invalid = canonical_system_model.model_copy(update={"data_flows": [broken_flow]})

        violations = BoundaryCrossingFlowRule().validate(invalid)

        assert any("without encryption in transit" in violation for violation in violations)

    def test_unreferenced_extracted_item_rule_requires_component_linkage(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        invalid = canonical_system_model.model_copy(update={"data_flows": [], "entry_points": []})

        violations = UnreferencedExtractedItemRule().validate(invalid)

        assert any(
            "components" in violation and "not referenced" in violation for violation in violations
        )

    def test_unreferenced_extracted_item_rule_requires_data_store_linkage(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        invalid = canonical_system_model.model_copy(
            update={
                "data_flows": [],
                "trust_boundaries": [
                    boundary.model_copy(update={"component_ids": []})
                    for boundary in canonical_system_model.trust_boundaries
                ],
            }
        )

        violations = UnreferencedExtractedItemRule().validate(invalid)

        assert any(
            "data_stores" in violation and "not referenced" in violation for violation in violations
        )

    def test_trust_boundary_crossing_consistency_detects_mismatch(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        # Place source and destination in the same boundary membership set.
        shared_ids = [
            canonical_system_model.components[0].id,
            canonical_system_model.data_stores[0].id,
        ]
        boundaries = [
            boundary.model_copy(update={"component_ids": shared_ids})
            for boundary in canonical_system_model.trust_boundaries
        ]
        flow = canonical_system_model.data_flows[0].model_copy(
            update={"trust_boundary_crossed": True}
        )
        invalid = canonical_system_model.model_copy(
            update={"trust_boundaries": boundaries, "data_flows": [flow]}
        )

        violations = TrustBoundaryCrossingConsistencyRule().validate(invalid)

        assert any("trust_boundary_crossed=true" in violation for violation in violations)

    def test_trust_boundary_crossing_consistency_allows_correct_flags(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        violations = TrustBoundaryCrossingConsistencyRule().validate(canonical_system_model)

        assert violations == []

    def test_external_exposure_coverage_rule_requires_network_boundary(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        boundary = canonical_system_model.trust_boundaries[0].model_copy(
            update={"boundary_type": TrustBoundaryType.IDENTITY}
        )
        invalid = canonical_system_model.model_copy(update={"trust_boundaries": [boundary]})

        violations = ExternalExposureCoverageRule().validate(invalid)

        assert any("network or external" in violation for violation in violations)

    def test_external_entry_point_boundary_rule_requires_external_boundary_membership(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        network_only = [
            boundary
            for boundary in canonical_system_model.trust_boundaries
            if boundary.boundary_type is not TrustBoundaryType.EXTERNAL
        ]
        invalid = canonical_system_model.model_copy(update={"trust_boundaries": network_only})

        violations = ExternalEntryPointBoundaryRule().validate(invalid)

        assert any("not in an external trust boundary" in violation for violation in violations)

    def test_external_entry_point_boundary_rule_allows_overlapping_membership(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        violations = ExternalEntryPointBoundaryRule().validate(canonical_system_model)

        assert violations == []

    def test_production_rules_accept_canonical_fixture(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        validated = CanonicalSystemModelValidator(production_system_model_rules()).validate(
            canonical_system_model
        )

        assert validated is canonical_system_model


class TestSystemModelValidatorBranchCoverage:
    """Cover remaining business-rule and helper branches."""

    def test_reference_integrity_rule_rejects_unknown_flow_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        broken_flow = canonical_system_model.data_flows[0].model_copy(
            update={"actor_ids": ["missing-actor"]}
        )
        invalid = canonical_system_model.model_copy(update={"data_flows": [broken_flow]})
        violations = ReferenceIntegrityRule().validate(invalid)
        assert any("unknown actor missing-actor" in violation for violation in violations)

    def test_unreferenced_rule_skips_items_without_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        actor_without_id = canonical_system_model.actors[0].model_copy(update={"id": ""})
        model = canonical_system_model.model_copy(update={"actors": [actor_without_id]})
        violations = UnreferencedExtractedItemRule().validate(model)
        assert not any("``" in violation for violation in violations)

    def test_crossing_consistency_both_unplaced_endpoints(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        flow = canonical_system_model.data_flows[0].model_copy(
            update={
                "source_component_id": "unplaced-src",
                "destination_component_id": "unplaced-dst",
                "trust_boundary_crossed": False,
            }
        )
        model = canonical_system_model.model_copy(
            update={"trust_boundaries": [], "data_flows": [flow]}
        )
        violations = TrustBoundaryCrossingConsistencyRule().validate(model)
        assert violations == []

    def test_crossing_consistency_flags_false_when_actually_crossing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        source_id = canonical_system_model.components[0].id
        dest_id = canonical_system_model.data_stores[0].id
        boundaries = [
            boundary.model_copy(update={"component_ids": [source_id]})
            for boundary in canonical_system_model.trust_boundaries
        ]
        flow = canonical_system_model.data_flows[0].model_copy(
            update={
                "source_component_id": source_id,
                "destination_component_id": dest_id,
                "trust_boundary_crossed": False,
            }
        )
        invalid = canonical_system_model.model_copy(
            update={"trust_boundaries": boundaries, "data_flows": [flow]}
        )
        violations = TrustBoundaryCrossingConsistencyRule().validate(invalid)
        assert any("trust_boundary_crossed=false" in violation for violation in violations)

    def test_reference_checker_trust_boundary_and_entry_point_paths(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        boundary_violations = checker(
            "trust_boundaries",
            {"id": "tb1", "component_ids": ["missing-member"]},
            {"components": [{"id": "api-1"}], "data_stores": []},
        )
        assert any("unknown member missing-member" in item for item in boundary_violations)

        entry_violations = checker(
            "entry_points",
            {
                "id": "ep1",
                "component_id": "api-1",
                "exposure": ExposureType.EXTERNAL.value,
                "authentication_method": 123,
            },
            {"components": [{"id": "api-1"}], "actors": []},
        )
        assert entry_violations == []

    def test_helper_formatting_and_gap_matching(self) -> None:
        many_ids = {f"id-{index}" for index in range(15)}
        formatted = _format_known_ids(many_ids)
        assert "... (15 total)" in formatted
        assert _check_flow_endpoint(None, role="source", flow_label="flow", valid_ids=set(), known_targets="") == []
        assert (
            _check_actor_ids("not-a-list", item_label="flow", actor_ids=set(), known_actors="")
            == []
        )
        assert (
            _external_entry_point_auth_violations(
                {"exposure": ExposureType.EXTERNAL.value, "authentication_method": 99},
                "ep1",
            )
            == []
        )
        assert _id_cited_in_gap_text("actor-1", "No link for actor-1x yet") is False
        assert _id_cited_in_gap_text("actor-1", "Gap cites actor-1 explicitly.") is True


class TestCanonicalSystemModelReferenceCheckerBranches:
    """Verify incremental reference checker defensive branches."""

    def test_system_model_reference_checker_branch_coverage(self) -> None:
        checker = CanonicalSystemModelReferenceChecker()
        assert (
            checker(
                "data_flows",
                {
                    "id": "df1",
                    "source_component_id": "known",
                    "destination_component_id": "known",
                    "actor_ids": "not-a-list",
                },
                {
                    "components": [{"id": "known"}],
                    "data_stores": [{"id": "known"}],
                    "actors": [],
                },
            )
            == []
        )
        assert (
            checker(
                "trust_boundaries",
                {"id": "tb1", "component_ids": "not-a-list"},
                {"components": [], "data_stores": []},
            )
            == []
        )
        assert checker(
            "entry_points",
            {
                "id": "ep1",
                "component_id": "missing-component",
                "actor_id": "missing-actor",
                "exposure": "external",
                "authentication_method": "oauth",
            },
            {
                "components": [{"id": "known-component"}],
                "data_stores": [],
                "actors": [{"id": "known-actor"}],
            },
        )
        assert (
            checker(
                "components",
                {"id": "comp-1"},
                {"components": [], "data_stores": [], "actors": []},
            )
            == []
        )

    def test_system_model_validator_branch_gaps(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        from threatmodeler.contracts.reference_graph import ReferenceGraphEdgeSpec
        from threatmodeler.validation.system_model_validator import (
            ReferenceIntegrityRule,
            _check_actor_ids,
            _collect_referenced_ids,
            _entity_ids,
        )

        broken_flow = canonical_system_model.data_flows[0].model_copy(update={"actor_ids": []})
        invalid = canonical_system_model.model_copy(update={"data_flows": [broken_flow]})
        assert ReferenceIntegrityRule().validate(invalid) == []

        actor_id = canonical_system_model.actors[0].id
        valid_flow = canonical_system_model.data_flows[0].model_copy(update={"actor_ids": [actor_id]})
        valid = canonical_system_model.model_copy(update={"data_flows": [valid_flow]})
        assert ReferenceIntegrityRule().validate(valid) == []

        checker = CanonicalSystemModelReferenceChecker()
        assert (
            checker(
                "trust_boundaries",
                {"id": "tb1", "component_ids": ["known"]},
                {"components": [{"id": "known"}], "data_stores": []},
            )
            == []
        )

        assert _entity_ids([{"id": 123}, {"id": "valid"}]) == {"valid"}
        assert _check_actor_ids(["", "missing"], item_label="flow", actor_ids={"known"}, known_actors="known") == [
            "flow references unknown actor missing. Known actor ids: known (add missing ones with add_actor first)."
        ]

        class FlowItem(BaseModel):
            actor_ids: list[str]

        class FlowModel(BaseModel):
            data_flows: list[FlowItem]

        collected = _collect_referenced_ids(
            FlowModel.model_construct(
                data_flows=[FlowItem.model_construct(actor_ids=["actor-1", 123])]
            ),
            [ReferenceGraphEdgeSpec(list_field="data_flows", id_fields=("actor_ids",))],
        )
        assert collected == {"actor-1"}
