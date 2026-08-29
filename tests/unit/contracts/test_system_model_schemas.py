"""Validation tests for canonical threat-modeling contracts."""

import json
from collections.abc import Callable

import pytest
from pydantic import ValidationError
from threatmodeler.contracts import (
    Actor,
    ActorType,
    ApplicationInfo,
    CanonicalSystemModel,
    Component,
    ComponentType,
    Criticality,
    DataClassification,
    DataFlow,
    DataStore,
    DeploymentModel,
    EntryPoint,
    Evidence,
    SourceReference,
    SourceType,
    TrustBoundary,
)
from threatmodeler.contracts.base import ExtractedItem


@pytest.fixture
def source_reference() -> SourceReference:
    """Create a valid source reference for schema tests."""
    return SourceReference(
        source_type=SourceType.CONFLUENCE_PAGE,
        source_id="ARB-42",
        location="Architecture / Runtime view",
        excerpt="Requests pass through the public API gateway.",
    )


@pytest.fixture
def evidence(source_reference: SourceReference) -> list[Evidence]:
    """Create valid evidence for an extracted item."""
    return [
        Evidence(
            summary="The architecture review identifies this item.",
            source_references=[source_reference],
        )
    ]


@pytest.fixture
def extracted_item_factory(
    evidence: list[Evidence], source_reference: SourceReference
) -> Callable[[str, str], ExtractedItem]:
    """Return a fixture factory for production extracted-item contracts."""

    def create(item_id: str, name: str) -> ExtractedItem:
        return ExtractedItem(
            id=item_id,
            name=name,
            description=f"Description for {name}",
            evidence=evidence,
            confidence=0.9,
            source_reference=source_reference,
        )

    return create


@pytest.fixture
def canonical_model(
    extracted_item_factory: Callable[[str, str], ExtractedItem],
) -> CanonicalSystemModel:
    """Create a valid canonical system model containing every entity type."""
    application = ApplicationInfo(
        **extracted_item_factory("app-1", "Payments").model_dump(),
        business_purpose="Process customer payments",
        owner="Payments Engineering",
        criticality=Criticality.CRITICAL,
        environments=["production", "staging"],
        data_classification=DataClassification.RESTRICTED,
    )
    actor = Actor(
        **extracted_item_factory("actor-1", "Customer").model_dump(),
        actor_type=ActorType.HUMAN_USER,
    )
    api = Component(
        **extracted_item_factory("component-api", "Payments API").model_dump(),
        component_type=ComponentType.API,
    )
    database = Component(
        **extracted_item_factory("component-db", "Payments Database").model_dump(),
        component_type=ComponentType.DATABASE,
    )
    data_store = DataStore(
        **extracted_item_factory("store-1", "Payment Records").model_dump(),
        data_elements=["payment token", "amount"],
        encrypted_at_rest=True,
    )
    data_flow = DataFlow(
        **extracted_item_factory("flow-1", "Persist payment").model_dump(),
        source_component_id="component-api",
        destination_component_id="component-db",
        protocol="TLS/PostgreSQL",
        authentication_method="workload identity",
        data_elements=["payment token", "amount"],
        encrypted_in_transit=True,
        trust_boundary_crossed=True,
    )
    boundary = TrustBoundary(
        **extracted_item_factory("boundary-1", "Production network").model_dump(),
        component_ids=["component-api", "component-db"],
    )
    entry_point = EntryPoint(
        **extracted_item_factory("entry-1", "Payment endpoint").model_dump(),
        component_id="component-api",
        protocol="HTTPS",
        authentication_method="OAuth 2.0",
        actor_id="actor-1",
    )
    deployment = DeploymentModel(
        **extracted_item_factory("deployment-1", "Primary deployment").model_dump(),
        provider="Example Cloud",
        regions=["region-1"],
    )
    return CanonicalSystemModel(
        application=application,
        actors=[actor],
        components=[api, database],
        data_stores=[data_store],
        data_flows=[data_flow],
        trust_boundaries=[boundary],
        entry_points=[entry_point],
        deployment=deployment,
        assumptions=["The review document reflects the production environment."],
        missing_information=["Disaster recovery RTO is not documented."],
    )


class TestSystemModelSchemasPositive:
    """Verify supported inputs and successful behavior."""

    def test_canonical_model_serializes_and_round_trips_as_json(
        self, canonical_model: CanonicalSystemModel
    ) -> None:
        model = canonical_model

        serialized = model.model_dump_json()
        restored = CanonicalSystemModel.model_validate_json(serialized)

        assert restored == model
        payload = json.loads(serialized)
        assert payload["application"]["criticality"] == "critical"
        assert payload["actors"][0]["actor_type"] == "human_user"
        assert payload["data_flows"][0]["encrypted_in_transit"] is True


class TestSystemModelSchemasNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_required_fields_are_enforced(
        self, extracted_item_factory: Callable[[str, str], ExtractedItem]
    ) -> None:
        payload: dict[str, object] = extracted_item_factory("component-1", "API").model_dump()
        del payload["description"]
        payload["component_type"] = ComponentType.API

        with pytest.raises(ValidationError, match="description"):
            Component.model_validate(payload)

    @pytest.mark.parametrize(
        "confidence",
        [-0.01, 1.01, float("inf"), float("nan"), "0.5"],
    )

    def test_extracted_item_rejects_invalid_confidence(
        self,
        confidence: object,
        extracted_item_factory: Callable[[str, str], ExtractedItem],
    ) -> None:
        payload: dict[str, object] = extracted_item_factory("actor-1", "Customer").model_dump()
        payload.update(confidence=confidence, actor_type=ActorType.HUMAN_USER)

        with pytest.raises(ValidationError):
            Actor.model_validate(payload)

    def test_invalid_enum_is_rejected(
        self, extracted_item_factory: Callable[[str, str], ExtractedItem]
    ) -> None:
        payload: dict[str, object] = extracted_item_factory("actor-1", "Customer").model_dump()
        payload["actor_type"] = "robot"

        with pytest.raises(ValidationError, match="actor_type"):
            Actor.model_validate(payload)

    def test_empty_evidence_is_rejected(
        self, extracted_item_factory: Callable[[str, str], ExtractedItem]
    ) -> None:
        payload: dict[str, object] = extracted_item_factory("actor-1", "Customer").model_dump()
        payload.update(evidence=[], actor_type=ActorType.HUMAN_USER)

        with pytest.raises(ValidationError, match="evidence"):
            Actor.model_validate(payload)

    def test_strict_boolean_validation_rejects_string_values(
        self, extracted_item_factory: Callable[[str, str], ExtractedItem]
    ) -> None:
        payload: dict[str, object] = {
            **extracted_item_factory("flow-1", "API request").model_dump(),
            "source_component_id": "component-1",
            "destination_component_id": "component-2",
            "protocol": "HTTPS",
            "authentication_method": "OAuth 2.0",
            "data_elements": ["request"],
            "encrypted_in_transit": "yes",
            "trust_boundary_crossed": False,
        }

        with pytest.raises(ValidationError):
            DataFlow.model_validate(payload)

    def test_source_reference_rejects_blank_required_fields(self) -> None:
        with pytest.raises(ValidationError, match="source_id"):
            SourceReference(
                source_type=SourceType.DIAGRAM,
                source_id="   ",
                location="Page 2",
                excerpt="API to database",
            )

    def test_unknown_fields_are_rejected(
        self, extracted_item_factory: Callable[[str, str], ExtractedItem]
    ) -> None:
        payload: dict[str, object] = {
            **extracted_item_factory("component-1", "API").model_dump(),
            "component_type": ComponentType.API,
            "unexpected": "not part of the contract",
        }

        with pytest.raises(ValidationError, match="unexpected"):
            Component.model_validate(payload)
