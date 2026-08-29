"""Unit tests for deterministic inventory generation."""

import pytest
from threatmodeler.contracts.system_model import ActorType, CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.inventory_generation import InventoryGenerationService


class TestInventoryGenerationPositive:
    """Verify architecture-aware inventory artifacts."""

    def test_trust_boundary_map_includes_crossing_flows(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        trust_boundary_map = service.generate_trust_boundary_map(canonical_system_model)

        assert len(trust_boundary_map.crossing_flows) == 1
        assert trust_boundary_map.crossing_flows[0].data_flow_id == "flow-payment"

    def test_actor_model_includes_entry_point_interactions(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        actor_model = service.generate_actor_model(canonical_system_model)

        assert len(actor_model.interactions) == 1
        assert actor_model.interactions[0].actor_id == "actor-customer"
        assert actor_model.interactions[0].component_id == "component-api"

    def test_asset_inventory_derives_data_elements_and_service_asset(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        asset_inventory = service.generate_asset_inventory(canonical_system_model)

        asset_names = {asset.name for asset in asset_inventory.assets}
        assert "Payment Records" in asset_names
        assert "payment token" in asset_names
        assert canonical_system_model.application.name in asset_names

    def test_authentication_model_includes_authorization_rules(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        auth_model = service.generate_authentication_authorization_model(canonical_system_model)

        assert len(auth_model.authorization_rules) == 1
        assert auth_model.authorization_rules[0].component_ids == ["component-api"]

    def test_deployment_model_maps_components_to_region(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        deployment_model = service.generate_deployment_model(canonical_system_model)

        assert deployment_model.component_placements["component-api"] == "region-1"

    def test_interaction_actor_selection_prefers_human_user_for_external_entry_points(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        external_entry = canonical_system_model.entry_points[0].model_copy(
            update={"exposure": ExposureType.EXTERNAL, "actor_id": None}
        )
        admin_actor = canonical_system_model.actors[0].model_copy(
            update={
                "id": "actor-admin",
                "name": "Administrator",
                "actor_type": ActorType.ADMIN,
            }
        )
        model = canonical_system_model.model_copy(
            update={
                "actors": [admin_actor, canonical_system_model.actors[0]],
                "entry_points": [external_entry],
            }
        )

        actor_model = service.generate_actor_model(model)

        assert actor_model.interactions[0].actor_id == "actor-customer"

    def test_interaction_uses_explicit_entry_point_actor_id(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        service_actor = canonical_system_model.actors[0].model_copy(
            update={
                "id": "actor-service",
                "name": "Workload",
                "actor_type": ActorType.SERVICE_ACCOUNT,
            }
        )
        entry = canonical_system_model.entry_points[0].model_copy(
            update={"actor_id": "actor-service", "exposure": ExposureType.EXTERNAL}
        )
        model = canonical_system_model.model_copy(
            update={
                "actors": [canonical_system_model.actors[0], service_actor],
                "entry_points": [entry],
            }
        )

        actor_model = service.generate_actor_model(model)

        assert actor_model.interactions[0].actor_id == "actor-service"

    def test_asset_inventory_includes_credential_assets_for_password_auth(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        entry = canonical_system_model.entry_points[0].model_copy(
            update={"authentication_method": "Username and password login"}
        )
        model = canonical_system_model.model_copy(update={"entry_points": [entry]})

        asset_inventory = service.generate_asset_inventory(model)

        credential_assets = [
            asset for asset in asset_inventory.assets if asset.asset_type.value == "credential"
        ]
        assert len(credential_assets) == 1
        assert credential_assets[0].name == "Credentials for Payments Endpoint"

    def test_asset_inventory_assigns_trust_level_ids_from_entry_points_and_flows(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        entry = canonical_system_model.entry_points[0].model_copy(
            update={"trust_level_ids": ["trust-level-customer"]}
        )
        actor = canonical_system_model.actors[0].model_copy(
            update={"trust_level_ids": ["trust-level-customer"]}
        )
        model = canonical_system_model.model_copy(
            update={"entry_points": [entry], "actors": [actor]}
        )

        asset_inventory = service.generate_asset_inventory(model)

        store_asset = next(
            asset for asset in asset_inventory.assets if asset.name == "Payment Records"
        )
        service_asset = next(
            asset
            for asset in asset_inventory.assets
            if asset.name == model.application.name
        )

        assert store_asset.trust_level_ids == ["trust-level-customer"]
        assert service_asset.trust_level_ids == ["trust-level-customer"]

    def test_actor_model_skips_interactions_for_unknown_actors(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        model = canonical_system_model.model_copy(update={"actors": []})

        actor_model = service.generate_actor_model(model)

        assert actor_model.interactions == []

    def test_trust_boundary_map_lists_unassigned_components(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        model = canonical_system_model.model_copy(update={"trust_boundaries": []})

        trust_boundary_map = service.generate_trust_boundary_map(model)

        assert trust_boundary_map.unassigned_component_ids == ["component-api"]

    def test_entry_point_inventory_preserves_canonical_entry_points(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        inventory = service.generate_entry_point_inventory(canonical_system_model)

        assert inventory.entry_points == canonical_system_model.entry_points

    def test_component_inventory_preserves_canonical_components(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())

        inventory = service.generate_component_inventory(canonical_system_model)

        assert inventory.components == canonical_system_model.components


class TestInventoryGenerationAuthMapping:
    """Verify authentication and authorization enum mapping branches."""

    @pytest.mark.parametrize(
        ("method", "expected"),
        [
            ("OAuth 2.0 client credentials", "oauth2"),
            ("OpenID Connect login", "oidc"),
            ("SAML federation", "saml"),
            ("API key header", "api_key"),
            ("Mutual TLS certificate", "certificate"),
            ("Workload identity token", "workload_identity"),
            ("Password login", "password"),
            ("anonymous", "none"),
            ("none", "none"),
            ("Custom scheme", "unknown"),
        ],
    )

    def test_authentication_type_mapping(
        self,
        canonical_system_model: CanonicalSystemModel,
        method: str,
        expected: str,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        entry = canonical_system_model.entry_points[0].model_copy(
            update={"authentication_method": method}
        )
        model = canonical_system_model.model_copy(update={"entry_points": [entry]})

        auth_model = service.generate_authentication_authorization_model(model)

        assert auth_model.authentication_mechanisms[0].authentication_type.value == expected

    @pytest.mark.parametrize(
        ("exposure", "expected"),
        [
            (ExposureType.EXTERNAL, "rbac"),
            (ExposureType.PARTNER, "policy_based"),
            (ExposureType.INTERNAL, "acl"),
            (ExposureType.UNKNOWN, "unknown"),
        ],
    )

    def test_authorization_model_type_mapping(
        self,
        canonical_system_model: CanonicalSystemModel,
        exposure: ExposureType,
        expected: str,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        entry = canonical_system_model.entry_points[0].model_copy(update={"exposure": exposure})
        model = canonical_system_model.model_copy(update={"entry_points": [entry]})

        auth_model = service.generate_authentication_authorization_model(model)

        assert auth_model.authorization_rules[0].model_type.value == expected

    def test_interaction_actor_selection_falls_back_to_first_actor(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        service_actor = canonical_system_model.actors[0].model_copy(
            update={"id": "actor-service", "actor_type": ActorType.SERVICE_ACCOUNT}
        )
        internal_entry = canonical_system_model.entry_points[0].model_copy(
            update={"exposure": ExposureType.INTERNAL, "actor_id": None}
        )
        model = canonical_system_model.model_copy(
            update={"actors": [service_actor], "entry_points": [internal_entry]}
        )

        actor_model = service.generate_actor_model(model)

        assert actor_model.interactions[0].actor_id == "actor-service"

    def test_deployment_model_uses_deployment_name_when_regions_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = InventoryGenerationService(ArtifactMetadataService())
        deployment = canonical_system_model.deployment.model_copy(update={"regions": []})
        model = canonical_system_model.model_copy(update={"deployment": deployment})

        deployment_model = service.generate_deployment_model(model)

        assert deployment_model.component_placements["component-api"] == "Cloud Deployment"
