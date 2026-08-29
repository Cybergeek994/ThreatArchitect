"""Deterministic inventory and architecture-view generation."""

from threatmodeler.contracts.artifacts import (
    ActorInteraction,
    ActorModel,
    Asset,
    AssetInventory,
    AssetType,
    AuthenticationAuthorizationModel,
    AuthenticationMechanism,
    AuthenticationType,
    AuthorizationModelType,
    AuthorizationRule,
    ComponentInventory,
    DeploymentModelArtifact,
    EntryPointInventory,
    TrustBoundaryCrossingFlow,
    TrustBoundaryMap,
)
from threatmodeler.contracts.system_model import (
    ActorType,
    CanonicalSystemModel,
    EntryPoint,
    ExposureType,
)
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class InventoryGenerationService:
    """Generate deterministic inventories from the canonical system model."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate_component_inventory(self, model: CanonicalSystemModel) -> ComponentInventory:
        """Generate the component inventory.

        Args:
            model: Canonical model containing extracted components.

        Returns:
            Inventory preserving the canonical component contracts.
        """
        return ComponentInventory(
            **self._metadata.artifact_fields(
                "component-inventory",
                "Component Inventory",
                "Components extracted from the canonical architecture model.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    model.components, when_empty=model.application.confidence
                ),
            ).model_dump(),
            components=model.components,
        )

    def generate_asset_inventory(self, model: CanonicalSystemModel) -> AssetInventory:
        """Derive data, credential, and service assets from canonical entities.

        Args:
            model: Canonical model containing data stores, flows, and entry points.

        Returns:
            Asset inventory linked to canonical identifiers and data elements.
        """
        assets: list[Asset] = [
            Asset(
                **self._metadata.item_fields(
                    f"asset-{store.id}",
                    store.name,
                    store.description,
                    store.evidence,
                    store.confidence,
                    model.assumptions,
                ).model_dump(),
                asset_type=AssetType.DATA,
                owner=model.application.owner,
                classification=model.application.data_classification.value,
                data_store_ids=[store.id],
            )
            for store in model.data_stores
        ]
        for store in model.data_stores:
            for element in store.data_elements:
                assets.append(
                    Asset(
                        **self._metadata.item_fields(
                            f"asset-element-{store.id}-{element}",
                            element,
                            f"Data element stored in {store.name}.",
                            store.evidence,
                            store.confidence,
                            model.assumptions,
                        ).model_dump(),
                        asset_type=AssetType.DATA,
                        owner=model.application.owner,
                        classification=model.application.data_classification.value,
                        data_store_ids=[store.id],
                    )
                )
        for entry in model.entry_points:
            if "password" in entry.authentication_method.lower():
                assets.append(
                    Asset(
                        **self._metadata.item_fields(
                            f"asset-credential-{entry.id}",
                            f"Credentials for {entry.name}",
                            entry.authentication_method,
                            entry.evidence,
                            entry.confidence,
                            model.assumptions,
                        ).model_dump(),
                        asset_type=AssetType.CREDENTIAL,
                        owner=model.application.owner,
                        classification=model.application.data_classification.value,
                        component_ids=[entry.component_id],
                        trust_level_ids=list(entry.trust_level_ids),
                    )
                )
        if model.components:
            assets.append(
                Asset(
                    **self._metadata.item_fields(
                        f"asset-service-{model.application.id}",
                        model.application.name,
                        model.application.description,
                        model.application.evidence,
                        model.application.confidence,
                        model.assumptions,
                    ).model_dump(),
                    asset_type=AssetType.SERVICE,
                    owner=model.application.owner,
                    classification=model.application.data_classification.value,
                    component_ids=[component.id for component in model.components],
                )
            )
        enriched_assets = [
            self._apply_asset_trust_level_ids(model, asset) for asset in assets
        ]
        return AssetInventory(
            **self._metadata.artifact_fields(
                "asset-inventory",
                "Asset Inventory",
                "Security-relevant assets derived from canonical architecture entities.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    enriched_assets, when_empty=model.application.confidence
                ),
            ).model_dump(),
            assets=enriched_assets,
        )

    def generate_actor_model(self, model: CanonicalSystemModel) -> ActorModel:
        """Preserve canonical actors and derive entry-point interactions.

        Args:
            model: Canonical model containing validated actors and entry points.

        Returns:
            Actor model with source-supported actor-to-component interactions.
        """
        actor_ids = {actor.id for actor in model.actors}
        interactions: list[ActorInteraction] = []
        for entry in model.entry_points:
            actor_id = self._interaction_actor_id(model, entry)
            if actor_id not in actor_ids:
                continue
            interactions.append(
                ActorInteraction(
                    **self._metadata.item_fields(
                        f"interaction-{actor_id}-{entry.id}",
                        f"{actor_id} accesses {entry.name}",
                        f"Actor reaches {entry.component_id} through {entry.protocol}.",
                        entry.evidence,
                        entry.confidence,
                        model.assumptions,
                    ).model_dump(),
                    actor_id=actor_id,
                    component_id=entry.component_id,
                    privileges=[entry.authentication_method],
                )
            )
        return ActorModel(
            **self._metadata.artifact_fields(
                "actor-model",
                "Actor Model",
                "Actors and entry-point interactions from the canonical model.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    [*model.actors, *interactions],
                    when_empty=model.application.confidence,
                ),
            ).model_dump(),
            actors=model.actors,
            interactions=interactions,
        )

    def generate_trust_boundary_map(self, model: CanonicalSystemModel) -> TrustBoundaryMap:
        """Generate trust-boundary membership and crossing data flows.

        Args:
            model: Canonical model containing boundaries, components, and flows.

        Returns:
            Trust-boundary map with crossing flows and unassigned components.
        """
        assigned_ids = {
            component_id
            for boundary in model.trust_boundaries
            for component_id in boundary.component_ids
        }
        crossing_flows = [
            TrustBoundaryCrossingFlow(
                data_flow_id=flow.id,
                source_component_id=flow.source_component_id,
                destination_component_id=flow.destination_component_id,
            )
            for flow in model.data_flows
            if flow.trust_boundary_crossed
        ]
        return TrustBoundaryMap(
            **self._metadata.artifact_fields(
                "trust-boundary-map",
                "Trust Boundary Map",
                "Canonical trust boundaries, crossing flows, and component membership.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    model.trust_boundaries, when_empty=model.application.confidence
                ),
            ).model_dump(),
            trust_boundaries=model.trust_boundaries,
            crossing_flows=crossing_flows,
            unassigned_component_ids=[
                component.id for component in model.components if component.id not in assigned_ids
            ],
        )

    def generate_entry_point_inventory(self, model: CanonicalSystemModel) -> EntryPointInventory:
        """Generate the entry-point inventory.

        Args:
            model: Canonical model containing validated entry points.

        Returns:
            Inventory preserving canonical entry-point contracts.
        """
        return EntryPointInventory(
            **self._metadata.artifact_fields(
                "entry-point-inventory",
                "Entry Point Inventory",
                "Entry points extracted from the canonical architecture model.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    model.entry_points, when_empty=model.application.confidence
                ),
            ).model_dump(),
            entry_points=model.entry_points,
        )

    def generate_authentication_authorization_model(
        self, model: CanonicalSystemModel
    ) -> AuthenticationAuthorizationModel:
        """Map canonical entry-point authentication text to closed mechanism types.

        Args:
            model: Canonical model containing entry-point authentication evidence.

        Returns:
            Authentication and authorization artifact using closed enum values.
        """
        mechanisms = [
            AuthenticationMechanism(
                **self._metadata.item_fields(
                    f"authentication-{entry.id}",
                    f"Authentication for {entry.name}",
                    entry.authentication_method,
                    entry.evidence,
                    entry.confidence,
                    model.assumptions,
                ).model_dump(),
                authentication_type=self._authentication_type(entry.authentication_method),
                component_ids=[entry.component_id],
                multi_factor_required="mfa" in entry.authentication_method.lower(),
            )
            for entry in model.entry_points
        ]
        authorization_rules = [
            AuthorizationRule(
                **self._metadata.item_fields(
                    f"authorization-{entry.id}",
                    f"Authorization for {entry.name}",
                    (
                        f"Access to {entry.component_id} via {entry.protocol} requires "
                        f"{entry.authentication_method}."
                    ),
                    entry.evidence,
                    entry.confidence,
                    model.assumptions,
                ).model_dump(),
                model_type=self._authorization_model_type(entry.exposure),
                actor_ids=[
                    actor.id
                    for actor in model.actors
                    if actor.id == self._interaction_actor_id(model, entry)
                ],
                component_ids=[entry.component_id],
                permissions=[entry.protocol],
            )
            for entry in model.entry_points
        ]
        return AuthenticationAuthorizationModel(
            **self._metadata.artifact_fields(
                "authentication-authorization-model",
                "Authentication and Authorization Model",
                "Validated authentication mechanisms and documented authorization rules.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    [*mechanisms, *authorization_rules],
                    when_empty=model.application.confidence,
                ),
            ).model_dump(),
            authentication_mechanisms=mechanisms,
            authorization_rules=authorization_rules,
        )

    def generate_deployment_model(self, model: CanonicalSystemModel) -> DeploymentModelArtifact:
        """Generate the deployment artifact with component placement hints.

        Args:
            model: Canonical model containing validated deployment details.

        Returns:
            Deployment artifact preserving canonical confidence and assumptions.
        """
        placement = self._component_placements(model)
        return DeploymentModelArtifact(
            **self._metadata.artifact_fields(
                "deployment-model",
                "Deployment Model",
                "Deployment details from the canonical architecture model.",
                model.assumptions,
                confidence=model.deployment.confidence,
            ).model_dump(),
            deployment=model.deployment,
            component_placements=placement,
        )

    def _apply_asset_trust_level_ids(self, model: CanonicalSystemModel, asset: Asset) -> Asset:
        resolved = self._resolve_asset_trust_level_ids(
            model,
            component_ids=asset.component_ids,
            data_store_ids=asset.data_store_ids,
        )
        merged = sorted({*asset.trust_level_ids, *resolved})
        if merged == asset.trust_level_ids:
            return asset
        return asset.model_copy(update={"trust_level_ids": merged})

    def _resolve_asset_trust_level_ids(
        self,
        model: CanonicalSystemModel,
        *,
        component_ids: list[str],
        data_store_ids: list[str],
    ) -> list[str]:
        related_component_ids = set(component_ids)
        related_store_ids = set(data_store_ids)
        for flow in model.data_flows:
            if flow.source_component_id in related_store_ids:
                related_component_ids.add(flow.destination_component_id)
            if flow.destination_component_id in related_store_ids:
                related_component_ids.add(flow.source_component_id)
            if flow.source_component_id in related_component_ids:
                if flow.destination_component_id in {
                    store.id for store in model.data_stores
                }:
                    related_store_ids.add(flow.destination_component_id)
            if flow.destination_component_id in related_component_ids:
                if flow.source_component_id in {store.id for store in model.data_stores}:
                    related_store_ids.add(flow.source_component_id)

        trust_level_ids: set[str] = set()
        actor_ids = {actor.id: actor for actor in model.actors}
        for entry in model.entry_points:
            if entry.component_id not in related_component_ids:
                continue
            trust_level_ids.update(entry.trust_level_ids)
            if entry.actor_id is not None:
                actor = actor_ids.get(entry.actor_id)
                if actor is not None:
                    trust_level_ids.update(actor.trust_level_ids)
        for flow in model.data_flows:
            if not flow.actor_ids:
                continue
            touches_asset = (
                flow.source_component_id in related_component_ids
                or flow.destination_component_id in related_component_ids
                or flow.source_component_id in related_store_ids
                or flow.destination_component_id in related_store_ids
            )
            if not touches_asset:
                continue
            for actor_id in flow.actor_ids:
                actor = actor_ids.get(actor_id)
                if actor is not None:
                    trust_level_ids.update(actor.trust_level_ids)
        return sorted(trust_level_ids)

    def _interaction_actor_id(
        self,
        model: CanonicalSystemModel,
        entry: EntryPoint,
    ) -> str:
        if entry.actor_id is not None:
            return entry.actor_id
        preferred_types = (
            (ActorType.HUMAN_USER, ActorType.EXTERNAL_SYSTEM)
            if entry.exposure is ExposureType.EXTERNAL
            else (ActorType.SERVICE_ACCOUNT, ActorType.ADMIN)
        )
        for actor_type in preferred_types:
            for actor in model.actors:
                if actor.actor_type is actor_type:
                    return actor.id
        return model.actors[0].id if model.actors else "unknown-actor"

    def _component_placements(self, model: CanonicalSystemModel) -> dict[str, str]:
        region = model.deployment.regions[0] if model.deployment.regions else model.deployment.name
        return {component.id: region for component in model.components}

    def _authentication_type(self, method: str) -> AuthenticationType:
        normalized = method.lower()
        if "oauth" in normalized:
            return AuthenticationType.OAUTH2
        if "oidc" in normalized or "openid" in normalized:
            return AuthenticationType.OIDC
        if "saml" in normalized:
            return AuthenticationType.SAML
        if "api key" in normalized or "api_key" in normalized:
            return AuthenticationType.API_KEY
        if "certificate" in normalized or "mtls" in normalized:
            return AuthenticationType.CERTIFICATE
        if "workload" in normalized:
            return AuthenticationType.WORKLOAD_IDENTITY
        if "password" in normalized:
            return AuthenticationType.PASSWORD
        if normalized in {"none", "anonymous"}:
            return AuthenticationType.NONE
        return AuthenticationType.UNKNOWN

    def _authorization_model_type(self, exposure: ExposureType) -> AuthorizationModelType:
        if exposure is ExposureType.EXTERNAL:
            return AuthorizationModelType.RBAC
        if exposure is ExposureType.PARTNER:
            return AuthorizationModelType.POLICY_BASED
        if exposure is ExposureType.INTERNAL:
            return AuthorizationModelType.ACL
        return AuthorizationModelType.UNKNOWN
