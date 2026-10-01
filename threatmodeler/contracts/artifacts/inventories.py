"""MVP1 component, asset, actor, and entry-point inventories."""

from typing import Annotated

from pydantic import Field

from threatmodeler.contracts.artifacts.base import ArtifactItem, ArtifactModel
from threatmodeler.contracts.artifacts.enums import AssetType
from threatmodeler.contracts.system_model import Actor, Component, EntryPoint


class ComponentInventory(ArtifactModel):
    """Inventory of architecture components in modeling scope."""

    components: list[Component]


class Asset(ArtifactItem):
    """A security-relevant business or technical asset."""

    asset_type: AssetType
    owner: Annotated[str, Field(strict=True, min_length=1)] | None = None
    classification: Annotated[str, Field(strict=True, min_length=1)]
    component_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )
    data_store_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )
    trust_level_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Reference to trust_levels ids indicating which access "
                    "rights can interact with this asset."
                ),
            ),
        ]
    ] = Field(
        default_factory=list,
        description="Trust levels that may access or affect this asset.",
    )


class AssetInventory(ArtifactModel):
    """Inventory of assets requiring protection."""

    assets: list[Asset]


class ActorInteraction(ArtifactItem):
    """A modeled interaction between an actor and a component."""

    actor_id: Annotated[str, Field(strict=True, min_length=1)]
    component_id: Annotated[str, Field(strict=True, min_length=1)]
    privileges: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(default_factory=list)


class ActorModel(ArtifactModel):
    """Actors and their interactions with the modeled system."""

    actors: list[Actor]
    interactions: list[ActorInteraction]


class EntryPointInventory(ArtifactModel):
    """Inventory of exposed and internal system entry points."""

    entry_points: list[EntryPoint]
