"""MVP1 architecture view artifacts."""

from typing import Annotated

from pydantic import Field, StrictBool

from threatmodeler.contracts.artifacts.base import ArtifactItem, ArtifactModel
from threatmodeler.contracts.artifacts.enums import (
    AuthenticationType,
    AuthorizationModelType,
)
from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.system_model import (
    Component,
    DataFlow,
    DataStore,
    DeploymentModel,
    TrustBoundary,
)


class TrustBoundaryCrossingFlow(ContractModel):
    """A data flow that crosses one or more trust boundaries."""

    data_flow_id: Annotated[str, Field(strict=True, min_length=1)]
    source_component_id: Annotated[str, Field(strict=True, min_length=1)]
    destination_component_id: Annotated[str, Field(strict=True, min_length=1)]


class DataFlowDiagramModel(ArtifactModel):
    """Machine-readable data flow diagram model."""

    components: list[Component]
    data_stores: list[DataStore]
    data_flows: list[DataFlow]


class TrustBoundaryMap(ArtifactModel):
    """Trust boundaries and the components contained by them."""

    trust_boundaries: list[TrustBoundary]
    crossing_flows: list[TrustBoundaryCrossingFlow] = Field(default_factory=list)
    unassigned_component_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )


class AuthenticationMechanism(ArtifactItem):
    """Authentication mechanism protecting one or more components."""

    authentication_type: AuthenticationType
    component_ids: list[Annotated[str, Field(strict=True, min_length=1)]]
    multi_factor_required: StrictBool
    credential_storage: Annotated[str, Field(strict=True, min_length=1)] | None = None


class AuthorizationRule(ArtifactItem):
    """Authorization policy for subjects, resources, and permissions."""

    model_type: AuthorizationModelType
    actor_ids: list[Annotated[str, Field(strict=True, min_length=1)]]
    component_ids: list[Annotated[str, Field(strict=True, min_length=1)]]
    permissions: list[Annotated[str, Field(strict=True, min_length=1)]]


class AuthenticationAuthorizationModel(ArtifactModel):
    """Authentication mechanisms and authorization policies."""

    authentication_mechanisms: list[AuthenticationMechanism]
    authorization_rules: list[AuthorizationRule]


class DeploymentModelArtifact(ArtifactModel):
    """Deployment view and component placement details."""

    deployment: DeploymentModel
    component_placements: dict[str, Annotated[str, Field(strict=True, min_length=1)]]
