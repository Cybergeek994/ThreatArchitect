"""Upstream artifact context supplied to STRIDE generation."""

from pydantic import model_validator

from threatmodeler.contracts.artifacts.architecture import (
    AuthenticationAuthorizationModel,
    DataFlowDiagramModel,
    DeploymentModelArtifact,
    TrustBoundaryMap,
)
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph
from threatmodeler.contracts.artifacts.inventories import (
    ActorModel,
    AssetInventory,
    ComponentInventory,
    EntryPointInventory,
)
from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.system_model import CanonicalSystemModel


class PreStrideArtifacts(ContractModel):
    """Validated upstream artifacts produced before architecture graph generation."""

    system_model: CanonicalSystemModel
    component_inventory: ComponentInventory
    asset_inventory: AssetInventory
    actor_model: ActorModel
    data_flow_diagram: DataFlowDiagramModel
    trust_boundary_map: TrustBoundaryMap
    entry_point_inventory: EntryPointInventory
    authentication_authorization_model: AuthenticationAuthorizationModel
    deployment_model: DeploymentModelArtifact


class StrideUpstreamContext(PreStrideArtifacts):
    """Validated upstream artifacts consumed by STRIDE generation."""

    architecture_graph: ArchitectureGraph

    @model_validator(mode="after")
    def require_non_empty_graph(self) -> "StrideUpstreamContext":
        """Reject STRIDE context without a populated architecture graph."""
        if not self.architecture_graph.nodes:
            raise ValueError("architecture_graph must contain at least one node")
        if not self.architecture_graph.attack_paths:
            raise ValueError("architecture_graph must contain at least one attack path")
        return self
