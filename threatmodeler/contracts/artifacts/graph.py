"""Typed architecture graph and attack-path artifacts."""

from typing import Annotated, Self

from pydantic import Field, StrictBool, model_validator

from threatmodeler.contracts.artifacts.base import ArtifactItem, ArtifactModel
from threatmodeler.contracts.artifacts.enums import GraphEdgeKind, GraphNodeKind, StrideCategory
from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.source import Evidence

_REF_ID = (
    "Reference to another item's id declared in the input payload or graph lists. "
    "Must match an id field on an upstream item."
)


class GraphNode(ArtifactItem):
    """One typed node in the architecture graph."""

    kind: GraphNodeKind
    actor_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `actors`.",
        ),
    ] | None = None
    component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `components`.",
        ),
    ] | None = None
    data_store_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `data_stores`.",
        ),
    ] | None = None
    entry_point_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `entry_points`.",
        ),
    ] | None = None
    asset_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `assets`.",
        ),
    ] | None = None
    external_dependency_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `external_dependencies`.",
        ),
    ] | None = None

    @model_validator(mode="after")
    def require_anchor_or_evidence(self) -> Self:
        """Require a canonical ref or non-empty evidence for every node."""
        has_anchor = any(
            (
                self.actor_id,
                self.component_id,
                self.data_store_id,
                self.entry_point_id,
                self.asset_id,
                self.external_dependency_id,
            )
        )
        if not has_anchor and not self.evidence:
            raise ValueError(
                "GraphNode must link to a canonical id or include non-empty evidence"
            )
        return self


class GraphEdge(ArtifactItem):
    """One typed directed edge in the architecture graph."""

    kind: GraphEdgeKind
    source_node_id: Annotated[str, Field(strict=True, min_length=1)]
    target_node_id: Annotated[str, Field(strict=True, min_length=1)]
    data_flow_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `data_flows`.",
        ),
    ] | None = None
    trust_boundary_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target: `trust_boundaries`.",
        ),
    ] | None = None
    protocol: Annotated[str, Field(strict=True, min_length=1)] | None = None
    authentication_method: Annotated[str, Field(strict=True, min_length=1)] | None = None
    encrypted_in_transit: StrictBool | None = None


class AttackPathStep(ContractModel):
    """One hop in an enumerated attack path walk."""

    node_id: Annotated[str, Field(strict=True, min_length=1)]
    via_edge_id: Annotated[str, Field(strict=True, min_length=1)] | None = None


class AttackPath(ArtifactItem):
    """A first-class attack path through the architecture graph."""

    steps: Annotated[list[AttackPathStep], Field(min_length=1)]
    entry_node_id: Annotated[str, Field(strict=True, min_length=1)]
    target_node_id: Annotated[str, Field(strict=True, min_length=1)]
    stride_categories: list[StrideCategory] = Field(default_factory=list)


class ArchitectureGraph(ArtifactModel):
    """Typed architecture graph with enumerated attack paths."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    attack_paths: list[AttackPath]

    @model_validator(mode="after")
    def require_unique_ids(self) -> Self:
        """Reject duplicate ids across nodes, edges, and attack paths."""
        seen: set[str] = set()
        duplicates: set[str] = set()
        for item in (*self.nodes, *self.edges, *self.attack_paths):
            if item.id in seen:
                duplicates.add(item.id)
            seen.add(item.id)
        if duplicates:
            joined = ", ".join(sorted(duplicates))
            raise ValueError(f"ArchitectureGraph contains duplicate ids: {joined}")
        return self
