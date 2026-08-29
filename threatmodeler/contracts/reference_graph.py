"""Reference-graph policy models shared by validation and prompt guidance."""

from pydantic import BaseModel, ConfigDict, Field


class ReferenceGraphEdgeSpec(BaseModel):
    """How items in one list field reference ids of other items."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    list_field: str = Field(strict=True, min_length=1)
    id_fields: tuple[str, ...] = Field(min_length=1)


class ReferenceGraphNodeSpec(BaseModel):
    """A list field whose items must appear in at least one reference edge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    list_field: str = Field(strict=True, min_length=1)
    edges: tuple[ReferenceGraphEdgeSpec, ...] = Field(min_length=1)


class ReferenceGraphPolicy(BaseModel):
    """Declares which list fields are nodes and which fields form reference edges."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    nodes: tuple[ReferenceGraphNodeSpec, ...] = Field(min_length=1)


def default_reference_graph_policy() -> ReferenceGraphPolicy:
    """Return the production reference-graph policy for unreferenced-item checks."""
    flow_edges = ReferenceGraphEdgeSpec(
        list_field="data_flows",
        id_fields=("source_component_id", "destination_component_id"),
    )
    entry_component_edge = ReferenceGraphEdgeSpec(
        list_field="entry_points",
        id_fields=("component_id",),
    )
    boundary_edge = ReferenceGraphEdgeSpec(
        list_field="trust_boundaries",
        id_fields=("component_ids",),
    )
    entry_actor_edge = ReferenceGraphEdgeSpec(
        list_field="entry_points",
        id_fields=("actor_id",),
    )
    flow_actor_edge = ReferenceGraphEdgeSpec(
        list_field="data_flows",
        id_fields=("actor_ids",),
    )
    return ReferenceGraphPolicy(
        nodes=(
            ReferenceGraphNodeSpec(
                list_field="components",
                edges=(flow_edges, entry_component_edge),
            ),
            ReferenceGraphNodeSpec(
                list_field="data_stores",
                edges=(flow_edges, boundary_edge),
            ),
            ReferenceGraphNodeSpec(
                list_field="actors",
                edges=(entry_actor_edge, flow_actor_edge),
            ),
        )
    )
