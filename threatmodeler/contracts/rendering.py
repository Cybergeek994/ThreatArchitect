"""Pydantic contracts for deterministic structured graph rendering."""

from typing import Annotated

from pydantic import Field, StrictBool

from threatmodeler.contracts.base import ContractModel


class FlowDiagramNode(ContractModel):
    """A node in the structured flow diagram output."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    label: Annotated[str, Field(strict=True, min_length=1)]
    node_type: Annotated[str, Field(strict=True, min_length=1)]


class FlowDiagramEdge(ContractModel):
    """A directional edge in the structured flow diagram output."""

    id: Annotated[str, Field(strict=True, min_length=1)]
    source: Annotated[str, Field(strict=True, min_length=1)]
    target: Annotated[str, Field(strict=True, min_length=1)]
    label: Annotated[str, Field(strict=True, min_length=1)]
    encrypted_in_transit: StrictBool
    trust_boundary_crossed: StrictBool


class FlowDiagramGraph(ContractModel):
    """Machine-readable graph representation of a data flow diagram."""

    nodes: list[FlowDiagramNode]
    edges: list[FlowDiagramEdge]
