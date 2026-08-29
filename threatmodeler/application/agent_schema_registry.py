"""Registered output schemas for agent-backed artifact generation."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import (
    AbuseMisuseCases,
    AttackTree,
    ControlMapping,
    DataFlowDiagramModel,
    ExecutiveSummary,
    MissingInformationReport,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideThreatRegister,
    TechnicalThreatModelReport,
)
from threatmodeler.validation.schema_registry import PydanticOutputSchemaRegistry


def create_downstream_schema_registry() -> PydanticOutputSchemaRegistry:
    """Create the schema registry used by the downstream agent gateway.

    Returns:
        Registry containing every schema-bound downstream artifact model.
    """
    schemas: dict[str, type[BaseModel]] = {
        "DataFlowDiagramModel": DataFlowDiagramModel,
        "AttackTree": AttackTree,
        "AbuseMisuseCases": AbuseMisuseCases,
        "RiskRegister": RiskRegister,
        "MitigationPlan": MitigationPlan,
        "SecurityRequirements": SecurityRequirements,
        "MissingInformationReport": MissingInformationReport,
        "ControlMapping": ControlMapping,
        "ExecutiveSummary": ExecutiveSummary,
        "TechnicalThreatModelReport": TechnicalThreatModelReport,
    }
    return PydanticOutputSchemaRegistry(schemas)


def create_stride_schema_registry() -> PydanticOutputSchemaRegistry:
    """Create the schema registry used by STRIDE threat generation.

    Returns:
        Registry containing the STRIDE threat register contract.
    """
    return PydanticOutputSchemaRegistry({"StrideThreatRegister": StrideThreatRegister})
