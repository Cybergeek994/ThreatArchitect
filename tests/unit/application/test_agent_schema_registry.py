"""Tests for agent output-schema registry helpers."""

from threatmodeler.application.agent_schema_registry import (
    create_downstream_schema_registry,
    create_stride_schema_registry,
)
from threatmodeler.contracts.artifacts import RiskRegister, StrideThreatRegister


class TestAgentSchemaRegistryPositive:
    """Verify production schema maps include downstream and STRIDE contracts."""

    def test_downstream_registry_contains_risk_register(self) -> None:
        registry = create_downstream_schema_registry()

        assert registry.get("RiskRegister") is RiskRegister

    def test_stride_registry_contains_threat_register(self) -> None:
        registry = create_stride_schema_registry()

        assert registry.get("StrideThreatRegister") is StrideThreatRegister
