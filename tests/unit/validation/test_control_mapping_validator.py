"""Tests for OWASP ASVS control-mapping validation."""

import pytest
from threatmodeler.contracts.artifacts import ControlMapping, ControlMappingEntry, ControlStatus
from threatmodeler.contracts.source import Evidence, SourceReference, SourceType
from threatmodeler.errors import AgentSchemaValidationError
from threatmodeler.shared.constants import ControlFrameworkName
from threatmodeler.validation.control_mapping_validator import ControlMappingCatalogRule


class TestControlMappingCatalogRulePositive:
    """Verify catalogued identifiers are accepted."""

    def test_valid_asvs_mapping_is_returned(self) -> None:
        mapping = self._mapping(
            self._entry(framework=ControlFrameworkName.OWASP_ASVS, control_id="v5.0.0-2.2.1")
        )

        validated = ControlMappingCatalogRule().validate(mapping)

        assert validated is mapping

    def _mapping(self, *entries: ControlMappingEntry) -> ControlMapping:
        return ControlMapping(
            artifact_id="control-mapping",
            title="Control Mapping",
            description="Test mapping",
            confidence=1.0,
            assumptions=[],
            controls=list(entries),
        )

    def _entry(self, *, framework: str, control_id: str) -> ControlMappingEntry:
        source = SourceReference(
            source_type=SourceType.MANUAL_INPUT,
            source_id="controls",
            location="test",
            excerpt="control mapping",
        )
        return ControlMappingEntry(
            id="control-1",
            name="Auth control",
            description="Map authentication requirement",
            evidence=[Evidence(summary="test", source_references=[source])],
            confidence=1.0,
            assumptions=[],
            framework=framework,
            framework_control_id=control_id,
            status=ControlStatus.NOT_STARTED,
        )


class TestControlMappingCatalogRuleErrors:
    """Verify invented identifiers fail without fallback."""

    def test_unknown_control_id_raises_catalog_error(self) -> None:
        mapping = TestControlMappingCatalogRulePositive()._mapping(
            TestControlMappingCatalogRulePositive()._entry(
                framework=ControlFrameworkName.OWASP_ASVS, control_id="AC-1"
            )
        )

        with pytest.raises(AgentSchemaValidationError) as captured:
            ControlMappingCatalogRule().validate(mapping)

        assert captured.value.error_code == "CONTROL_MAPPING_CATALOG_INVALID"

    def test_unsupported_framework_raises_catalog_error(self) -> None:
        mapping = TestControlMappingCatalogRulePositive()._mapping(
            TestControlMappingCatalogRulePositive()._entry(
                framework="NIST SP 800-53", control_id="V2.2.1"
            )
        )

        with pytest.raises(AgentSchemaValidationError) as captured:
            ControlMappingCatalogRule().validate(mapping)

        assert captured.value.error_code == "CONTROL_MAPPING_CATALOG_INVALID"
