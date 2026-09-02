"""Validate generated control mappings against the ASVS 5.0 registry."""

from threatmodeler.contracts.artifacts import ControlMapping
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.infrastructure.control_catalogs.asvs_control_registry_factory import (
    AsvsControlRegistryFactory,
)
from threatmodeler.errors.application import AgentSchemaValidationError
from threatmodeler.shared.constants import ControlFrameworkName


class ControlMappingCatalogRule:
    """Require agent control mappings to use catalogued OWASP ASVS identifiers."""

    def __init__(
        self,
        registry: AsvsControlRegistry | None = None,
        *,
        registry_factory: AsvsControlRegistryFactory | None = None,
    ) -> None:
        self._registry = registry or (registry_factory or AsvsControlRegistryFactory.packaged()).create()

    def validate(self, mapping: ControlMapping) -> ControlMapping:
        """Reject mappings that invent framework identifiers.

        Args:
            mapping: Schema-valid control mapping produced by an agent.

        Returns:
            Original mapping when every control identifier is catalogued.

        Raises:
            AgentSchemaValidationError: If a control is outside the ASVS catalog.
        """
        violations: list[str] = []
        for entry in mapping.controls:
            if entry.framework != ControlFrameworkName.OWASP_ASVS:
                violations.append(
                    f"Control {entry.id} uses unsupported framework {entry.framework}"
                )
            if not self._registry.contains(entry.framework_control_id):
                violations.append(
                    f"Control {entry.id} uses unknown ASVS id {entry.framework_control_id}"
                )
        if violations:
            raise AgentSchemaValidationError(
                "Control mapping is not limited to the supplied OWASP ASVS catalog",
                error_code="CONTROL_MAPPING_CATALOG_INVALID",
                retryable=False,
                context={"violations": violations},
            )
        return mapping
