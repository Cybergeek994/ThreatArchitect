"""Business validation for generated control mappings."""

from threatmodeler.contracts.artifacts import ControlMapping
from threatmodeler.domain.control_catalogs.owasp_asvs import OwaspAsvsCatalog
from threatmodeler.errors.application import AgentSchemaValidationError
from threatmodeler.shared.constants import ControlFrameworkName


class ControlMappingCatalogRule:
    """Require agent control mappings to use catalogued OWASP ASVS identifiers."""

    def __init__(self, catalog: OwaspAsvsCatalog | None = None) -> None:
        self._catalog = catalog or OwaspAsvsCatalog.load_default()

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
            if not self._catalog.contains(entry.framework_control_id):
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
