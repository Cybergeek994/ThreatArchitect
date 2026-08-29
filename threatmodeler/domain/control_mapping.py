"""Deterministic OWASP ASVS mapping used by local mock providers."""

from threatmodeler.contracts.artifacts import (
    ControlMapping,
    ControlMappingEntry,
    ControlStatus,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.control_catalogs.owasp_asvs import OwaspAsvsCatalog
from threatmodeler.shared.constants import ControlFrameworkName


class ControlMappingService:
    """Map validated requirements to curated OWASP ASVS control identifiers."""

    def __init__(
        self,
        metadata: ArtifactMetadataService,
        catalog: OwaspAsvsCatalog | None = None,
    ) -> None:
        self._metadata = metadata
        self._catalog = catalog or OwaspAsvsCatalog.load_default()

    def generate(
        self,
        model: CanonicalSystemModel,
        risks: RiskRegister,
        mitigations: MitigationPlan,
        requirements: SecurityRequirements,
    ) -> ControlMapping:
        """Generate traceable control mappings from validated artifacts.

        Args:
            model: Canonical model supplying shared assumptions.
            risks: Validated risks linked to modeled threats.
            mitigations: Validated treatments linked to risks and threats.
            requirements: Validated security requirements to map to controls.

        Returns:
            Control mapping linking requirements, threats, risks, and ASVS controls.
        """
        risk_ids_by_threat = {
            threat_id: risk.id for risk in risks.risks for threat_id in risk.threat_ids
        }
        mitigation_ids_by_threat = {
            threat_id: mitigation.id
            for mitigation in mitigations.mitigations
            for threat_id in mitigation.threat_ids
        }
        controls = []
        for requirement in requirements.requirements:
            control = self._catalog.match(
                " ".join([requirement.name, requirement.statement, requirement.description]),
                requirement.category,
            )
            fallback_assumption = (
                f"Mapped to {control.id} because no stronger keyword match was found "
                "in the curated OWASP ASVS catalog."
            )
            controls.append(
                ControlMappingEntry(
                    **self._metadata.item_fields(
                        f"control-{requirement.id}",
                        requirement.name,
                        requirement.statement,
                        requirement.evidence,
                        requirement.confidence,
                        [*model.assumptions, *requirement.assumptions, fallback_assumption],
                    ).model_dump(),
                    framework=ControlFrameworkName.OWASP_ASVS,
                    framework_control_id=control.id,
                    threat_ids=requirement.threat_ids,
                    risk_ids=[
                        risk_ids_by_threat[threat_id]
                        for threat_id in requirement.threat_ids
                        if threat_id in risk_ids_by_threat
                    ],
                    requirement_ids=[requirement.id],
                    component_ids=requirement.component_ids,
                    status=(
                        ControlStatus.NOT_STARTED
                        if any(
                            threat_id in mitigation_ids_by_threat
                            for threat_id in requirement.threat_ids
                        )
                        else ControlStatus.PARTIAL
                    ),
                )
            )
        return ControlMapping(
            **self._metadata.artifact_fields(
                "control-mapping",
                "Control Mapping",
                "Mappings between requirements, threats, risks, and OWASP ASVS controls. "
                "The catalog is a curated ASVS 4.0 subset, not the complete standard.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    controls, when_empty=requirements.confidence
                ),
            ).model_dump(),
            controls=controls,
        )
