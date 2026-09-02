"""Build control mappings from LLM-ranked ASVS candidates."""

from threatmodeler.contracts.artifacts import (
    ControlMapping,
    ControlMappingEntry,
    ControlStatus,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
)
from threatmodeler.contracts.control_catalog import RequirementMappingNeed
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.control_catalogs.asvs_compact_index import AsvsCompactIndexBuilder
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.infrastructure.control_catalogs.asvs_control_registry_factory import (
    AsvsControlRegistryFactory,
)
from threatmodeler.ports.asvs_semantic_ranker import AsvsSemanticRanker
from threatmodeler.shared.constants import ControlFrameworkName


class ControlMappingService:
    """Map validated requirements to ranked OWASP ASVS 5.0 controls."""

    def __init__(
        self,
        metadata: ArtifactMetadataService,
        ranker: AsvsSemanticRanker,
        registry: AsvsControlRegistry | None = None,
        *,
        registry_factory: AsvsControlRegistryFactory | None = None,
        compact_index_builder: AsvsCompactIndexBuilder | None = None,
    ) -> None:
        self._metadata = metadata
        self._ranker = ranker
        self._registry = registry or (registry_factory or AsvsControlRegistryFactory.packaged()).create()
        builder = compact_index_builder or AsvsCompactIndexBuilder()
        self._compact_index = builder.build(self._registry.snapshot)

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
        needs = tuple(
            RequirementMappingNeed(
                requirement_id=requirement.id,
                implementation_need=" ".join(
                    part
                    for part in (
                        requirement.name,
                        requirement.statement,
                        requirement.description,
                    )
                    if part
                ),
                category=requirement.category.value,
            )
            for requirement in requirements.requirements
        )
        ranked_by_requirement = {
            mapping.requirement_id: mapping
            for mapping in self._ranker.rank_all(
                needs,
                self._compact_index,
            ).mappings
        }
        controls = []
        for requirement in requirements.requirements:
            ranked = ranked_by_requirement[requirement.id]
            primary = ranked.candidates[0]
            mapping_assumption = (
                f"Mapped to {primary.id} from LLM-ranked ASVS 5.0 candidates "
                f"for requirement {requirement.id}."
            )
            controls.append(
                ControlMappingEntry(
                    **self._metadata.item_fields(
                        f"control-{requirement.id}",
                        requirement.name,
                        requirement.statement,
                        requirement.evidence,
                        requirement.confidence,
                        [*model.assumptions, *requirement.assumptions, mapping_assumption],
                    ).model_dump(),
                    framework=ControlFrameworkName.OWASP_ASVS,
                    framework_control_id=primary.id,
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
                "Mappings between requirements, threats, risks, and OWASP ASVS 5.0 controls.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    controls, when_empty=requirements.confidence
                ),
            ).model_dump(),
            controls=controls,
        )
