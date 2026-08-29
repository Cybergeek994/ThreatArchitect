"""Deterministic mitigation and security-requirement generation."""

from threatmodeler.contracts.artifacts import (
    Mitigation,
    MitigationPlan,
    MitigationStatus,
    RiskRegister,
    RiskSeverity,
    SecurityRequirement,
    SecurityRequirementCategory,
    SecurityRequirements,
    StrideThreatRegister,
    WorkPriority,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class MitigationGenerationService:
    """Generate treatments and verifiable requirements from validated risks."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate_plan(
        self,
        model: CanonicalSystemModel,
        risks: RiskRegister,
    ) -> MitigationPlan:
        """Generate one treatment for every validated risk.

        Args:
            model: Canonical model supplying shared assumptions.
            risks: Validated risk register requiring treatment.

        Returns:
            Mitigation plan linked to all supplied risks and threats.
        """
        mitigations = [
            Mitigation(
                **self._metadata.item_fields(
                    f"mitigation-{risk.id}",
                    f"Mitigate {risk.name}",
                    f"Implement controls for {risk.name} affecting {', '.join(risk.threat_ids)}.",
                    risk.evidence,
                    risk.confidence,
                    [*model.assumptions, *risk.assumptions],
                ).model_dump(),
                risk_ids=[risk.id],
                threat_ids=risk.threat_ids,
                status=MitigationStatus.PROPOSED,
                priority=self._priority(risk.severity),
            )
            for risk in risks.risks
        ]
        return MitigationPlan(
            **self._metadata.artifact_fields(
                "mitigation-plan",
                "Mitigation Plan",
                "Risk treatments derived from the validated risk register.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    mitigations, when_empty=risks.confidence
                ),
            ).model_dump(),
            mitigations=mitigations,
        )

    def generate_requirements(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
        risks: RiskRegister,
    ) -> SecurityRequirements:
        """Generate verifiable requirements linked to threats and risks.

        Args:
            model: Canonical model supplying assumptions and architecture identifiers.
            threats: Validated STRIDE register driving requirement creation.
            risks: Validated risks used to determine requirement priority.

        Returns:
            Security requirements linked to their source threats and components.
        """
        risk_by_threat = {threat_id: risk for risk in risks.risks for threat_id in risk.threat_ids}
        requirements = []
        for threat in threats.threats:
            risk = risk_by_threat.get(threat.id)
            severity = risk.severity if risk is not None else RiskSeverity.MEDIUM
            component_targets = threat.component_ids or [threat.component_id or "the system"]
            requirements.append(
                SecurityRequirement(
                    **self._metadata.item_fields(
                        f"requirement-{threat.id}",
                        f"Control {threat.name}",
                        f"Security requirement derived from threat {threat.id}.",
                        threat.evidence,
                        threat.confidence,
                        [*model.assumptions, *threat.assumptions],
                    ).model_dump(),
                    statement=(
                        f"The system shall enforce controls that prevent or detect "
                        f"{threat.category.value.replace('_', ' ')} against "
                        f"{', '.join(component_targets)}."
                    ),
                    category=self._requirement_category(threat.category.value),
                    priority=self._priority(severity),
                    component_ids=threat.component_ids
                    or ([threat.component_id] if threat.component_id else []),
                    threat_ids=[threat.id],
                    verification_method="Automated test or documented security review",
                )
            )
        return SecurityRequirements(
            **self._metadata.artifact_fields(
                "security-requirements",
                "Security Requirements",
                "Verifiable requirements derived from validated threats and risks.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    requirements, when_empty=threats.confidence
                ),
            ).model_dump(),
            requirements=requirements,
        )

    def _priority(self, severity: RiskSeverity) -> WorkPriority:
        if severity is RiskSeverity.CRITICAL:
            return WorkPriority.CRITICAL
        if severity is RiskSeverity.HIGH:
            return WorkPriority.HIGH
        if severity is RiskSeverity.MEDIUM:
            return WorkPriority.MEDIUM
        return WorkPriority.LOW

    def _requirement_category(self, category: str) -> SecurityRequirementCategory:
        if category == "spoofing":
            return SecurityRequirementCategory.AUTHENTICATION
        if category in {"tampering", "repudiation"}:
            return SecurityRequirementCategory.INTEGRITY
        if category == "information_disclosure":
            return SecurityRequirementCategory.CONFIDENTIALITY
        if category == "denial_of_service":
            return SecurityRequirementCategory.AVAILABILITY
        return SecurityRequirementCategory.AUTHORIZATION
