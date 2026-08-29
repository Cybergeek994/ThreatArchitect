"""Deterministic risk scoring from validated STRIDE threats."""

from threatmodeler.contracts.artifacts import (
    RiskLikelihood,
    RiskRecord,
    RiskRegister,
    RiskSeverity,
    RiskStatus,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class RiskScoringService:
    """Assign closed severity and likelihood values to validated threats."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> RiskRegister:
        """Generate one deterministic risk record per STRIDE threat.

        Args:
            model: Canonical model supplying shared assumptions and entry points.
            threat_register: Validated threats requiring qualitative scoring.

        Returns:
            Risk register with closed likelihood, severity, and status values.
        """
        external_component_ids = {
            entry.component_id
            for entry in model.entry_points
            if entry.exposure is ExposureType.EXTERNAL
        }
        risks = [
            RiskRecord(
                **self._metadata.item_fields(
                    f"risk-{threat.id}",
                    f"Risk: {threat.name}",
                    threat.impact,
                    threat.evidence,
                    threat.confidence,
                    [*model.assumptions, *threat.assumptions],
                ).model_dump(),
                threat_ids=[threat.id],
                severity=self._severity(threat),
                likelihood=self._likelihood(threat, external_component_ids),
                status=RiskStatus.OPEN,
            )
            for threat in threat_register.threats
        ]
        return RiskRegister(
            **self._metadata.artifact_fields(
                "risk-register",
                "Risk Register",
                "Qualitative risks scored from the validated STRIDE threat register.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    risks, when_empty=threat_register.confidence
                ),
            ).model_dump(),
            risks=risks,
        )

    def _severity(self, threat: StrideThreat) -> RiskSeverity:
        """Determine severity from STRIDE category and impact assessment.

        Uses OWASP risk assessment questions when impact_assessment is present:
        - Full system compromise -> CRITICAL
        - Admin access or sensitive data exposure -> HIGH
        - System crash possible -> HIGH (for availability threats)
        Falls back to STRIDE-category-based defaults otherwise.
        """
        if threat.impact_assessment is not None:
            impact = threat.impact_assessment
            if impact.full_system_compromise:
                return RiskSeverity.CRITICAL
            if impact.admin_access_possible or impact.sensitive_data_exposure:
                return RiskSeverity.HIGH
            if impact.system_crash_possible:
                return RiskSeverity.HIGH

        return self._severity_from_category(threat.category)

    def _severity_from_category(self, category: StrideCategory) -> RiskSeverity:
        """Determine severity from STRIDE category alone (legacy behavior)."""
        if category in {
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.ELEVATION_OF_PRIVILEGE,
        }:
            return RiskSeverity.HIGH
        if category in {
            StrideCategory.SPOOFING,
            StrideCategory.TAMPERING,
            StrideCategory.DENIAL_OF_SERVICE,
        }:
            return RiskSeverity.MEDIUM
        return RiskSeverity.LOW

    def _likelihood(
        self,
        threat: StrideThreat,
        external_component_ids: set[str],
    ) -> RiskLikelihood:
        """Determine likelihood from exploitability assessment and exposure.

        Uses OWASP risk assessment questions when exploitability is present:
        - Remote + automatable + no auth -> ALMOST_CERTAIN
        - Remote + automatable -> LIKELY
        - Remote -> LIKELY (if external components)
        Falls back to exposure-based defaults otherwise.
        """
        if threat.exploitability is not None:
            exploit = threat.exploitability
            if exploit.exploitable_remotely:
                if exploit.exploit_automatable and not exploit.requires_authentication:
                    return RiskLikelihood.ALMOST_CERTAIN
                if exploit.exploit_automatable:
                    return RiskLikelihood.LIKELY
                return RiskLikelihood.LIKELY
            if exploit.exploit_automatable:
                return RiskLikelihood.POSSIBLE
            return RiskLikelihood.UNLIKELY

        return self._likelihood_from_exposure(threat, external_component_ids)

    def _likelihood_from_exposure(
        self,
        threat: StrideThreat,
        external_component_ids: set[str],
    ) -> RiskLikelihood:
        """Determine likelihood from component exposure (legacy behavior)."""
        component_ids = set(threat.component_ids)
        if threat.component_id:
            component_ids.add(threat.component_id)
        if component_ids & external_component_ids:
            return RiskLikelihood.LIKELY
        return RiskLikelihood.POSSIBLE
