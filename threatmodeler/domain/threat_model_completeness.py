"""Deterministic threat-model completeness verification (verify phase)."""

from threatmodeler.contracts.artifacts.architecture import DataFlowDiagramModel
from threatmodeler.contracts.artifacts.enums import CompletenessCheckStatus, ThreatStatus
from threatmodeler.contracts.artifacts.governance import (
    MitigationPlan,
    MissingInformationReport,
    ThreatModelCompletenessCheck,
    ThreatModelCompletenessReport,
)
from threatmodeler.contracts.artifacts.threats import StrideThreatRegister
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class ThreatModelCompletenessService:
    """Compute verify-phase completeness checks from validated artifacts."""

    _EXTERNAL_EXPOSURES = frozenset({ExposureType.EXTERNAL, ExposureType.PARTNER})

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def assess(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
        mitigations: MitigationPlan,
        dfd: DataFlowDiagramModel,
        missing_information: MissingInformationReport,
    ) -> ThreatModelCompletenessReport:
        """Build a structured completeness report for the supplied artifacts.

        Args:
            model: Canonical architecture model in scope.
            threats: Validated STRIDE threat register.
            mitigations: Validated mitigation plan.
            dfd: Validated data-flow diagram artifact.
            missing_information: Validated missing-information report.

        Returns:
            Completeness report with per-check status and overall satisfaction flag.
        """
        checks = (
            self._check_dfd_present(model, dfd),
            self._check_external_entry_coverage(model, threats),
            self._check_threat_mitigation_linkage(threats, mitigations),
            self._check_missing_information_documented(missing_information),
        )
        overall_satisfied = all(
            check.status != CompletenessCheckStatus.GAP for check in checks
        )
        return ThreatModelCompletenessReport(
            **self._metadata.artifact_fields(
                "completeness-report",
                "Threat Model Completeness Report",
                "Verify-phase checklist for diagram, coverage, and mitigation linkage.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    list(checks), when_empty=model.application.confidence
                ),
            ).model_dump(),
            checks=list(checks),
            overall_satisfied=overall_satisfied,
        )

    def _check_dfd_present(
        self,
        model: CanonicalSystemModel,
        dfd: DataFlowDiagramModel,
    ) -> ThreatModelCompletenessCheck:
        has_dfd = bool(dfd.components or dfd.data_flows or dfd.data_stores)
        has_model = bool(model.components or model.data_flows or model.data_stores)
        if has_dfd or has_model:
            return ThreatModelCompletenessCheck(
                check_id="dfd-present",
                name="Data flow diagram documented",
                description=(
                    "Architecture components, data stores, or data flows are present "
                    "in the model or DFD artifact."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id="dfd-present",
            name="Data flow diagram documented",
            description="No components, data stores, or data flows were documented.",
            status=CompletenessCheckStatus.GAP,
        )

    def _check_external_entry_coverage(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
    ) -> ThreatModelCompletenessCheck:
        external_entries = [
            entry
            for entry in model.entry_points
            if entry.exposure in self._EXTERNAL_EXPOSURES
        ]
        if not external_entries:
            return ThreatModelCompletenessCheck(
                check_id="external-entry-coverage",
                name="External entry point threat coverage",
                description="No external or partner entry points require threat coverage.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        covered_components = self._threat_component_ids(threats)
        uncovered = [
            entry.id
            for entry in external_entries
            if entry.component_id not in covered_components
        ]
        if not uncovered:
            return ThreatModelCompletenessCheck(
                check_id="external-entry-coverage",
                name="External entry point threat coverage",
                description=(
                    "Every external or partner entry point component is referenced "
                    "by at least one threat."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id="external-entry-coverage",
            name="External entry point threat coverage",
            description=(
                "External or partner entry points lack a threat referencing their "
                "component id."
            ),
            status=CompletenessCheckStatus.GAP,
            related_ids=uncovered,
        )

    def _check_threat_mitigation_linkage(
        self,
        threats: StrideThreatRegister,
        mitigations: MitigationPlan,
    ) -> ThreatModelCompletenessCheck:
        if not threats.threats:
            return ThreatModelCompletenessCheck(
                check_id="threat-mitigation-linkage",
                name="Threat mitigation linkage",
                description="No threats were identified; mitigation linkage is not applicable.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        mitigated_threat_ids = {
            threat_id
            for mitigation in mitigations.mitigations
            for threat_id in mitigation.threat_ids
        }
        unlinked = [
            threat.id
            for threat in threats.threats
            if threat.status not in {ThreatStatus.ACCEPTED, ThreatStatus.MITIGATED}
            and threat.id not in mitigated_threat_ids
        ]
        if not unlinked:
            return ThreatModelCompletenessCheck(
                check_id="threat-mitigation-linkage",
                name="Threat mitigation linkage",
                description=(
                    "Every open threat is linked to at least one mitigation, or is "
                    "marked mitigated or accepted."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id="threat-mitigation-linkage",
            name="Threat mitigation linkage",
            description="One or more threats lack mitigation linkage.",
            status=CompletenessCheckStatus.GAP,
            related_ids=unlinked,
        )

    def _check_missing_information_documented(
        self,
        missing_information: MissingInformationReport,
    ) -> ThreatModelCompletenessCheck:
        if missing_information.items:
            return ThreatModelCompletenessCheck(
                check_id="missing-information-documented",
                name="Missing information documented",
                description=(
                    "Evidence gaps are recorded in the missing-information report."
                ),
                status=CompletenessCheckStatus.SATISFIED,
                related_ids=[item.id for item in missing_information.items],
            )
        return ThreatModelCompletenessCheck(
            check_id="missing-information-documented",
            name="Missing information documented",
            description=(
                "No missing-information items were recorded; confirm the source is "
                "complete or document gaps explicitly."
            ),
            status=CompletenessCheckStatus.SATISFIED,
        )

    @staticmethod
    def _threat_component_ids(threats: StrideThreatRegister) -> set[str]:
        covered: set[str] = set()
        for threat in threats.threats:
            if threat.component_id:
                covered.add(threat.component_id)
            covered.update(threat.component_ids)
            covered.update(threat.affected_component_ids)
        return covered
