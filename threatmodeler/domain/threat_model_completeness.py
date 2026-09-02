"""Deterministic threat-model completeness verification (verify phase)."""

from threatmodeler.contracts.artifacts.architecture import DataFlowDiagramModel
from threatmodeler.contracts.artifacts.enums import (
    CompletenessCheckId,
    CompletenessCheckStatus,
    ThreatStatus,
)
from threatmodeler.contracts.artifacts.governance import (
    MitigationPlan,
    MissingInformationReport,
    ThreatModelCompletenessCheck,
    ThreatModelCompletenessReport,
)
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph
from threatmodeler.contracts.artifacts.threats import StrideThreatRegister
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class ThreatModelCompletenessService:
    """Compute verify-phase completeness checks from validated artifacts."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def assess(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
        mitigations: MitigationPlan,
        dfd: DataFlowDiagramModel,
        missing_information: MissingInformationReport,
        architecture_graph: ArchitectureGraph,
    ) -> ThreatModelCompletenessReport:
        """Build a structured completeness report for the supplied artifacts.

        Args:
            model: Canonical architecture model in scope.
            threats: Validated STRIDE threat register.
            mitigations: Validated mitigation plan.
            dfd: Validated data-flow diagram artifact.
            missing_information: Validated missing-information report.
            architecture_graph: Validated architecture graph with attack paths.

        Returns:
            Completeness report with per-check status and overall satisfaction flag.
        """
        checks = (
            self._check_dfd_present(model, dfd),
            self._check_external_entry_coverage(model, threats),
            self._check_architecture_graph_entry_path_coverage(model, architecture_graph),
            self._check_threat_attack_path_grounded(threats, architecture_graph),
            self._check_threat_mitigation_linkage(threats, mitigations),
            self._check_threat_evidence_present(threats),
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
                check_id=CompletenessCheckId.DFD_PRESENT.value,
                name="Data flow diagram documented",
                description=(
                    "Architecture components, data stores, or data flows are present "
                    "in the model or DFD artifact."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.DFD_PRESENT.value,
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
            entry for entry in model.entry_points if entry.exposure.is_external_facing()
        ]
        if not external_entries:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.EXTERNAL_ENTRY_COVERAGE.value,
                name="External entry point threat coverage",
                description="No external or partner entry points require threat coverage.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        covered_entry_ids = {
            threat.provenance.entry_point_id
            for threat in threats.threats
            if threat.provenance.entry_point_id is not None
        }
        uncovered = [
            entry.id for entry in external_entries if entry.id not in covered_entry_ids
        ]
        if not uncovered:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.EXTERNAL_ENTRY_COVERAGE.value,
                name="External entry point threat coverage",
                description=(
                    "Every external or partner entry point is referenced by at least "
                    "one threat via provenance.entry_point_id."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.EXTERNAL_ENTRY_COVERAGE.value,
            name="External entry point threat coverage",
            description=(
                "External or partner entry points lack a threat with matching "
                "provenance.entry_point_id."
            ),
            status=CompletenessCheckStatus.GAP,
            related_ids=uncovered,
        )

    def _check_architecture_graph_entry_path_coverage(
        self,
        model: CanonicalSystemModel,
        architecture_graph: ArchitectureGraph,
    ) -> ThreatModelCompletenessCheck:
        external_entries = [
            entry for entry in model.entry_points if entry.exposure.is_external_facing()
        ]
        if not external_entries:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.ARCHITECTURE_GRAPH_ENTRY_PATH_COVERAGE.value,
                name="Architecture graph entry path coverage",
                description="No external or partner entry points require graph attack paths.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        entry_node_ids = {
            node.entry_point_id
            for node in architecture_graph.nodes
            if node.entry_point_id is not None
        }
        covered_entry_ids = {
            node.entry_point_id
            for path in architecture_graph.attack_paths
            for node in architecture_graph.nodes
            if node.id == path.entry_node_id and node.entry_point_id is not None
        }
        uncovered = [
            entry.id
            for entry in external_entries
            if entry.id in entry_node_ids and entry.id not in covered_entry_ids
        ]
        if not uncovered:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.ARCHITECTURE_GRAPH_ENTRY_PATH_COVERAGE.value,
                name="Architecture graph entry path coverage",
                description=(
                    "Every external or partner entry point represented in the graph "
                    "has at least one enumerated attack path."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.ARCHITECTURE_GRAPH_ENTRY_PATH_COVERAGE.value,
            name="Architecture graph entry path coverage",
            description=(
                "External or partner entry points lack an enumerated attack path "
                "in the architecture graph."
            ),
            status=CompletenessCheckStatus.GAP,
            related_ids=uncovered,
        )

    def _check_threat_attack_path_grounded(
        self,
        threats: StrideThreatRegister,
        architecture_graph: ArchitectureGraph,
    ) -> ThreatModelCompletenessCheck:
        if not threats.threats:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.THREAT_ATTACK_PATH_GROUNDED.value,
                name="Threat attack path grounding",
                description="No threats were identified; attack path grounding is not applicable.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        known_path_ids = {path.id for path in architecture_graph.attack_paths}
        ungrounded = [
            threat.id
            for threat in threats.threats
            if threat.provenance.attack_path_id not in known_path_ids
        ]
        if not ungrounded:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.THREAT_ATTACK_PATH_GROUNDED.value,
                name="Threat attack path grounding",
                description="Every threat cites a valid architecture graph attack path id.",
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.THREAT_ATTACK_PATH_GROUNDED.value,
            name="Threat attack path grounding",
            description="One or more threats cite an unknown attack_path_id.",
            status=CompletenessCheckStatus.GAP,
            related_ids=ungrounded,
        )

    def _check_threat_mitigation_linkage(
        self,
        threats: StrideThreatRegister,
        mitigations: MitigationPlan,
    ) -> ThreatModelCompletenessCheck:
        if not threats.threats:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.THREAT_MITIGATION_LINKAGE.value,
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
                check_id=CompletenessCheckId.THREAT_MITIGATION_LINKAGE.value,
                name="Threat mitigation linkage",
                description=(
                    "Every open threat is linked to at least one mitigation, or is "
                    "marked mitigated or accepted."
                ),
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.THREAT_MITIGATION_LINKAGE.value,
            name="Threat mitigation linkage",
            description="One or more threats lack mitigation linkage.",
            status=CompletenessCheckStatus.GAP,
            related_ids=unlinked,
        )

    def _check_threat_evidence_present(
        self,
        threats: StrideThreatRegister,
    ) -> ThreatModelCompletenessCheck:
        if not threats.threats:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.THREAT_EVIDENCE_PRESENT.value,
                name="Threat evidence present",
                description="No threats were identified; evidence coverage is not applicable.",
                status=CompletenessCheckStatus.NOT_APPLICABLE,
            )
        missing_evidence = [threat.id for threat in threats.threats if not threat.evidence]
        if not missing_evidence:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.THREAT_EVIDENCE_PRESENT.value,
                name="Threat evidence present",
                description="Every threat includes non-empty evidence.",
                status=CompletenessCheckStatus.SATISFIED,
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.THREAT_EVIDENCE_PRESENT.value,
            name="Threat evidence present",
            description="One or more threats lack evidence.",
            status=CompletenessCheckStatus.GAP,
            related_ids=missing_evidence,
        )

    def _check_missing_information_documented(
        self,
        missing_information: MissingInformationReport,
    ) -> ThreatModelCompletenessCheck:
        if missing_information.items:
            return ThreatModelCompletenessCheck(
                check_id=CompletenessCheckId.MISSING_INFORMATION_DOCUMENTED.value,
                name="Missing information documented",
                description=(
                    "Evidence gaps are recorded in the missing-information report."
                ),
                status=CompletenessCheckStatus.SATISFIED,
                related_ids=[item.id for item in missing_information.items],
            )
        return ThreatModelCompletenessCheck(
            check_id=CompletenessCheckId.MISSING_INFORMATION_DOCUMENTED.value,
            name="Missing information documented",
            description=(
                "No missing-information items were recorded; confirm the source is "
                "complete or document gaps explicitly."
            ),
            status=CompletenessCheckStatus.SATISFIED,
        )
