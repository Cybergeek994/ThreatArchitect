"""Tests for verify-phase threat-model completeness assessment."""

from collections.abc import Callable
from typing import Any

import pytest
from threatmodeler.contracts import Evidence, SourceReference, SourceType
from threatmodeler.contracts.artifacts import (
    CompletenessCheckStatus,
    Mitigation,
    MitigationPlan,
    MitigationStatus,
    MissingInformationReport,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    ThreatProvenance,
    ThreatStatus,
    WorkPriority,
)
from threatmodeler.contracts.artifacts.architecture import DataFlowDiagramModel
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService

from tests.fixtures.graph_fixtures import (
    architecture_graph_for_model,
    attack_path_narrative,
    default_attack_path_id,
)


@pytest.fixture
def completeness_service() -> ThreatModelCompletenessService:
    """Provide a completeness service with production metadata."""
    return ThreatModelCompletenessService(ArtifactMetadataService())


@pytest.fixture
def item_fields_factory() -> Callable[[str], dict[str, Any]]:
    """Return minimal artifact-item fields for threat records."""

    def create(item_id: str) -> dict[str, Any]:
        source = SourceReference(
            source_type=SourceType.CONFLUENCE_PAGE,
            source_id="page-1",
            location="section",
            excerpt="evidence",
        )
        evidence = [
            Evidence(summary="supported", source_references=[source]),
        ]
        return {
            "id": item_id,
            "name": item_id,
            "description": "test item",
            "evidence": evidence,
            "confidence": 0.8,
            "assumptions": [],
        }

    return create


def _default_provenance(
    model: CanonicalSystemModel,
    *,
    entry_point_id: str | None = None,
    actor_id: str | None = None,
    trust_boundary_id: str | None = None,
) -> ThreatProvenance:
    graph = architecture_graph_for_model(model)
    attack_path_id = default_attack_path_id(graph)
    return ThreatProvenance(
        entry_point_id=entry_point_id,
        actor_id=actor_id,
        trust_boundary_id=trust_boundary_id,
        attack_path_id=attack_path_id,
        attack_path=attack_path_narrative(graph, attack_path_id),
        rationale="Identified from architecture evidence in the fixture.",
    )


class TestThreatModelCompletenessServicePositive:
    """Verify completeness checks for supported scenarios."""

    def test_assess_satisfied_when_external_entries_covered_and_mitigated(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        external_entry = next(
            entry
            for entry in canonical_system_model.entry_points
            if entry.exposure == ExposureType.EXTERNAL
        )
        threat = StrideThreat(
            **item_fields_factory("threat-api"),
            category=StrideCategory.SPOOFING,
            status=ThreatStatus.IDENTIFIED,
            component_id=external_entry.component_id,
            impact="Unauthorized access.",
            provenance=_default_provenance(
                canonical_system_model,
                entry_point_id=external_entry.id,
                actor_id=external_entry.actor_id,
            ),
        )
        threats = StrideThreatRegister(
            artifact_id="stride-register",
            title="STRIDE",
            description="threats",
            confidence=0.8,
            assumptions=[],
            threats=[threat],
        )
        mitigation = Mitigation(
            **item_fields_factory("mitigation-1"),
            threat_ids=[threat.id],
            status=MitigationStatus.PLANNED,
            priority=WorkPriority.HIGH,
        )
        mitigations = MitigationPlan(
            artifact_id="mitigation-plan",
            title="Mitigations",
            description="plan",
            confidence=0.8,
            assumptions=[],
            mitigations=[mitigation],
        )
        dfd = DataFlowDiagramModel(
            artifact_id="dfd",
            title="DFD",
            description="diagram",
            confidence=0.8,
            assumptions=[],
            components=[],
            data_stores=[],
            data_flows=[],
        )
        missing = MissingInformationReport(
            artifact_id="missing",
            title="Missing",
            description="gaps",
            confidence=0.8,
            assumptions=[],
            items=[],
        )

        report = completeness_service.assess(
            canonical_system_model,
            threats,
            mitigations,
            dfd,
            missing,
            architecture_graph_for_model(canonical_system_model),
        )

        coverage = next(
            check for check in report.checks if check.check_id == "external-entry-coverage"
        )
        assert coverage.status in {
            CompletenessCheckStatus.SATISFIED,
            CompletenessCheckStatus.NOT_APPLICABLE,
        }
        linkage = next(
            check for check in report.checks if check.check_id == "threat-mitigation-linkage"
        )
        assert linkage.status == CompletenessCheckStatus.SATISFIED
        assert report.overall_satisfied


class TestThreatModelCompletenessServiceNegative:
    """Verify gap detection for incomplete threat models."""

    def test_external_entry_gap_when_component_not_in_threats(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        if not any(
            entry.exposure == ExposureType.EXTERNAL
            for entry in canonical_system_model.entry_points
        ):
            pytest.skip("Fixture has no external entry points")

        threat = StrideThreat(
            **item_fields_factory("threat-unrelated"),
            category=StrideCategory.TAMPERING,
            status=ThreatStatus.IDENTIFIED,
            component_id="nonexistent-component",
            impact="Impact.",
            provenance=_default_provenance(canonical_system_model),
        )
        threats = StrideThreatRegister(
            artifact_id="stride-register",
            title="STRIDE",
            description="threats",
            confidence=0.8,
            assumptions=[],
            threats=[threat],
        )
        report = completeness_service.assess(
            canonical_system_model,
            threats,
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(canonical_system_model),
        )

        coverage = next(
            check for check in report.checks if check.check_id == "external-entry-coverage"
        )
        assert coverage.status == CompletenessCheckStatus.GAP
        assert coverage.related_ids
        assert report.overall_satisfied is False

    def test_mitigation_linkage_gap_for_open_threat(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        threat = StrideThreat(
            **item_fields_factory("threat-open"),
            category=StrideCategory.REPUDIATION,
            status=ThreatStatus.IDENTIFIED,
            component_id=canonical_system_model.components[0].id,
            impact="Impact.",
            provenance=_default_provenance(
                canonical_system_model,
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
            ),
        )
        threats = StrideThreatRegister(
            artifact_id="stride-register",
            title="STRIDE",
            description="threats",
            confidence=0.8,
            assumptions=[],
            threats=[threat],
        )
        report = completeness_service.assess(
            canonical_system_model,
            threats,
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(canonical_system_model),
        )

        linkage = next(
            check for check in report.checks if check.check_id == "threat-mitigation-linkage"
        )
        assert linkage.status == CompletenessCheckStatus.GAP
        assert threat.id in linkage.related_ids

    def test_dfd_gap_when_model_and_dfd_are_empty(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        empty_model = canonical_system_model.model_copy(
            update={"components": [], "data_flows": [], "data_stores": []}
        )
        report = completeness_service.assess(
            empty_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(empty_model),
        )

        dfd_check = next(check for check in report.checks if check.check_id == "dfd-present")
        assert dfd_check.status == CompletenessCheckStatus.GAP

    def test_external_entry_not_applicable_when_only_internal_exposure(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        internal_model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    entry.model_copy(update={"exposure": ExposureType.INTERNAL})
                    for entry in canonical_system_model.entry_points
                ]
            }
        )
        report = completeness_service.assess(
            internal_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(internal_model),
        )

        coverage = next(
            check for check in report.checks if check.check_id == "external-entry-coverage"
        )
        assert coverage.status == CompletenessCheckStatus.NOT_APPLICABLE

    def test_external_entry_gap_when_component_covered_but_entry_point_id_missing(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        external_entry = next(
            entry
            for entry in canonical_system_model.entry_points
            if entry.exposure == ExposureType.EXTERNAL
        )
        threat = StrideThreat(
            **item_fields_factory("threat-component-only"),
            category=StrideCategory.TAMPERING,
            status=ThreatStatus.IDENTIFIED,
            component_id=external_entry.component_id,
            impact="Impact.",
            provenance=_default_provenance(canonical_system_model),
        )
        report = completeness_service.assess(
            canonical_system_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[threat],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(canonical_system_model),
        )

        coverage = next(
            check for check in report.checks if check.check_id == "external-entry-coverage"
        )
        assert coverage.status == CompletenessCheckStatus.GAP
        assert external_entry.id in coverage.related_ids

    def test_threat_evidence_not_applicable_when_no_threats(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        internal_evidence_model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    entry.model_copy(update={"exposure": ExposureType.INTERNAL})
                    for entry in canonical_system_model.entry_points
                ]
            }
        )
        report = completeness_service.assess(
            internal_evidence_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(internal_evidence_model),
        )
        evidence_check = next(
            check for check in report.checks if check.check_id == "threat-evidence-present"
        )
        assert evidence_check.status == CompletenessCheckStatus.NOT_APPLICABLE

    def test_threat_evidence_gap_when_evidence_empty(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        fields = item_fields_factory("threat-no-evidence")
        fields["evidence"] = []
        threat = StrideThreat.model_construct(
            **fields,
            category=StrideCategory.SPOOFING,
            status=ThreatStatus.IDENTIFIED,
            component_id=canonical_system_model.components[0].id,
            impact="Impact.",
            provenance=_default_provenance(
                canonical_system_model,
                entry_point_id=canonical_system_model.entry_points[0].id,
                actor_id=canonical_system_model.entry_points[0].actor_id,
            ),
        )
        report = completeness_service.assess(
            canonical_system_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[threat],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            architecture_graph_for_model(canonical_system_model),
        )
        evidence_check = next(
            check for check in report.checks if check.check_id == "threat-evidence-present"
        )
        assert evidence_check.status == CompletenessCheckStatus.GAP
        assert threat.id in evidence_check.related_ids

    def test_architecture_graph_entry_path_gap_when_entry_uncovered(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        uncovered_graph = graph.model_copy(
            update={
                "attack_paths": [
                    path.model_copy(update={"entry_node_id": path.target_node_id})
                    for path in graph.attack_paths
                ]
            }
        )
        report = completeness_service.assess(
            canonical_system_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            uncovered_graph,
        )
        coverage = next(
            check
            for check in report.checks
            if check.check_id == "architecture-graph-entry-path-coverage"
        )
        assert coverage.status == CompletenessCheckStatus.GAP
        assert coverage.related_ids

    def test_threat_attack_path_grounded_gap_when_path_unknown(
        self,
        completeness_service: ThreatModelCompletenessService,
        canonical_system_model: CanonicalSystemModel,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        graph = architecture_graph_for_model(canonical_system_model)
        provenance = _default_provenance(canonical_system_model)
        provenance = provenance.model_copy(update={"attack_path_id": "missing-path"})
        threat = StrideThreat(
            **item_fields_factory("threat-ungrounded"),
            category=StrideCategory.SPOOFING,
            status=ThreatStatus.IDENTIFIED,
            component_id=canonical_system_model.components[0].id,
            impact="Impact.",
            provenance=provenance,
        )
        report = completeness_service.assess(
            canonical_system_model,
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[threat],
            ),
            MitigationPlan(
                artifact_id="mitigation-plan",
                title="Mitigations",
                description="plan",
                confidence=0.8,
                assumptions=[],
                mitigations=[],
            ),
            DataFlowDiagramModel(
                artifact_id="dfd",
                title="DFD",
                description="diagram",
                confidence=0.8,
                assumptions=[],
                components=[],
                data_stores=[],
                data_flows=[],
            ),
            MissingInformationReport(
                artifact_id="missing",
                title="Missing",
                description="gaps",
                confidence=0.8,
                assumptions=[],
                items=[],
            ),
            graph,
        )
        grounding = next(
            check for check in report.checks if check.check_id == "threat-attack-path-grounded"
        )
        assert grounding.status == CompletenessCheckStatus.GAP
        assert threat.id in grounding.related_ids
