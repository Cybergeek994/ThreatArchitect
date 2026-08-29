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
    ThreatStatus,
    WorkPriority,
)
from threatmodeler.contracts.artifacts.architecture import DataFlowDiagramModel
from threatmodeler.contracts.system_model import CanonicalSystemModel, ExposureType
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService


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
        )

        coverage = next(
            check for check in report.checks if check.check_id == "external-entry-coverage"
        )
        assert coverage.status == CompletenessCheckStatus.NOT_APPLICABLE

    def test_threat_component_ids_includes_list_and_affected_fields(
        self,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        threat = StrideThreat(
            **item_fields_factory("threat-multi"),
            category=StrideCategory.TAMPERING,
            status=ThreatStatus.IDENTIFIED,
            component_ids=["component-a"],
            affected_component_ids=["component-b"],
            impact="Impact.",
        )
        covered = ThreatModelCompletenessService._threat_component_ids(
            StrideThreatRegister(
                artifact_id="stride",
                title="STRIDE",
                description="t",
                confidence=0.8,
                assumptions=[],
                threats=[threat],
            )
        )

        assert covered == {"component-a", "component-b"}
