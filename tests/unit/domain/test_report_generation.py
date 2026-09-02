"""Tests for deterministic report generation."""

from threatmodeler.contracts.artifacts import TechnicalReportSection
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.dfd_generation import DfdGenerationService
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService
from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.graph_fixtures import (
    architecture_graph_for_model,
    stride_upstream_context_for_model,
)
from tests.fixtures.mock_agent_provider import create_mock_agent_provider


class TestReportGenerationPositive:
    """Verify report artifacts reflect validated upstream data."""

    def test_generate_missing_information_creates_follow_up_items(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = ReportGenerationService(ArtifactMetadataService())

        report = service.generate_missing_information(canonical_system_model)

        assert len(report.items) == len(canonical_system_model.missing_information)
        assert report.items[0].question == canonical_system_model.missing_information[0]

    def test_generate_assumptions_creates_register_entries(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        service = ReportGenerationService(ArtifactMetadataService())

        register = service.generate_assumptions(canonical_system_model)

        assert len(register.entries) == len(canonical_system_model.assumptions)

    def test_generate_executive_summary_summarizes_validated_artifacts(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(stride_upstream_context_for_model(canonical_system_model))
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model,
            risks,
        )
        service = ReportGenerationService(metadata)

        summary = service.generate_executive_summary(
            canonical_system_model,
            threats,
            risks,
            mitigations,
        )

        assert canonical_system_model.application.name in summary.overview
        assert len(summary.key_findings) == len(threats.threats)
        assert summary.recommended_actions

    def test_with_completeness_section_appends_verify_phase_section(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(stride_upstream_context_for_model(canonical_system_model))
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        report_service = ReportGenerationService(metadata)
        base_report = report_service.generate_technical_report(
            canonical_system_model,
            threats,
            risks,
        )
        completeness = ThreatModelCompletenessService(metadata).assess(
            canonical_system_model,
            threats,
            MitigationGenerationService(metadata).generate_plan(
                canonical_system_model,
                risks,
            ),
            DfdGenerationService(metadata).generate(canonical_system_model),
            report_service.generate_missing_information(canonical_system_model),
            architecture_graph_for_model(canonical_system_model),
        )
        enriched = report_service.with_completeness_section(
            base_report,
            canonical_system_model,
            completeness,
        )

        assert len(enriched.sections) == len(base_report.sections) + 1
        assert enriched.sections[-1].title == "Verify Phase Completeness"
        assert report_service.with_completeness_section(
            enriched,
            canonical_system_model,
            completeness,
        ) == enriched

    def test_generate_technical_report_includes_completeness_when_provided(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(stride_upstream_context_for_model(canonical_system_model))
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        report_service = ReportGenerationService(metadata)
        completeness = ThreatModelCompletenessService(metadata).assess(
            canonical_system_model,
            threats,
            MitigationGenerationService(metadata).generate_plan(
                canonical_system_model,
                risks,
            ),
            DfdGenerationService(metadata).generate(canonical_system_model),
            report_service.generate_missing_information(canonical_system_model),
            architecture_graph_for_model(canonical_system_model),
        )

        report = report_service.generate_technical_report(
            canonical_system_model,
            threats,
            risks,
            completeness=completeness,
        )

        assert report.sections[-1].title == "Verify Phase Completeness"

    def test_with_completeness_section_strips_llm_verify_duplicate(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(stride_upstream_context_for_model(canonical_system_model))
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        report_service = ReportGenerationService(metadata)
        base_report = report_service.generate_technical_report(
            canonical_system_model,
            threats,
            risks,
        )
        llm_verify_section = TechnicalReportSection(
            **metadata.artifact_fields(
                "technical-report-verify-llm",
                "Verify Phase and Completeness Check",
                "Agent-authored verify narrative.",
                canonical_system_model.assumptions,
                confidence=0.8,
            ).model_dump(),
            content="DFD presence: yes. Threat coverage: partial.",
            referenced_artifact_ids=["completeness-report"],
        )
        report_with_duplicate = base_report.model_copy(
            update={"sections": [*base_report.sections, llm_verify_section]}
        )
        completeness = ThreatModelCompletenessService(metadata).assess(
            canonical_system_model,
            threats,
            MitigationGenerationService(metadata).generate_plan(
                canonical_system_model,
                risks,
            ),
            DfdGenerationService(metadata).generate(canonical_system_model),
            report_service.generate_missing_information(canonical_system_model),
            architecture_graph_for_model(canonical_system_model),
        )

        enriched = report_service.with_completeness_section(
            report_with_duplicate,
            canonical_system_model,
            completeness,
        )

        assert enriched.sections[-1].artifact_id == "technical-report-completeness"
        assert all(
            section.title != "Verify Phase and Completeness Check"
            for section in enriched.sections
        )

    def test_with_completeness_section_removes_llm_duplicate_when_deterministic_present(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        metadata = ArtifactMetadataService()
        provider = create_mock_agent_provider()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                provider,
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(stride_upstream_context_for_model(canonical_system_model))
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        report_service = ReportGenerationService(metadata)
        completeness = ThreatModelCompletenessService(metadata).assess(
            canonical_system_model,
            threats,
            MitigationGenerationService(metadata).generate_plan(
                canonical_system_model,
                risks,
            ),
            DfdGenerationService(metadata).generate(canonical_system_model),
            report_service.generate_missing_information(canonical_system_model),
            architecture_graph_for_model(canonical_system_model),
        )
        deterministic = report_service._completeness_section(canonical_system_model, completeness)
        llm_verify_section = TechnicalReportSection(
            **metadata.artifact_fields(
                "technical-report-verify-llm",
                "Verify Phase and Completeness Check",
                "Agent-authored verify narrative.",
                canonical_system_model.assumptions,
                confidence=0.8,
            ).model_dump(),
            content="Duplicate verify narrative.",
            referenced_artifact_ids=[],
        )
        base_report = report_service.generate_technical_report(
            canonical_system_model,
            threats,
            risks,
        )
        report = base_report.model_copy(
            update={"sections": [*base_report.sections, llm_verify_section, deterministic]}
        )

        cleaned = report_service.with_completeness_section(
            report,
            canonical_system_model,
            completeness,
        )

        assert cleaned.sections[-1].artifact_id == "technical-report-completeness"
        assert all(
            section.title != "Verify Phase and Completeness Check"
            for section in cleaned.sections
        )

    def test_verify_completeness_helper_matches_artifact_id(self) -> None:
        from threatmodeler.domain.report_generation import _is_verify_completeness_section

        section = TechnicalReportSection.model_construct(
            artifact_id="technical-report-completeness",
            title="Other title",
            description="Completeness",
            confidence=1.0,
            assumptions=[],
            content="Checklist",
            referenced_artifact_ids=[],
        )

        assert _is_verify_completeness_section(section) is True
