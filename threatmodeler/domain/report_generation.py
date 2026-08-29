"""Deterministic register and report generation."""

from threatmodeler.contracts.artifacts import (
    AssumptionRecord,
    AssumptionsRegister,
    AssumptionStatus,
    ExecutiveSummary,
    MissingInformationItem,
    MissingInformationReport,
    MitigationPlan,
    RiskRegister,
    RiskSeverity,
    StrideThreatRegister,
    TechnicalReportSection,
    TechnicalThreatModelReport,
    ThreatModelCompletenessReport,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


def _is_verify_completeness_section(section: TechnicalReportSection) -> bool:
    """Return True when a section duplicates the pipeline completeness checklist."""
    if section.artifact_id == "technical-report-completeness":
        return True
    normalized = section.title.strip().lower()
    return "verify" in normalized and "completeness" in normalized


class ReportGenerationService:
    """Generate assumptions, gaps, and audience-specific reports."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate_assumptions(self, model: CanonicalSystemModel) -> AssumptionsRegister:
        """Generate an explicit assumptions register.

        Args:
            model: Canonical model containing extracted assumptions.

        Returns:
            Register of unverified assumptions and their potential impact.
        """
        entries = [
            AssumptionRecord(
                **self._metadata.item_fields(
                    f"assumption-{index}",
                    f"Assumption {index}",
                    statement,
                    [],
                    model.application.confidence,
                    [],
                ).model_dump(),
                rationale="Captured during canonical architecture extraction.",
                impact_if_false="Threat conclusions may require reassessment.",
                status=AssumptionStatus.UNVERIFIED,
            )
            for index, statement in enumerate(model.assumptions, start=1)
        ]
        return AssumptionsRegister(
            **self._metadata.artifact_fields(
                "assumptions-register",
                "Assumptions Register",
                "Assumptions carried forward from the canonical model.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    entries, when_empty=model.application.confidence
                ),
            ).model_dump(),
            entries=entries,
        )

    def generate_missing_information(self, model: CanonicalSystemModel) -> MissingInformationReport:
        """Generate a non-fatal missing-information report.

        Args:
            model: Canonical model containing extraction information gaps.

        Returns:
            Follow-up questions and the impact of unresolved information.
        """
        items = [
            MissingInformationItem(
                **self._metadata.item_fields(
                    f"missing-information-{index}",
                    f"Missing Information {index}",
                    statement,
                    [],
                    model.application.confidence,
                    model.assumptions,
                ).model_dump(),
                question=statement,
                impact="The affected threat-model conclusion may be incomplete.",
            )
            for index, statement in enumerate(model.missing_information, start=1)
        ]
        return MissingInformationReport(
            **self._metadata.artifact_fields(
                "missing-information-report",
                "Missing Information Report",
                "Architecture information gaps requiring follow-up.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    items, when_empty=model.application.confidence
                ),
            ).model_dump(),
            items=items,
        )

    def generate_executive_summary(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
        risks: RiskRegister,
        mitigations: MitigationPlan,
    ) -> ExecutiveSummary:
        """Generate a concise business-facing summary from validated artifacts.

        Args:
            model: Canonical model supplying application context and assumptions.
            threats: Validated STRIDE findings summarized for stakeholders.
            risks: Validated risk register used to identify top risks.
            mitigations: Validated plan used to recommend actions.

        Returns:
            Business-facing executive summary containing no free-form provider output.
        """
        top_risk_ids = [
            risk.id
            for risk in risks.risks
            if risk.severity in {RiskSeverity.HIGH, RiskSeverity.CRITICAL}
        ]
        return ExecutiveSummary(
            **self._metadata.artifact_fields(
                "executive-summary",
                "Executive Summary",
                "Business-facing summary of validated threat-model results.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    [threats, risks, mitigations],
                    when_empty=model.application.confidence,
                ),
            ).model_dump(),
            overview=(
                f"{model.application.name} has {len(threats.threats)} identified threats "
                f"and {len(risks.risks)} scored risks across "
                f"{len(model.components)} components."
            ),
            key_findings=[f"{threat.category.value}: {threat.name}" for threat in threats.threats],
            top_risk_ids=top_risk_ids,
            recommended_actions=[mitigation.name for mitigation in mitigations.mitigations],
        )

    def generate_technical_report(
        self,
        model: CanonicalSystemModel,
        threats: StrideThreatRegister,
        risks: RiskRegister,
        completeness: ThreatModelCompletenessReport | None = None,
    ) -> TechnicalThreatModelReport:
        """Generate an engineering-facing technical report.

        Args:
            model: Canonical model supplying scope and assumptions.
            threats: Validated STRIDE register summarized in the report.
            risks: Validated risk register summarized in the report.
            completeness: Optional verify-phase completeness report to include.

        Returns:
            Structured technical report assembled only from validated artifacts.
        """
        threat_section = TechnicalReportSection(
            **self._metadata.artifact_fields(
                "technical-report-threats",
                "STRIDE Threat Findings",
                "Validated STRIDE threats linked to architecture identifiers.",
                model.assumptions,
                confidence=threats.confidence,
            ).model_dump(),
            content="\n".join(
                f"- {threat.id}: {threat.name} ({threat.category.value})"
                for threat in threats.threats
            )
            or "No STRIDE threats were identified.",
            referenced_artifact_ids=[threats.artifact_id],
        )
        risk_section = TechnicalReportSection(
            **self._metadata.artifact_fields(
                "technical-report-risks",
                "Qualitative Risk Findings",
                "Validated risk records derived from STRIDE threats.",
                model.assumptions,
                confidence=risks.confidence,
            ).model_dump(),
            content="\n".join(
                f"- {risk.id}: {risk.severity.value}/{risk.likelihood.value} for "
                f"{', '.join(risk.threat_ids)}"
                for risk in risks.risks
            )
            or "No risks were scored.",
            referenced_artifact_ids=[risks.artifact_id],
        )
        architecture_section = TechnicalReportSection(
            **self._metadata.artifact_fields(
                "technical-report-architecture",
                "Architecture Scope",
                "Canonical components, data flows, and entry points in scope.",
                model.assumptions,
                confidence=model.application.confidence,
            ).model_dump(),
            content=(
                f"Components: {', '.join(component.name for component in model.components)}. "
                f"Data flows: {', '.join(flow.name for flow in model.data_flows)}. "
                f"Entry points: {', '.join(entry.name for entry in model.entry_points)}."
            ),
            referenced_artifact_ids=[],
        )
        sections = [architecture_section, threat_section, risk_section]
        if completeness is not None:
            sections.append(self._completeness_section(model, completeness))
        return TechnicalThreatModelReport(
            **self._metadata.artifact_fields(
                "technical-threat-model-report",
                "Technical Threat Model Report",
                "Engineering report assembled exclusively from validated artifacts.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    sections, when_empty=model.application.confidence
                ),
            ).model_dump(),
            scope=model.application.description,
            methodology=(
                "STRIDE analysis with deterministic qualitative risk scoring and "
                "architecture-linked abuse-case derivation."
            ),
            sections=sections,
            conclusion=(
                "Review the mitigation plan, security requirements, and missing "
                "information before approving the architecture."
            ),
        )

    def with_completeness_section(
        self,
        report: TechnicalThreatModelReport,
        model: CanonicalSystemModel,
        completeness: ThreatModelCompletenessReport,
    ) -> TechnicalThreatModelReport:
        """Append a verify-phase completeness section to an existing technical report."""
        if any(
            section.artifact_id == "technical-report-completeness"
            for section in report.sections
        ):
            cleaned_sections = [
                section
                for section in report.sections
                if section.artifact_id == "technical-report-completeness"
                or not _is_verify_completeness_section(section)
            ]
            if len(cleaned_sections) != len(report.sections):
                return report.model_copy(
                    update={
                        "sections": cleaned_sections,
                        "confidence": self._metadata.compute_confidence(
                            cleaned_sections, when_empty=report.confidence
                        ),
                    }
                )
            return report
        sections = [
            *(
                section
                for section in report.sections
                if not _is_verify_completeness_section(section)
            ),
            self._completeness_section(model, completeness),
        ]
        return report.model_copy(
            update={
                "sections": sections,
                "confidence": self._metadata.compute_confidence(
                    sections, when_empty=report.confidence
                ),
            }
        )

    def _completeness_section(
        self,
        model: CanonicalSystemModel,
        completeness: ThreatModelCompletenessReport,
    ) -> TechnicalReportSection:
        """Build the verify-phase completeness section for a technical report."""
        lines: list[str] = []
        for check in completeness.checks:
            line = f"- [{check.status.value}] {check.name}: {check.description}"
            if check.related_ids:
                line = f"{line} (ids: {', '.join(check.related_ids)})"
            lines.append(line)
        summary = (
            "Overall completeness satisfied."
            if completeness.overall_satisfied
            else "Completeness gaps require follow-up before sign-off."
        )
        return TechnicalReportSection(
            **self._metadata.artifact_fields(
                "technical-report-completeness",
                "Verify Phase Completeness",
                "Structured checklist for diagram, coverage, and mitigation linkage.",
                model.assumptions,
                confidence=completeness.confidence,
            ).model_dump(),
            content="\n".join([*lines, summary]),
            referenced_artifact_ids=[completeness.artifact_id],
        )
