"""Markdown technical threat model report renderer."""

from pydantic import BaseModel

from threatmodeler.contracts.artifacts import (
    ArtifactBundle,
    TechnicalReportSection,
    TechnicalThreatModelReport,
)
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.renderers.markdown_section_formatter import (
    DefaultMarkdownSectionFormatter,
    MarkdownSectionFormatter,
)
from threatmodeler.renderers.mitigation_by_threat_index import MitigationByThreatIndex


class MarkdownReportRenderer:
    """Render a validated technical report as deterministic Markdown.

    Accepts either an ``ArtifactBundle`` (enriched output with artifact detail
    tables) or a standalone ``TechnicalThreatModelReport`` (basic output).
    """

    def __init__(
        self,
        artifact_name: str = "technical-report",
        section_formatter: MarkdownSectionFormatter | None = None,
    ) -> None:
        self._artifact_name = artifact_name
        self._section_formatter = section_formatter or DefaultMarkdownSectionFormatter()

    def render(self, artifact: BaseModel) -> RenderedArtifact:
        """Render report metadata, sections, artifact details, and conclusion.

        Args:
            artifact: Validated artifact bundle or technical threat model report.

        Returns:
            Deterministic Markdown artifact for the technical report.

        Raises:
            ArtifactRenderingError: If the artifact type is unsupported.
        """
        if isinstance(artifact, ArtifactBundle):
            content = self._render_enriched(artifact)
        elif isinstance(artifact, TechnicalThreatModelReport):
            content = self._render_basic(artifact)
        else:
            raise ArtifactRenderingError(
                "Markdown report rendering requires ArtifactBundle or TechnicalThreatModelReport",
                error_code="MARKDOWN_REPORT_TYPE_INVALID",
                retryable=False,
                context={"artifact_type": type(artifact).__name__},
            )
        return RenderedArtifact(
            name=self._artifact_name,
            content=content,
            media_type="text/markdown",
            file_extension=".md",
        )

    def _render_enriched(self, bundle: ArtifactBundle) -> str:
        report = bundle.technical_report
        lines = self._header_lines(report)
        lines.extend(
            self._existing_section_lines(
                report,
                skip_verify_completeness_sections=True,
            )
        )
        lines.extend(self._enriched_detail_lines(bundle))
        lines.extend(["", "## Conclusion", "", report.conclusion])
        assumption_lines = self._assumption_lines(report, bundle)
        if assumption_lines:
            lines.extend(assumption_lines)
        return "\n".join(lines) + "\n"

    def _render_basic(self, report: TechnicalThreatModelReport) -> str:
        lines = self._header_lines(report)
        lines.extend(self._existing_section_lines(report))
        lines.extend(["", "## Conclusion", "", report.conclusion])
        if report.assumptions:
            lines.extend(["", "## Assumptions", ""])
            lines.extend(f"- {assumption}" for assumption in report.assumptions)
        return "\n".join(lines) + "\n"

    def _header_lines(self, report: TechnicalThreatModelReport) -> list[str]:
        return [
            f"# {report.title}",
            "",
            report.description,
            "",
            f"**Confidence:** {report.confidence:.2f}",
            "",
            "## Scope",
            "",
            report.scope,
            "",
            "## Methodology",
            "",
            report.methodology,
        ]

    def _existing_section_lines(
        self,
        report: TechnicalThreatModelReport,
        *,
        skip_verify_completeness_sections: bool = False,
    ) -> list[str]:
        lines: list[str] = []
        for section in report.sections:
            if skip_verify_completeness_sections and self._is_verify_completeness_section(
                section
            ):
                continue
            lines.extend(["", f"## {section.title}", "", section.content])
            if section.referenced_artifact_ids:
                lines.extend(
                    [
                        "",
                        "**Referenced artifacts:** "
                        + ", ".join(section.referenced_artifact_ids),
                    ]
                )
        return lines

    @staticmethod
    def _is_verify_completeness_section(section: TechnicalReportSection) -> bool:
        if section.artifact_id == "technical-report-completeness":
            return True
        normalized = section.title.strip().lower()
        return "verify" in normalized and "completeness" in normalized

    def _enriched_detail_lines(self, bundle: ArtifactBundle) -> list[str]:
        formatter = self._section_formatter
        return [
            "",
            "## System Architecture Details",
            "",
            "### Components",
            "",
            formatter.format_components_table(bundle.component_inventory),
            "",
            "### Entry Points",
            "",
            formatter.format_entry_points_table(bundle.entry_point_inventory),
            "",
            "### Assets",
            "",
            formatter.format_assets_table(bundle.asset_inventory),
            "",
            "## Detailed Threats",
            "",
            formatter.format_threat_dossiers(
                bundle.stride_threat_register,
                MitigationByThreatIndex(bundle.mitigation_plan),
            ),
            "",
            "## Risk Register Details",
            "",
            formatter.format_risks_table(bundle.risk_register),
            "",
            "## Mitigations",
            "",
            formatter.format_mitigations_table(bundle.mitigation_plan),
            "",
            "## Security Requirements",
            "",
            formatter.format_security_requirements_table(bundle.security_requirements),
            "",
            "## Attack Scenarios",
            "",
            "### Attack Tree Summary",
            "",
            formatter.format_attack_tree_summary(bundle.attack_tree),
            "",
            "### Abuse Cases",
            "",
            formatter.format_abuse_cases_section(bundle.abuse_misuse_cases),
            "",
            "## Control Mappings",
            "",
            formatter.format_control_mappings_table(bundle.control_mapping),
            "",
            "## Completeness and Gaps",
            "",
            "### Verify Phase Completeness",
            "",
            formatter.format_completeness_section(bundle.completeness_report),
            "",
            "### Missing Information",
            "",
            formatter.format_missing_information_list(bundle.missing_information_report),
            "",
            "### Assumptions Register",
            "",
            formatter.format_assumptions_table(bundle.assumptions_register),
        ]

    def _assumption_lines(
        self,
        report: TechnicalThreatModelReport,
        bundle: ArtifactBundle,
    ) -> list[str]:
        # Prefer the structured assumptions register already rendered above;
        # only emit free-form report assumptions when the register is empty.
        if bundle.assumptions_register.entries or not report.assumptions:
            return []
        return [
            "",
            "## Assumptions",
            "",
            *[f"- {assumption}" for assumption in report.assumptions],
        ]
