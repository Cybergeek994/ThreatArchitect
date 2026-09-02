"""Deterministic Markdown section formatters for technical-report enrichment."""

from enum import IntEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from threatmodeler.contracts.artifacts import (
    AbuseMisuseCases,
    AssetInventory,
    AssumptionsRegister,
    AttackTree,
    AttackTreeNode,
    ComponentInventory,
    ControlMapping,
    EntryPointInventory,
    MissingInformationReport,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideThreatRegister,
    ThreatModelCompletenessReport,
)
from threatmodeler.renderers.mitigation_by_threat_index import MitigationByThreatIndex


class MarkdownCellLimit(IntEnum):
    """Maximum character lengths for Markdown table cells."""

    SHORT = 48
    MEDIUM = 80
    LONG = 120


class MarkdownTableSpec(BaseModel):
    """Immutable specification for one Markdown table."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    empty_message: str = Field(min_length=1)


class MarkdownSectionFormatter(Protocol):
    """Strategy boundary for formatting artifact details as Markdown sections."""

    def format_components_table(self, inventory: ComponentInventory) -> str:
        """Format component inventory as a Markdown table."""
        ...

    def format_entry_points_table(self, inventory: EntryPointInventory) -> str:
        """Format entry points as a Markdown table."""
        ...

    def format_assets_table(self, inventory: AssetInventory) -> str:
        """Format assets as a Markdown table."""
        ...

    def format_threats_table(self, threats: StrideThreatRegister) -> str:
        """Format STRIDE threats as a Markdown table."""
        ...

    def format_threat_dossiers(
        self,
        threats: StrideThreatRegister,
        mitigation_index: MitigationByThreatIndex,
    ) -> str:
        """Format per-threat provenance dossiers with linked mitigations."""
        ...

    def format_risks_table(self, risks: RiskRegister) -> str:
        """Format risks as a Markdown table."""
        ...

    def format_mitigations_table(self, mitigations: MitigationPlan) -> str:
        """Format mitigations as a Markdown table."""
        ...

    def format_security_requirements_table(self, requirements: SecurityRequirements) -> str:
        """Format security requirements as a Markdown table."""
        ...

    def format_attack_tree_summary(self, tree: AttackTree) -> str:
        """Format attack-tree root goals as a Markdown summary."""
        ...

    def format_abuse_cases_section(self, cases: AbuseMisuseCases) -> str:
        """Format abuse/misuse cases as Markdown subsections."""
        ...

    def format_control_mappings_table(self, controls: ControlMapping) -> str:
        """Format control mappings as a Markdown table."""
        ...

    def format_completeness_section(self, report: ThreatModelCompletenessReport) -> str:
        """Format completeness checks as a Markdown checklist."""
        ...

    def format_missing_information_list(self, report: MissingInformationReport) -> str:
        """Format missing-information items as a Markdown list."""
        ...

    def format_assumptions_table(self, register: AssumptionsRegister) -> str:
        """Format assumptions as a Markdown table."""
        ...


class DefaultMarkdownSectionFormatter:
    """Deterministic Markdown tables and lists for technical-report enrichment."""

    def format_components_table(self, inventory: ComponentInventory) -> str:
        """Format component inventory as a Markdown table.

        Args:
            inventory: Validated component inventory artifact.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(component.id, MarkdownCellLimit.SHORT),
                self._cell(component.name, MarkdownCellLimit.MEDIUM),
                self._cell(component.component_type.value, MarkdownCellLimit.SHORT),
            )
            for component in sorted(inventory.components, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=("ID", "Name", "Type"),
                rows=rows,
                empty_message="No components were documented.",
            )
        )

    def format_entry_points_table(self, inventory: EntryPointInventory) -> str:
        """Format entry points as a Markdown table.

        Args:
            inventory: Validated entry-point inventory artifact.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(entry.id, MarkdownCellLimit.SHORT),
                self._cell(entry.name, MarkdownCellLimit.MEDIUM),
                self._cell(entry.component_id, MarkdownCellLimit.SHORT),
                self._cell(entry.protocol, MarkdownCellLimit.SHORT),
                self._cell(entry.authentication_method, MarkdownCellLimit.MEDIUM),
                self._cell(entry.exposure.value, MarkdownCellLimit.SHORT),
            )
            for entry in sorted(inventory.entry_points, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Name",
                    "Component",
                    "Protocol",
                    "Authentication",
                    "Exposure",
                ),
                rows=rows,
                empty_message="No entry points were documented.",
            )
        )

    def format_assets_table(self, inventory: AssetInventory) -> str:
        """Format assets as a Markdown table.

        Args:
            inventory: Validated asset inventory artifact.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(asset.id, MarkdownCellLimit.SHORT),
                self._cell(asset.name, MarkdownCellLimit.MEDIUM),
                self._cell(asset.asset_type.value, MarkdownCellLimit.SHORT),
                self._cell(asset.classification, MarkdownCellLimit.SHORT),
                self._join_ids(asset.trust_level_ids),
            )
            for asset in sorted(inventory.assets, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=("ID", "Name", "Type", "Classification", "Trust Levels"),
                rows=rows,
                empty_message="No assets were documented.",
            )
        )

    def format_threats_table(self, threats: StrideThreatRegister) -> str:
        """Format STRIDE threats as compact dossiers without mitigation joins.

        Args:
            threats: Validated STRIDE threat register.

        Returns:
            Markdown dossiers or empty-message paragraph.
        """
        return self.format_threat_dossiers(threats, MitigationByThreatIndex.empty())

    def format_threat_dossiers(
        self,
        threats: StrideThreatRegister,
        mitigation_index: MitigationByThreatIndex,
    ) -> str:
        """Format per-threat provenance dossiers with linked mitigations.

        Args:
            threats: Validated STRIDE threat register.
            mitigation_index: Reverse index of mitigations by threat id.

        Returns:
            Markdown dossiers or empty-message paragraph.
        """
        if not threats.threats:
            return "_No STRIDE threats were identified._"
        blocks: list[str] = []
        for threat in sorted(threats.threats, key=lambda item: item.id):
            evidence_lines = [
                f"- {self._cell(item.summary, MarkdownCellLimit.LONG)}"
                for item in threat.evidence[:2]
            ]
            if not evidence_lines:
                evidence_lines = ["- No evidence recorded"]
            linked = mitigation_index.for_threat(threat.id)
            mitigation_lines = (
                [
                    f"- `{item.id}`: {self._cell(item.name, MarkdownCellLimit.MEDIUM)}"
                    for item in linked
                ]
                if linked
                else ["- No linked mitigations"]
            )
            attack_path = " → ".join(
                self._cell(step, MarkdownCellLimit.MEDIUM)
                for step in threat.provenance.attack_path
            )
            blocks.extend(
                [
                    f"### {self._escape(threat.id)}: {self._escape(threat.name)}",
                    "",
                    f"- **Category:** {threat.category.value}",
                    f"- **Status:** {threat.status.value}",
                    f"- **Impact:** {self._cell(threat.impact, MarkdownCellLimit.LONG)}",
                    f"- **Component:** {self._escape(threat.component_id) if threat.component_id else '—'}",
                    f"- **Data flow:** {self._escape(threat.data_flow_id) if threat.data_flow_id else '—'}",
                    f"- **Asset:** {self._escape(threat.asset_id) if threat.asset_id else '—'}",
                    f"- **Entry point:** {self._escape(threat.provenance.entry_point_id) if threat.provenance.entry_point_id else '—'}",
                    f"- **Trust boundary:** {self._escape(threat.provenance.trust_boundary_id) if threat.provenance.trust_boundary_id else '—'}",
                    f"- **Actor:** {self._escape(threat.provenance.actor_id) if threat.provenance.actor_id else '—'}",
                    f"- **Exit point:** {self._escape(threat.provenance.exit_point_id) if threat.provenance.exit_point_id else '—'}",
                    f"- **Affected components:** {self._join_ids(threat.affected_component_ids)}",
                    f"- **Preconditions:** {self._join_text(threat.attack_preconditions)}",
                    f"- **Attack path id:** {self._escape(threat.provenance.attack_path_id)}",
                    f"- **Attack path:** {attack_path}",
                    f"- **Rationale:** {self._cell(threat.provenance.rationale, MarkdownCellLimit.LONG)}",
                    "",
                    "**Evidence**",
                    "",
                    *evidence_lines,
                    "",
                    "**Linked mitigations**",
                    "",
                    *mitigation_lines,
                    "",
                ]
            )
        return "\n".join(blocks).rstrip()

    def format_risks_table(self, risks: RiskRegister) -> str:
        """Format risks as a Markdown table.

        Args:
            risks: Validated risk register.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(risk.id, MarkdownCellLimit.SHORT),
                self._cell(risk.name, MarkdownCellLimit.MEDIUM),
                self._cell(risk.severity.value, MarkdownCellLimit.SHORT),
                self._cell(risk.likelihood.value, MarkdownCellLimit.SHORT),
                self._cell(risk.status.value, MarkdownCellLimit.SHORT),
                self._cell(
                    risk.response_type.value if risk.response_type else "—",
                    MarkdownCellLimit.SHORT,
                ),
                self._cell(risk.owner or "—", MarkdownCellLimit.SHORT),
                self._join_ids(risk.threat_ids),
            )
            for risk in sorted(risks.risks, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Name",
                    "Severity",
                    "Likelihood",
                    "Status",
                    "Response",
                    "Owner",
                    "Threats",
                ),
                rows=rows,
                empty_message="No risks were scored.",
            )
        )

    def format_mitigations_table(self, mitigations: MitigationPlan) -> str:
        """Format mitigations as a Markdown table.

        Args:
            mitigations: Validated mitigation plan.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(item.id, MarkdownCellLimit.SHORT),
                self._cell(item.name, MarkdownCellLimit.MEDIUM),
                self._cell(item.control_type.value, MarkdownCellLimit.SHORT),
                self._cell(item.status.value, MarkdownCellLimit.SHORT),
                self._cell(item.priority.value, MarkdownCellLimit.SHORT),
                self._join_ids(item.threat_ids),
                self._join_ids(item.risk_ids),
            )
            for item in sorted(mitigations.mitigations, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Name",
                    "Control Type",
                    "Status",
                    "Priority",
                    "Threats",
                    "Risks",
                ),
                rows=rows,
                empty_message="No mitigations were planned.",
            )
        )

    def format_security_requirements_table(self, requirements: SecurityRequirements) -> str:
        """Format security requirements as a Markdown table.

        Args:
            requirements: Validated security requirements catalog.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(item.id, MarkdownCellLimit.SHORT),
                self._cell(item.name, MarkdownCellLimit.MEDIUM),
                self._cell(item.category.value, MarkdownCellLimit.SHORT),
                self._cell(item.priority.value, MarkdownCellLimit.SHORT),
                self._cell(item.verification_method, MarkdownCellLimit.MEDIUM),
                self._join_ids(item.threat_ids),
            )
            for item in sorted(requirements.requirements, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Name",
                    "Category",
                    "Priority",
                    "Verification",
                    "Threats",
                ),
                rows=rows,
                empty_message="No security requirements were derived.",
            )
        )

    def format_attack_tree_summary(self, tree: AttackTree) -> str:
        """Format attack-tree root goals as a Markdown summary.

        Args:
            tree: Validated attack tree.

        Returns:
            Bullet list summarizing root goals, or an empty-message paragraph.
        """
        if not tree.root_nodes:
            return "No attack-tree goals were documented."
        lines = [
            f"- **{self._escape(root.id)}**: {self._escape(root.name)} "
            f"({root.node_type}, {root.operator}"
            f"{f', difficulty={root.difficulty}' if root.difficulty else ''}"
            f"; children={self._count_nodes(root) - 1})"
            for root in sorted(tree.root_nodes, key=lambda item: item.id)
        ]
        return "\n".join(lines)

    def format_abuse_cases_section(self, cases: AbuseMisuseCases) -> str:
        """Format abuse/misuse cases as Markdown subsections.

        Args:
            cases: Validated abuse/misuse case collection.

        Returns:
            Nested Markdown for each case, or an empty-message paragraph.
        """
        if not cases.cases:
            return "No abuse or misuse cases were documented."
        blocks: list[str] = []
        for case in sorted(cases.cases, key=lambda item: item.id):
            preconditions = (
                "; ".join(self._escape(item) for item in case.preconditions)
                if case.preconditions
                else "—"
            )
            steps = "; ".join(self._escape(item) for item in case.steps) if case.steps else "—"
            blocks.extend(
                [
                    f"#### {self._escape(case.name)} (`{self._escape(case.id)}`)",
                    "",
                    f"- **Actors:** {self._join_ids(case.actor_ids) or '—'}",
                    f"- **Preconditions:** {preconditions}",
                    f"- **Steps:** {steps}",
                    f"- **Impact:** {self._escape(case.impact)}",
                    "",
                ]
            )
        return "\n".join(blocks).rstrip()

    def format_control_mappings_table(self, controls: ControlMapping) -> str:
        """Format control mappings as a Markdown table.

        Args:
            controls: Validated control-mapping artifact.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(item.id, MarkdownCellLimit.SHORT),
                self._cell(item.framework, MarkdownCellLimit.MEDIUM),
                self._cell(item.framework_control_id, MarkdownCellLimit.SHORT),
                self._cell(item.status.value, MarkdownCellLimit.SHORT),
                self._join_ids(item.threat_ids),
                self._join_ids(item.risk_ids),
            )
            for item in sorted(controls.controls, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Framework",
                    "Control ID",
                    "Status",
                    "Threats",
                    "Risks",
                ),
                rows=rows,
                empty_message="No control mappings were documented.",
            )
        )

    def format_completeness_section(self, report: ThreatModelCompletenessReport) -> str:
        """Format completeness checks as a Markdown checklist.

        Args:
            report: Validated completeness report.

        Returns:
            Checklist lines plus overall satisfaction summary.
        """
        if not report.checks:
            return "No completeness checks were recorded."
        lines = [
            (
                f"- [{check.status.value}] {self._escape(check.name)}: "
                f"{self._escape(check.description)}"
                + (
                    f" (ids: {', '.join(self._escape(item) for item in check.related_ids)})"
                    if check.related_ids
                    else ""
                )
            )
            for check in report.checks
        ]
        summary = (
            "Overall completeness satisfied."
            if report.overall_satisfied
            else "Completeness gaps require follow-up before sign-off."
        )
        return "\n".join([*lines, summary])

    def format_missing_information_list(self, report: MissingInformationReport) -> str:
        """Format missing-information items as a Markdown list.

        Args:
            report: Validated missing-information report.

        Returns:
            Bullet list or empty-message paragraph.
        """
        if not report.items:
            return "No missing information was recorded."
        return "\n".join(
            (
                f"- **{self._escape(item.id)}**: {self._escape(item.question)} "
                f"(impact: {self._escape(item.impact)})"
            )
            for item in sorted(report.items, key=lambda item: item.id)
        )

    def format_assumptions_table(self, register: AssumptionsRegister) -> str:
        """Format assumptions as a Markdown table.

        Args:
            register: Validated assumptions register.

        Returns:
            Markdown table or empty-message paragraph.
        """
        rows = tuple(
            (
                self._cell(item.id, MarkdownCellLimit.SHORT),
                self._cell(item.name, MarkdownCellLimit.MEDIUM),
                self._cell(item.status.value, MarkdownCellLimit.SHORT),
                self._cell(item.rationale, MarkdownCellLimit.LONG),
                self._cell(item.impact_if_false, MarkdownCellLimit.LONG),
                self._cell(item.owner or "—", MarkdownCellLimit.SHORT),
            )
            for item in sorted(register.entries, key=lambda item: item.id)
        )
        return self._render_table(
            MarkdownTableSpec(
                headers=(
                    "ID",
                    "Name",
                    "Status",
                    "Rationale",
                    "Impact If False",
                    "Owner",
                ),
                rows=rows,
                empty_message="No assumptions were recorded.",
            )
        )

    def _render_table(self, spec: MarkdownTableSpec) -> str:
        if not spec.rows:
            return spec.empty_message
        header = "| " + " | ".join(spec.headers) + " |"
        separator = "| " + " | ".join("---" for _ in spec.headers) + " |"
        body = ["| " + " | ".join(row) + " |" for row in spec.rows]
        return "\n".join([header, separator, *body])

    def _join_ids(self, values: list[str]) -> str:
        """Join identifier lists into a compact cell value."""
        if not values:
            return "—"
        joined = ", ".join(sorted(values))
        return self._cell(joined, MarkdownCellLimit.MEDIUM)

    def _join_text(self, values: list[str]) -> str:
        """Join free-text lists into a compact cell value."""
        if not values:
            return "—"
        return "; ".join(self._cell(value, MarkdownCellLimit.MEDIUM) for value in values)

    def _cell(self, value: str, limit: MarkdownCellLimit) -> str:
        return self._escape(self._truncate(value, limit))

    def _truncate(self, value: str, limit: MarkdownCellLimit) -> str:
        normalized = " ".join(value.split())
        if len(normalized) <= int(limit):
            return normalized
        return f"{normalized[: int(limit) - 1]}…"

    def _escape(self, value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")

    def _count_nodes(self, node: AttackTreeNode) -> int:
        return 1 + sum(self._count_nodes(child) for child in node.children)
