"""Tests for deterministic Markdown section formatters."""

from threatmodeler.contracts.artifacts import (
    ThreatProvenance,
    AbuseMisuseCase,
    AbuseMisuseCases,
    Asset,
    AssetInventory,
    AssetType,
    AssumptionRecord,
    AssumptionsRegister,
    AssumptionStatus,
    AttackTree,
    AttackTreeNode,
    CompletenessCheckStatus,
    ComponentInventory,
    ControlMapping,
    ControlMappingEntry,
    ControlStatus,
    ControlType,
    EntryPointInventory,
    MissingInformationItem,
    MissingInformationReport,
    Mitigation,
    MitigationPlan,
    MitigationStatus,
    RiskLikelihood,
    RiskRecord,
    RiskRegister,
    RiskResponseType,
    RiskSeverity,
    RiskStatus,
    SecurityRequirement,
    SecurityRequirementCategory,
    SecurityRequirements,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    ThreatModelCompletenessCheck,
    ThreatModelCompletenessReport,
    ThreatStatus,
    WorkPriority,
)
from threatmodeler.contracts.system_model import (
    Component,
    ComponentType,
    EntryPoint,
    ExposureType,
)
from threatmodeler.renderers.markdown_section_formatter import (
    DefaultMarkdownSectionFormatter,
    MarkdownCellLimit,
)


def _item_fields(item_id: str, name: str = "Item") -> dict[str, object]:
    return {
        "id": item_id,
        "name": name,
        "description": f"Description for {name}",
        "evidence": [],
        "confidence": 0.9,
        "assumptions": [],
    }


def _artifact_fields(artifact_id: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "title": artifact_id,
        "description": f"Description for {artifact_id}",
        "confidence": 0.9,
        "assumptions": [],
    }


class TestDefaultMarkdownSectionFormatterPositive:
    """Verify populated artifacts render as deterministic Markdown tables."""

    def test_format_components_table_includes_sorted_rows(self) -> None:
        inventory = ComponentInventory.model_construct(
            **_artifact_fields("components"),
            components=[
                Component.model_construct(
                    id="comp-b",
                    name="Beta",
                    component_type=ComponentType.API,
                ),
                Component.model_construct(
                    id="comp-a",
                    name="Alpha",
                    component_type=ComponentType.WEB_APP,
                ),
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_components_table(inventory)

        assert "| ID | Name | Type |" in rendered
        assert rendered.index("comp-a") < rendered.index("comp-b")
        assert "web_app" in rendered

    def test_format_entry_points_table_includes_exposure(self) -> None:
        inventory = EntryPointInventory.model_construct(
            **_artifact_fields("entry-points"),
            entry_points=[
                EntryPoint.model_construct(
                    id="entry-1",
                    name="Public API",
                    component_id="api-gateway",
                    protocol="HTTPS",
                    authentication_method="OAuth2",
                    exposure=ExposureType.EXTERNAL,
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_entry_points_table(inventory)

        assert "Public API" in rendered
        assert "external" in rendered
        assert "OAuth2" in rendered

    def test_format_assets_table_includes_trust_levels(self) -> None:
        inventory = AssetInventory.model_construct(
            **_artifact_fields("assets"),
            assets=[
                Asset.model_construct(
                    **_item_fields("asset-1", "Card Data"),
                    asset_type=AssetType.DATA,
                    classification="restricted",
                    trust_level_ids=["tl-customer", "tl-admin"],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_assets_table(inventory)

        assert "Card Data" in rendered
        assert "restricted" in rendered
        assert "tl-admin, tl-customer" in rendered

    def test_format_threat_dossiers_joins_mitigations_and_evidence(self) -> None:
        from threatmodeler.contracts.source import Evidence, SourceReference, SourceType
        from threatmodeler.renderers.mitigation_by_threat_index import MitigationByThreatIndex

        source = SourceReference(
            source_type=SourceType.CONFLUENCE_PAGE,
            source_id="page-1",
            location="section",
            excerpt="excerpt",
        )
        threats = StrideThreatRegister.model_construct(
            **_artifact_fields("threats"),
            threats=[
                StrideThreat.model_construct(
                    id="threat-1",
                    name="Spoofed webhook",
                    description="Description for Spoofed webhook",
                    confidence=0.9,
                    assumptions=[],
                    category=StrideCategory.SPOOFING,
                    status=ThreatStatus.IDENTIFIED,
                    impact="Impact",
                    affected_component_ids=[],
                    component_ids=["api"],
                    attack_preconditions=["Reach API"],
                    evidence=[Evidence(summary="Webhook is public", source_references=[source])],
                    provenance=ThreatProvenance(
                        entry_point_id="entry-1",
                        attack_path_id="attack-path-1",
                        attack_path=["Reach webhook", "Spoof identity"],
                        rationale="Identified from public webhook evidence.",
                    ),
                )
            ],
        )
        plan = MitigationPlan.model_construct(
            **_artifact_fields("mitigations"),
            mitigations=[
                Mitigation.model_construct(
                    **_item_fields("mit-1", "Add MFA"),
                    risk_ids=[],
                    threat_ids=["threat-1"],
                    status=MitigationStatus.PLANNED,
                    priority=WorkPriority.HIGH,
                    control_type=ControlType.PREVENTIVE,
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_threat_dossiers(
            threats,
            MitigationByThreatIndex(plan),
        )

        assert "Webhook is public" in rendered
        assert "Add MFA" in rendered
        assert "Reach API" in rendered

    def test_format_threats_table_includes_status_and_blast_radius(self) -> None:
        threats = StrideThreatRegister.model_construct(
            **_artifact_fields("threats"),
            threats=[
                StrideThreat.model_construct(
                    **_item_fields("threat-1", "Spoofed webhook"),
                    category=StrideCategory.SPOOFING,
                    status=ThreatStatus.PARTIALLY_MITIGATED,
                    impact="Forged callbacks alter settlement status.",
                    affected_component_ids=["payments-api", "api-gateway"],
                    component_ids=["api-gateway"],
                    provenance=ThreatProvenance(
                        attack_path_id="attack-path-1",
                        attack_path=["Reach webhook", "Spoof callback"],
                        rationale="Identified from webhook exposure evidence.",
                    ),
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_threats_table(threats)

        assert "partially_mitigated" in rendered
        assert "spoofing" in rendered
        assert "api-gateway, payments-api" in rendered
        assert "Rationale" in rendered
        assert "Attack path" in rendered

    def test_format_risks_table_handles_optional_owner_and_response(self) -> None:
        risks = RiskRegister.model_construct(
            **_artifact_fields("risks"),
            risks=[
                RiskRecord.model_construct(
                    **_item_fields("risk-1", "Open Risk"),
                    threat_ids=["threat-1"],
                    severity=RiskSeverity.HIGH,
                    likelihood=RiskLikelihood.LIKELY,
                    status=RiskStatus.OPEN,
                    owner=None,
                    response_type=None,
                ),
                RiskRecord.model_construct(
                    **_item_fields("risk-2", "Owned Risk"),
                    threat_ids=["threat-2"],
                    severity=RiskSeverity.MEDIUM,
                    likelihood=RiskLikelihood.POSSIBLE,
                    status=RiskStatus.OPEN,
                    owner="security-team",
                    response_type=RiskResponseType.MITIGATE,
                ),
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_risks_table(risks)

        assert "security-team" in rendered
        assert "mitigate" in rendered
        assert "—" in rendered

    def test_format_mitigations_table_includes_control_type(self) -> None:
        plan = MitigationPlan.model_construct(
            **_artifact_fields("mitigations"),
            mitigations=[
                Mitigation.model_construct(
                    **_item_fields("mit-1", "Add MFA"),
                    risk_ids=["risk-1"],
                    threat_ids=["threat-1"],
                    status=MitigationStatus.PLANNED,
                    priority=WorkPriority.HIGH,
                    control_type=ControlType.PREVENTIVE,
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_mitigations_table(plan)

        assert "preventive" in rendered
        assert "planned" in rendered
        assert "threat-1" in rendered

    def test_format_security_requirements_table_includes_verification(self) -> None:
        requirements = SecurityRequirements.model_construct(
            **_artifact_fields("requirements"),
            requirements=[
                SecurityRequirement.model_construct(
                    **_item_fields("req-1", "Validate tokens"),
                    statement="Validate issuer and audience.",
                    category=SecurityRequirementCategory.AUTHENTICATION,
                    priority=WorkPriority.HIGH,
                    verification_method="Integration test",
                    threat_ids=["threat-1"],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_security_requirements_table(
            requirements
        )

        assert "authentication" in rendered
        assert "Integration test" in rendered

    def test_format_attack_tree_summary_includes_difficulty_and_children(self) -> None:
        child = AttackTreeNode.model_construct(
            **_item_fields("child-1", "Step"),
            operator="leaf",
            node_type="attack_step",
            children=[],
            component_ids=["api"],
        )
        root = AttackTreeNode.model_construct(
            **_item_fields("root-1", "Goal"),
            operator="or",
            node_type="goal",
            difficulty="high",
            children=[child],
            component_ids=["api"],
        )
        tree = AttackTree.model_construct(
            **_artifact_fields("attack-tree"),
            root_nodes=[root],
        )

        rendered = DefaultMarkdownSectionFormatter().format_attack_tree_summary(tree)

        assert "root-1" in rendered
        assert "difficulty=high" in rendered
        assert "children=1" in rendered

    def test_format_abuse_cases_section_includes_nested_details(self) -> None:
        cases = AbuseMisuseCases.model_construct(
            **_artifact_fields("abuse-cases"),
            cases=[
                AbuseMisuseCase.model_construct(
                    **_item_fields("abuse-1", "Replay settlement"),
                    actor_ids=["attacker"],
                    preconditions=["Queue reachable"],
                    steps=["Resubmit message"],
                    impact="Duplicate settlement",
                    component_ids=["payment-queue"],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_abuse_cases_section(cases)

        assert "#### Replay settlement" in rendered
        assert "attacker" in rendered
        assert "Queue reachable" in rendered
        assert "Duplicate settlement" in rendered

    def test_format_control_mappings_table_includes_framework(self) -> None:
        controls = ControlMapping.model_construct(
            **_artifact_fields("controls"),
            controls=[
                ControlMappingEntry.model_construct(
                    **_item_fields("ctrl-1", "IA-2"),
                    framework="OWASP ASVS",
                    framework_control_id="V2.1.1",
                    status=ControlStatus.PARTIAL,
                    threat_ids=["threat-1"],
                    risk_ids=["risk-1"],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_control_mappings_table(controls)

        assert "OWASP ASVS" in rendered
        assert "V2.1.1" in rendered
        assert "partial" in rendered

    def test_format_completeness_section_satisfied_summary(self) -> None:
        report = ThreatModelCompletenessReport.model_construct(
            **_artifact_fields("completeness"),
            checks=[
                ThreatModelCompletenessCheck.model_construct(
                    check_id="check-1",
                    name="DFD present",
                    description="Flows are documented.",
                    status=CompletenessCheckStatus.SATISFIED,
                    related_ids=["flow-1"],
                )
            ],
            overall_satisfied=True,
        )

        rendered = DefaultMarkdownSectionFormatter().format_completeness_section(report)

        assert "[satisfied]" in rendered
        assert "ids: flow-1" in rendered
        assert "Overall completeness satisfied." in rendered

    def test_format_completeness_section_gap_summary(self) -> None:
        report = ThreatModelCompletenessReport.model_construct(
            **_artifact_fields("completeness"),
            checks=[
                ThreatModelCompletenessCheck.model_construct(
                    check_id="check-1",
                    name="Coverage",
                    description="Entry point uncovered.",
                    status=CompletenessCheckStatus.GAP,
                    related_ids=[],
                )
            ],
            overall_satisfied=False,
        )

        rendered = DefaultMarkdownSectionFormatter().format_completeness_section(report)

        assert "[gap]" in rendered
        assert "Completeness gaps require follow-up before sign-off." in rendered

    def test_format_missing_information_list_includes_impact(self) -> None:
        report = MissingInformationReport.model_construct(
            **_artifact_fields("missing"),
            items=[
                MissingInformationItem.model_construct(
                    **_item_fields("miss-1", "Token lifetime"),
                    question="What is the production token lifetime?",
                    impact="Replay exposure cannot be assessed.",
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_missing_information_list(report)

        assert "miss-1" in rendered
        assert "production token lifetime" in rendered
        assert "Replay exposure" in rendered

    def test_format_assumptions_table_includes_status(self) -> None:
        register = AssumptionsRegister.model_construct(
            **_artifact_fields("assumptions"),
            entries=[
                AssumptionRecord.model_construct(
                    **_item_fields("asm-1", "IdP managed"),
                    rationale="Central identity provider.",
                    impact_if_false="Token checks may fail.",
                    owner=None,
                    status=AssumptionStatus.UNVERIFIED,
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_assumptions_table(register)

        assert "unverified" in rendered
        assert "Central identity provider." in rendered


class TestDefaultMarkdownSectionFormatterEmpty:
    """Verify empty artifacts render graceful placeholder messages."""

    def test_empty_components(self) -> None:
        inventory = ComponentInventory.model_construct(
            **_artifact_fields("components"),
            components=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_components_table(inventory)
            == "No components were documented."
        )

    def test_empty_entry_points(self) -> None:
        inventory = EntryPointInventory.model_construct(
            **_artifact_fields("entry-points"),
            entry_points=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_entry_points_table(inventory)
            == "No entry points were documented."
        )

    def test_empty_assets(self) -> None:
        inventory = AssetInventory.model_construct(
            **_artifact_fields("assets"),
            assets=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_assets_table(inventory)
            == "No assets were documented."
        )

    def test_empty_threats(self) -> None:
        threats = StrideThreatRegister.model_construct(
            **_artifact_fields("threats"),
            threats=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_threats_table(threats)
            == "_No STRIDE threats were identified._"
        )

    def test_empty_risks(self) -> None:
        risks = RiskRegister.model_construct(
            **_artifact_fields("risks"),
            risks=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_risks_table(risks) == "No risks were scored."
        )

    def test_empty_mitigations(self) -> None:
        plan = MitigationPlan.model_construct(
            **_artifact_fields("mitigations"),
            mitigations=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_mitigations_table(plan)
            == "No mitigations were planned."
        )

    def test_empty_requirements(self) -> None:
        requirements = SecurityRequirements.model_construct(
            **_artifact_fields("requirements"),
            requirements=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_security_requirements_table(requirements)
            == "No security requirements were derived."
        )

    def test_empty_attack_tree(self) -> None:
        tree = AttackTree.model_construct(
            **_artifact_fields("attack-tree"),
            root_nodes=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_attack_tree_summary(tree)
            == "No attack-tree goals were documented."
        )

    def test_empty_abuse_cases(self) -> None:
        cases = AbuseMisuseCases.model_construct(
            **_artifact_fields("abuse-cases"),
            cases=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_abuse_cases_section(cases)
            == "No abuse or misuse cases were documented."
        )

    def test_empty_control_mappings(self) -> None:
        controls = ControlMapping.model_construct(
            **_artifact_fields("controls"),
            controls=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_control_mappings_table(controls)
            == "No control mappings were documented."
        )

    def test_empty_completeness(self) -> None:
        report = ThreatModelCompletenessReport.model_construct(
            **_artifact_fields("completeness"),
            checks=[],
            overall_satisfied=True,
        )
        assert (
            DefaultMarkdownSectionFormatter().format_completeness_section(report)
            == "No completeness checks were recorded."
        )

    def test_empty_missing_information(self) -> None:
        report = MissingInformationReport.model_construct(
            **_artifact_fields("missing"),
            items=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_missing_information_list(report)
            == "No missing information was recorded."
        )

    def test_empty_assumptions(self) -> None:
        register = AssumptionsRegister.model_construct(
            **_artifact_fields("assumptions"),
            entries=[],
        )
        assert (
            DefaultMarkdownSectionFormatter().format_assumptions_table(register)
            == "No assumptions were recorded."
        )


class TestDefaultMarkdownSectionFormatterEdgeCases:
    """Verify truncation, escaping, and sparse optional fields."""

    def test_truncates_long_cell_values(self) -> None:
        long_impact = "A" * (int(MarkdownCellLimit.LONG) + 20)
        threats = StrideThreatRegister.model_construct(
            **_artifact_fields("threats"),
            threats=[
                StrideThreat.model_construct(
                    **_item_fields("threat-1", "Long threat"),
                    category=StrideCategory.TAMPERING,
                    status=ThreatStatus.IDENTIFIED,
                    impact=long_impact,
                    affected_component_ids=[],
                    component_ids=["api"],
                    provenance=ThreatProvenance(
                        attack_path_id="attack-path-1",
                        attack_path=["Reach API", "Tamper data"],
                        rationale="Identified from long-impact fixture evidence.",
                    ),
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_threats_table(threats)

        assert "…" in rendered
        assert long_impact not in rendered

    def test_escapes_pipe_characters_in_cells(self) -> None:
        threats = StrideThreatRegister.model_construct(
            **_artifact_fields("threats"),
            threats=[
                StrideThreat.model_construct(
                    **_item_fields("threat-1", "Name | with pipe"),
                    category=StrideCategory.SPOOFING,
                    status=ThreatStatus.IDENTIFIED,
                    impact="Impact | text",
                    affected_component_ids=[],
                    component_ids=["api"],
                    provenance=ThreatProvenance(
                        attack_path_id="attack-path-1",
                        attack_path=["Reach API", "Spoof identity"],
                        rationale="Identified from pipe-escape fixture evidence.",
                    ),
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_threats_table(threats)

        assert "Name \\| with pipe" in rendered
        assert "Impact \\| text" in rendered

    def test_abuse_case_without_actors_preconditions_or_steps(self) -> None:
        cases = AbuseMisuseCases.model_construct(
            **_artifact_fields("abuse-cases"),
            cases=[
                AbuseMisuseCase.model_construct(
                    **_item_fields("abuse-1", "Sparse case"),
                    actor_ids=[],
                    preconditions=[],
                    steps=[],
                    impact="Limited impact",
                    component_ids=["api"],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_abuse_cases_section(cases)

        assert "**Actors:** —" in rendered
        assert "**Preconditions:** —" in rendered
        assert "**Steps:** —" in rendered

    def test_attack_tree_summary_without_difficulty(self) -> None:
        root = AttackTreeNode.model_construct(
            **_item_fields("root-1", "Goal"),
            operator="leaf",
            node_type="goal",
            difficulty=None,
            children=[],
            component_ids=["api"],
        )
        tree = AttackTree.model_construct(
            **_artifact_fields("attack-tree"),
            root_nodes=[root],
        )

        rendered = DefaultMarkdownSectionFormatter().format_attack_tree_summary(tree)

        assert "difficulty=" not in rendered
        assert "children=0" in rendered

    def test_join_ids_empty_returns_em_dash(self) -> None:
        inventory = AssetInventory.model_construct(
            **_artifact_fields("assets"),
            assets=[
                Asset.model_construct(
                    **_item_fields("asset-1", "Secret"),
                    asset_type=AssetType.CREDENTIAL,
                    classification="restricted",
                    trust_level_ids=[],
                )
            ],
        )

        rendered = DefaultMarkdownSectionFormatter().format_assets_table(inventory)

        assert rendered.splitlines()[-1].endswith("| — |")
