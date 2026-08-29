"""Validation and JSON round-trip tests for threat-modeling artifact schemas."""

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError
from threatmodeler.contracts import Evidence, SourceReference, SourceType
from threatmodeler.contracts.artifacts import (
    AbuseMisuseCase,
    AbuseMisuseCases,
    ActorModel,
    AssetInventory,
    AssumptionRecord,
    AssumptionsRegister,
    AssumptionStatus,
    AttackTree,
    AttackTreeNode,
    AuthenticationAuthorizationModel,
    ComponentInventory,
    ControlMapping,
    ControlMappingEntry,
    ControlStatus,
    DataFlowDiagramModel,
    DeploymentModelArtifact,
    EntryPointInventory,
    ExecutiveSummary,
    MachineReadableJsonBundle,
    MissingInformationItem,
    MissingInformationReport,
    Mitigation,
    MitigationPlan,
    MitigationStatus,
    RiskLikelihood,
    RiskRecord,
    RiskRegister,
    RiskSeverity,
    RiskStatus,
    SecurityRequirement,
    SecurityRequirementCategory,
    SecurityRequirements,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    TechnicalReportSection,
    TechnicalThreatModelReport,
    ThreatModelCompletenessReport,
    ThreatStatus,
    TrustBoundaryMap,
    WorkPriority,
)
from threatmodeler.contracts.artifacts.base import ArtifactItem, ArtifactModel
from threatmodeler.contracts.system_model import DeploymentModel


@pytest.fixture
def artifact_fields_factory() -> Callable[[str], dict[str, Any]]:
    """Return a fixture factory for validated artifact metadata."""

    def create(artifact_id: str) -> dict[str, Any]:
        metadata = ArtifactModel(
            artifact_id=artifact_id,
            title=artifact_id.replace("-", " ").title(),
            description=f"Threat-model artifact {artifact_id}",
            confidence=0.8,
            assumptions=["Architecture evidence is current."],
        )
        return metadata.model_dump()

    return create


@pytest.fixture
def source_reference() -> SourceReference:
    """Create traceable evidence provenance."""
    return SourceReference(
        source_type=SourceType.CONFLUENCE_PAGE,
        source_id="ARB-42",
        location="Architecture review",
        excerpt="The public API processes payment requests.",
    )


@pytest.fixture
def evidence(source_reference: SourceReference) -> list[Evidence]:
    """Create evidence shared by artifact records."""
    return [
        Evidence(
            summary="Supported by the architecture review.",
            source_references=[source_reference],
        )
    ]


@pytest.fixture
def item_fields_factory(evidence: list[Evidence]) -> Callable[[str], dict[str, Any]]:
    """Return a fixture factory for validated artifact-item fields."""

    def create(item_id: str) -> dict[str, Any]:
        item = ArtifactItem(
            id=item_id,
            name=item_id.replace("-", " ").title(),
            description=f"Generated record {item_id}",
            evidence=evidence,
            confidence=0.75,
            assumptions=["The source remains accurate."],
        )
        return item.model_dump()

    return create


@pytest.fixture
def artifacts(
    artifact_fields_factory: Callable[[str], dict[str, Any]],
    item_fields_factory: Callable[[str], dict[str, Any]],
    evidence: list[Evidence],
    source_reference: SourceReference,
) -> list[ArtifactModel]:
    """Instantiate every artifact model type, including a full machine-readable bundle."""
    component_inventory = ComponentInventory(
        **artifact_fields_factory("component-inventory"), components=[]
    )
    asset_inventory = AssetInventory(**artifact_fields_factory("asset-inventory"), assets=[])
    actor_model = ActorModel(**artifact_fields_factory("actor-model"), actors=[], interactions=[])
    data_flow_diagram = DataFlowDiagramModel(
        **artifact_fields_factory("data-flow-diagram"),
        components=[],
        data_stores=[],
        data_flows=[],
    )
    trust_boundary_map = TrustBoundaryMap(
        **artifact_fields_factory("trust-boundary-map"), trust_boundaries=[]
    )
    entry_point_inventory = EntryPointInventory(
        **artifact_fields_factory("entry-point-inventory"), entry_points=[]
    )
    authentication_model = AuthenticationAuthorizationModel(
        **artifact_fields_factory("authentication-authorization-model"),
        authentication_mechanisms=[],
        authorization_rules=[],
    )
    deployment = DeploymentModel(
        id="deployment",
        name="Cloud deployment",
        description="Primary deployment topology",
        evidence=evidence,
        confidence=0.8,
        source_reference=source_reference,
    )
    deployment_artifact = DeploymentModelArtifact(
        **artifact_fields_factory("deployment-model"),
        deployment=deployment,
        component_placements={},
    )
    threat = StrideThreat(
        **item_fields_factory("threat-1"),
        category=StrideCategory.SPOOFING,
        status=ThreatStatus.IDENTIFIED,
        component_ids=["component-api"],
        impact="An attacker could impersonate a customer.",
    )
    stride_register = StrideThreatRegister(
        **artifact_fields_factory("stride-register"), threats=[threat]
    )
    attack_node = AttackTreeNode(
        **item_fields_factory("attack-node-1"),
        operator="leaf",
        component_ids=["component-api"],
    )
    attack_tree = AttackTree(**artifact_fields_factory("attack-tree"), root_nodes=[attack_node])
    abuse_case = AbuseMisuseCase(
        **item_fields_factory("abuse-case-1"),
        component_ids=["component-api"],
        preconditions=["The API is internet-accessible."],
        steps=["Submit a stolen authentication token."],
        impact="Unauthorized account access.",
    )
    abuse_cases = AbuseMisuseCases(
        **artifact_fields_factory("abuse-misuse-cases"), cases=[abuse_case]
    )
    risk = RiskRecord(
        **item_fields_factory("risk-1"),
        threat_ids=[threat.id],
        severity=RiskSeverity.HIGH,
        likelihood=RiskLikelihood.POSSIBLE,
        status=RiskStatus.OPEN,
    )
    risk_register = RiskRegister(**artifact_fields_factory("risk-register"), risks=[risk])
    mitigation = Mitigation(
        **item_fields_factory("mitigation-1"),
        risk_ids=[risk.id],
        threat_ids=[threat.id],
        status=MitigationStatus.PLANNED,
        priority=WorkPriority.HIGH,
    )
    mitigation_plan = MitigationPlan(
        **artifact_fields_factory("mitigation-plan"), mitigations=[mitigation]
    )
    requirement = SecurityRequirement(
        **item_fields_factory("requirement-1"),
        statement="The API shall validate token issuer and audience.",
        category=SecurityRequirementCategory.AUTHENTICATION,
        priority=WorkPriority.HIGH,
        component_ids=["component-api"],
        threat_ids=[threat.id],
        verification_method="Automated integration test",
    )
    security_requirements = SecurityRequirements(
        **artifact_fields_factory("security-requirements"), requirements=[requirement]
    )
    assumption = AssumptionRecord(
        **item_fields_factory("assumption-1"),
        rationale="The identity provider is managed centrally.",
        impact_if_false="Token validation controls may be insufficient.",
        status=AssumptionStatus.UNVERIFIED,
    )
    assumptions_register = AssumptionsRegister(
        **artifact_fields_factory("assumptions-register"), entries=[assumption]
    )
    missing_item = MissingInformationItem(
        **item_fields_factory("missing-1"),
        question="What is the production token lifetime?",
        impact="Session replay exposure cannot be fully assessed.",
        related_component_ids=["component-api"],
    )
    missing_report = MissingInformationReport(
        **artifact_fields_factory("missing-information-report"), items=[missing_item]
    )
    control = ControlMappingEntry(
        **item_fields_factory("control-1"),
        framework="NIST SP 800-53",
        framework_control_id="IA-2",
        threat_ids=[threat.id],
        risk_ids=[risk.id],
        requirement_ids=[requirement.id],
        component_ids=["component-api"],
        status=ControlStatus.PARTIAL,
    )
    control_mapping = ControlMapping(
        **artifact_fields_factory("control-mapping"), controls=[control]
    )
    executive_summary = ExecutiveSummary(
        **artifact_fields_factory("executive-summary"),
        overview="The review identified one high-severity authentication risk.",
        key_findings=["Token validation requires strengthening."],
        top_risk_ids=[risk.id],
        recommended_actions=["Implement issuer and audience validation."],
    )
    report_section = TechnicalReportSection(
        **artifact_fields_factory("technical-section-1"),
        content="STRIDE analysis identified a spoofing threat.",
        referenced_artifact_ids=[stride_register.artifact_id],
    )
    technical_report = TechnicalThreatModelReport(
        **artifact_fields_factory("technical-report"),
        scope="Payments API architecture",
        methodology="STRIDE with qualitative risk analysis",
        sections=[report_section],
        conclusion="Address token validation before production release.",
    )
    completeness_report = ThreatModelCompletenessReport(
        **artifact_fields_factory("completeness-report"),
        checks=[],
        overall_satisfied=True,
    )
    bundle = MachineReadableJsonBundle(
        **artifact_fields_factory("machine-readable-json-bundle"),
        component_inventory=component_inventory,
        asset_inventory=asset_inventory,
        actor_model=actor_model,
        data_flow_diagram=data_flow_diagram,
        trust_boundary_map=trust_boundary_map,
        entry_point_inventory=entry_point_inventory,
        authentication_authorization_model=authentication_model,
        deployment_model=deployment_artifact,
        stride_threat_register=stride_register,
        attack_tree=attack_tree,
        abuse_misuse_cases=abuse_cases,
        risk_register=risk_register,
        mitigation_plan=mitigation_plan,
        security_requirements=security_requirements,
        assumptions_register=assumptions_register,
        missing_information_report=missing_report,
        control_mapping=control_mapping,
        executive_summary=executive_summary,
        technical_report=technical_report,
        completeness_report=completeness_report,
    )
    return [
        component_inventory,
        asset_inventory,
        actor_model,
        data_flow_diagram,
        trust_boundary_map,
        entry_point_inventory,
        authentication_model,
        deployment_artifact,
        stride_register,
        attack_tree,
        abuse_cases,
        risk_register,
        mitigation_plan,
        security_requirements,
        assumptions_register,
        missing_report,
        control_mapping,
        executive_summary,
        technical_report,
        completeness_report,
        bundle,
    ]


class TestArtifactSchemasPositive:
    """Verify supported inputs and successful behavior."""

    def test_all_artifact_models_serialize_and_round_trip_json(
        self, artifacts: list[ArtifactModel]
    ) -> None:
        assert len(artifacts) == 21
        for artifact in artifacts:
            serialized = artifact.model_dump_json()
            restored = type(artifact).model_validate_json(serialized)
            assert restored == artifact

    def test_required_artifact_fields_are_enforced(
        self, artifact_fields_factory: Callable[[str], dict[str, Any]]
    ) -> None:
        payload: dict[str, object] = dict(artifact_fields_factory("component-inventory"))
        del payload["title"]
        payload["components"] = []

        with pytest.raises(ValidationError, match="title"):
            ComponentInventory.model_validate(payload)


class TestArtifactSchemasNegative:
    """Verify invalid or adversarial inputs are rejected."""

    @pytest.mark.parametrize(
        ("field_name", "invalid_value"),
        [("severity", "catastrophic"), ("likelihood", "guaranteed")],
    )
    def test_risk_enum_constraints(
        self,
        field_name: str,
        invalid_value: str,
        item_fields_factory: Callable[[str], dict[str, Any]],
    ) -> None:
        risk_fields: dict[str, object] = {
            **item_fields_factory("risk-invalid"),
            "threat_ids": ["threat-1"],
            "severity": RiskSeverity.HIGH,
            "likelihood": RiskLikelihood.POSSIBLE,
            "status": RiskStatus.OPEN,
        }
        risk_fields[field_name] = invalid_value

        with pytest.raises(ValidationError, match=field_name):
            RiskRecord.model_validate(risk_fields)

    def test_artifact_confidence_is_bounded(
        self, artifact_fields_factory: Callable[[str], dict[str, Any]]
    ) -> None:
        payload: dict[str, object] = {
            **artifact_fields_factory("component-inventory"),
            "confidence": 1.1,
            "components": [],
        }

        with pytest.raises(ValidationError, match="confidence"):
            ComponentInventory.model_validate(payload)

    def test_stride_category_rejects_unknown_value(
        self, item_fields_factory: Callable[[str], dict[str, Any]]
    ) -> None:
        payload: dict[str, object] = {
            **item_fields_factory("threat-invalid"),
            "category": "malware",
            "status": ThreatStatus.IDENTIFIED,
            "component_ids": ["component-api"],
            "impact": "System compromise",
        }
        with pytest.raises(ValidationError, match="category"):
            StrideThreat.model_validate(payload)

    def test_threat_requires_architecture_or_evidence_traceability(
        self, item_fields_factory: Callable[[str], dict[str, Any]]
    ) -> None:
        payload: dict[str, object] = {
            **item_fields_factory("threat-unlinked"),
            "evidence": [],
            "category": StrideCategory.TAMPERING,
            "status": ThreatStatus.IDENTIFIED,
            "impact": "Data could be modified.",
        }

        with pytest.raises(ValidationError, match="must link"):
            StrideThreat.model_validate(payload)
