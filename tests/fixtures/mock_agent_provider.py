"""Standard mock configuration for deterministic agent responses."""

import json
from collections.abc import Callable, Mapping, Sequence
from typing import cast
from unittest.mock import Mock

from pydantic import BaseModel, JsonValue
from threatmodeler.contracts.artifacts import (
    ArchitectureGraph,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    StrideCategory,
    StrideThreat,
    StrideThreatRegister,
    ThreatProvenance,
    ThreatStatus,
)
from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.contracts.source import Evidence, SourceReference
from threatmodeler.contracts.artifacts.enums import StrideInputPayloadField
from threatmodeler.domain.architecture_graph_generation import ArchitectureGraphGenerationService
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.contracts.system_model import (
    ApplicationInfo,
    CanonicalSystemModel,
    Component,
    ComponentType,
    Criticality,
    DataClassification,
    DeploymentModel,
    EntryPoint,
    ExposureType,
    TrustBoundary,
    TrustBoundaryType,
)


def create_mock_agent_provider(
    responses: Mapping[str, dict[str, JsonValue]] | None = None,
    *,
    model_name: str = "mock-model",
    confidence: float = 1.0,
) -> Mock:
    """Configure a standard mock with deterministic schema-valid completions."""
    configured_responses = {
        task_name: dict(payload) for task_name, payload in (responses or {}).items()
    }
    provider = Mock(spec=["complete", "complete_with_tools"])

    def complete(request: AgentRequest) -> AgentResponse:
        configured_payload = configured_responses.get(request.task_name)
        if configured_payload is not None:
            payload = dict(configured_payload)
        elif request.task_name == "extract_canonical_system_model":
            payload = _canonical_system_model_payload(request)
        elif request.task_name == "generate_architecture_graph":
            payload = _architecture_graph_payload(request)
        elif request.task_name == "generate_stride_threats":
            payload = _stride_threat_register_payload(request)
        elif request.task_name == "rank_asvs_control_candidates":
            payload = _rank_asvs_control_candidates_payload(request)
        else:
            payload = dict(request.input_payload)
        return AgentResponse(
            output_payload=payload,
            confidence=confidence,
            raw_response=json.dumps(payload, separators=(",", ":")),
            provider_name="mock",
            model_name=model_name,
        )

    def complete_with_tools(
        request: AgentRequest,
        session: object,
        journal: object,
    ) -> AgentResponse:
        del session, journal
        return cast(AgentResponse, provider.complete(request))

    provider.complete.side_effect = complete
    provider.complete_with_tools.side_effect = complete_with_tools
    return provider


def create_mock_agent_provider_without_gaps(
    responses: Mapping[str, dict[str, JsonValue]] | None = None,
    *,
    model_name: str = "mock-model",
    confidence: float = 1.0,
) -> Mock:
    """Return a mock whose extracted canonical model has no information gaps."""
    provider = create_mock_agent_provider_for_agent_assisted(
        responses, model_name=model_name, confidence=confidence
    )
    original_complete = _complete_function(provider)

    def complete(request: AgentRequest) -> AgentResponse:
        response = original_complete(request)
        if request.task_name != "extract_canonical_system_model":
            return response
        payload_value = response.output_payload
        assert isinstance(payload_value, dict)
        payload = dict(payload_value)
        payload["missing_information"] = []
        return AgentResponse(
            output_payload=payload,
            confidence=response.confidence,
            raw_response=json.dumps(payload, separators=(",", ":")),
            provider_name=response.provider_name,
            model_name=response.model_name,
        )

    provider.complete.side_effect = complete
    return provider


def create_mock_agent_provider_with_gaps(
    gaps: Sequence[str],
    responses: Mapping[str, dict[str, JsonValue]] | None = None,
    *,
    model_name: str = "mock-model",
    confidence: float = 1.0,
) -> Mock:
    """Return a mock whose extracted canonical model lists explicit gaps."""
    provider = create_mock_agent_provider_for_agent_assisted(
        responses, model_name=model_name, confidence=confidence
    )
    original_complete = _complete_function(provider)

    def complete(request: AgentRequest) -> AgentResponse:
        response = original_complete(request)
        if request.task_name != "extract_canonical_system_model":
            return response
        payload_value = response.output_payload
        assert isinstance(payload_value, dict)
        payload = dict(payload_value)
        payload["missing_information"] = list(gaps)
        return AgentResponse(
            output_payload=payload,
            confidence=response.confidence,
            raw_response=json.dumps(payload, separators=(",", ":")),
            provider_name=response.provider_name,
            model_name=response.model_name,
        )

    provider.complete.side_effect = complete
    return provider


def create_mock_agent_provider_for_agent_assisted(
    responses: Mapping[str, dict[str, JsonValue]] | None = None,
    *,
    model_name: str = "mock-model",
    confidence: float = 1.0,
) -> Mock:
    """Return a mock that also produces schema-valid downstream artifacts."""
    provider = create_mock_agent_provider(responses, model_name=model_name, confidence=confidence)
    original_complete = _complete_function(provider)

    def complete(request: AgentRequest) -> AgentResponse:
        configured = (responses or {}).get(request.task_name)
        if configured is not None or request.task_name in {
            "extract_canonical_system_model",
            "generate_architecture_graph",
            "generate_stride_threats",
            "rank_asvs_control_candidates",
        }:
            return original_complete(request)
        payload = _downstream_artifact_payload(request)
        return AgentResponse(
            output_payload=payload,
            confidence=confidence,
            raw_response=json.dumps(payload, separators=(",", ":")),
            provider_name="mock",
            model_name=model_name,
        )

    provider.complete.side_effect = complete
    return provider


def _rank_asvs_control_candidates_payload(request: AgentRequest) -> dict[str, JsonValue]:
    requirements = request.input_payload.get("security_requirements")
    control_index = request.input_payload.get("control_index")
    if not isinstance(requirements, list) or not requirements:
        return {"mappings": []}
    default_control_id = "v5.0.0-1.1.1"
    if isinstance(control_index, list) and control_index:
        first_control = control_index[0]
        if isinstance(first_control, dict):
            control_id = first_control.get("id")
            if isinstance(control_id, str):
                default_control_id = control_id
    mappings: list[dict[str, JsonValue]] = []
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        requirement_id = requirement.get("requirement_id")
        if not isinstance(requirement_id, str):
            continue
        mappings.append(
            {
                "requirement_id": requirement_id,
                "control_id": default_control_id,
                "alternates": [],
                "confidence": "high",
                "rationale": "Mock ASVS batch ranker selected a catalog control.",
            }
        )
    return {"mappings": mappings}


def _downstream_artifact_payload(request: AgentRequest) -> dict[str, JsonValue]:
    from threatmodeler.domain.architecture_graph_generation import ArchitectureGraphGenerationService
    from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
    from threatmodeler.domain.attack_tree_generation import AttackTreeGenerationService
    from tests.fixtures.mock_asvs_semantic_ranker import create_mock_control_mapping_service
    from threatmodeler.domain.dfd_generation import DfdGenerationService
    from threatmodeler.domain.mitigation_generation import MitigationGenerationService
    from threatmodeler.domain.report_generation import ReportGenerationService
    from threatmodeler.domain.risk_scoring import RiskScoringService
    from threatmodeler.domain.stride_generation import (
        AgentStrideThreatGenerationStrategy,
        StrideThreatGenerationService,
    )
    from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
    from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

    system_model_payload = request.input_payload.get("system_model")
    if not isinstance(system_model_payload, dict):
        return {}
    model = CanonicalSystemModel.model_validate(system_model_payload)
    metadata = ArtifactMetadataService()
    threat_payload = request.input_payload.get("stride_threat_register")
    threats = (
        StrideThreatRegister.model_validate(threat_payload)
        if isinstance(threat_payload, dict)
        else StrideThreatRegister(
            artifact_id="stride-threat-register",
            title="STRIDE Threat Register",
            description="Empty STRIDE register for mock downstream generation.",
            confidence=0.1,
            assumptions=model.assumptions,
            threats=[],
        )
    )
    risk_payload = request.input_payload.get("risk_register")
    risks = (
        RiskRegister.model_validate(risk_payload)
        if isinstance(risk_payload, dict)
        else RiskScoringService(metadata).generate(model, threats)
    )
    mitigation_payload = request.input_payload.get("mitigation_plan")
    mitigations = (
        MitigationPlan.model_validate(mitigation_payload)
        if isinstance(mitigation_payload, dict)
        else MitigationGenerationService(metadata).generate_plan(model, risks)
    )
    requirements_payload = request.input_payload.get("security_requirements")
    requirements = (
        SecurityRequirements.model_validate(requirements_payload)
        if isinstance(requirements_payload, dict)
        else MitigationGenerationService(metadata).generate_requirements(model, threats, risks)
    )
    generators: dict[str, Callable[[], BaseModel]] = {
        "generate_dfd": lambda: DfdGenerationService(metadata).generate(model),
        "generate_architecture_graph": lambda: ArchitectureGraphGenerationService(
            metadata
        ).generate(model),
        "generate_attack_tree": lambda: AttackTreeGenerationService(metadata).generate(
            model, threats
        ),
        "generate_abuse_cases": lambda: StrideThreatGenerationService(
            strategy=AgentStrideThreatGenerationStrategy(
                create_mock_agent_provider(),
                StrideThreatPromptBuilder(SecurePromptTemplate(), PydanticSchemaProvider()),
                PydanticSchemaProvider(),
            ),
            metadata=metadata,
        ).generate_abuse_cases(model, threats),
        "generate_risk_register": lambda: risks,
        "generate_mitigation_plan": lambda: mitigations,
        "generate_security_requirements": lambda: requirements,
        "generate_missing_information": lambda: ReportGenerationService(
            metadata
        ).generate_missing_information(model),
        "generate_control_mapping": lambda: create_mock_control_mapping_service(metadata).generate(
            model, risks, mitigations, requirements
        ),
        "generate_executive_summary": lambda: ReportGenerationService(
            metadata
        ).generate_executive_summary(model, threats, risks, mitigations),
        "generate_technical_report": lambda: ReportGenerationService(
            metadata
        ).generate_technical_report(model, threats, risks),
    }
    generator = generators.get(request.task_name)
    if generator is None:
        return dict(request.input_payload)
    return generator().model_dump(mode="json")


def _complete_function(provider: Mock) -> Callable[[AgentRequest], AgentResponse]:
    original_complete = provider.complete.side_effect
    assert callable(original_complete)
    return cast(Callable[[AgentRequest], AgentResponse], original_complete)


def _canonical_system_model_payload(request: AgentRequest) -> dict[str, JsonValue]:
    source_payload = request.input_payload.get("source_reference")
    if not isinstance(source_payload, dict):
        source_payload = {
            "source_type": "manual_input",
            "source_id": "mock-source",
            "location": "mock",
            "excerpt": "Mock extraction source",
        }
    source_reference = SourceReference.model_validate(source_payload)
    title_value = request.input_payload.get("title")
    title = title_value if isinstance(title_value, str) and title_value else "Unknown application"
    raw_text_value = request.input_payload.get("raw_text")
    description = (
        raw_text_value[:500]
        if isinstance(raw_text_value, str) and raw_text_value
        else "Architecture details were not available to the mock provider."
    )
    evidence = [
        Evidence(
            summary="Generated from the parsed document by the local mock provider.",
            source_references=[source_reference],
        )
    ]
    application = ApplicationInfo(
        id="application",
        name=title,
        description=description,
        evidence=evidence,
        confidence=0.5,
        source_reference=source_reference,
        business_purpose="Unknown; requires review",
        owner="Unknown",
        criticality=Criticality.MEDIUM,
        environments=["unknown"],
        data_classification=DataClassification.INTERNAL,
    )
    component = Component(
        id="component-unknown",
        name="Unclassified application component",
        description="Placeholder component produced for local mock extraction.",
        evidence=evidence,
        confidence=0.25,
        source_reference=source_reference,
        component_type=ComponentType.UNKNOWN,
    )
    deployment = DeploymentModel(
        id="deployment",
        name="Unknown deployment",
        description="Deployment details were not identified by the mock provider.",
        evidence=evidence,
        confidence=0.1,
        source_reference=source_reference,
    )
    boundary = TrustBoundary(
        id="boundary-unknown",
        name="Unclassified trust boundary",
        description="Placeholder boundary produced so mock extraction satisfies membership rules.",
        evidence=evidence,
        confidence=0.25,
        source_reference=source_reference,
        boundary_type=TrustBoundaryType.NETWORK,
        component_ids=[component.id],
    )
    entry_point = EntryPoint(
        id="entry-unknown",
        name="Unclassified entry point",
        description="Placeholder entry point produced so mock extraction is not orphaned.",
        evidence=evidence,
        confidence=0.25,
        source_reference=source_reference,
        component_id=component.id,
        protocol="HTTPS",
        authentication_method="workload identity",
        exposure=ExposureType.INTERNAL,
    )
    topology_payload = request.input_payload.get("diagram_topology")
    diagram_evidence: list[str] = []
    if isinstance(topology_payload, list):
        for snapshot in topology_payload:
            if not isinstance(snapshot, dict):
                continue
            filename = snapshot.get("source_filename", "diagram")
            edges = snapshot.get("edges")
            if isinstance(edges, list):
                for edge in edges:
                    if not isinstance(edge, dict):
                        continue
                    diagram_evidence.append(
                        f"{filename}: {edge.get('source_id')} -> {edge.get('target_id')}"
                    )
    model = CanonicalSystemModel(
        application=application,
        actors=[],
        components=[component],
        data_stores=[],
        data_flows=[],
        trust_boundaries=[boundary],
        entry_points=[entry_point],
        deployment=deployment,
        assumptions=["Mock extraction is intended for local workflow validation only."],
        missing_information=[
            "Application ownership must be confirmed.",
            "Detailed actors, data flows, trust boundaries, and deployment are unknown.",
        ],
        diagram_evidence=diagram_evidence,
    )
    return model.model_dump(mode="json")


def _architecture_graph_payload(request: AgentRequest) -> dict[str, JsonValue]:
    system_model_payload = request.input_payload.get(StrideInputPayloadField.SYSTEM_MODEL)
    if not isinstance(system_model_payload, dict):
        return {}
    model = CanonicalSystemModel.model_validate(system_model_payload)
    graph = ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)
    return graph.model_dump(mode="json")


def _stride_threat_register_payload(request: AgentRequest) -> dict[str, JsonValue]:
    system_model_payload = request.input_payload.get(StrideInputPayloadField.SYSTEM_MODEL)
    graph_payload = request.input_payload.get(StrideInputPayloadField.ARCHITECTURE_GRAPH)
    if not isinstance(system_model_payload, dict) or not isinstance(graph_payload, dict):
        return {}
    model = CanonicalSystemModel.model_validate(system_model_payload)
    graph = ArchitectureGraph.model_validate(graph_payload)
    nodes_by_id = {node.id: node for node in graph.nodes}
    paths_by_target_component: dict[str, list] = {}
    for path in graph.attack_paths:
        target_node = nodes_by_id.get(path.target_node_id)
        if target_node is None or target_node.component_id is None:
            continue
        paths_by_target_component.setdefault(target_node.component_id, []).append(path)
    entries_by_component = {
        entry.component_id: entry
        for entry in model.entry_points
        if entry.exposure.is_external_facing()
    }
    crossed_flow_by_source = {
        flow.source_component_id: flow
        for flow in model.data_flows
        if flow.trust_boundary_crossed
    }
    boundary_id = model.trust_boundaries[0].id if model.trust_boundaries else None
    threats = []
    for component in model.components:
        entry = entries_by_component.get(component.id)
        crossed_flow = crossed_flow_by_source.get(component.id)
        candidate_paths = paths_by_target_component.get(component.id, graph.attack_paths)
        attack_path = candidate_paths[0]
        narrative = [
            nodes_by_id[step.node_id].name
            for step in attack_path.steps
            if step.node_id in nodes_by_id
        ]
        provenance = ThreatProvenance(
            entry_point_id=entry.id if entry is not None else None,
            trust_boundary_id=boundary_id if crossed_flow is not None else None,
            actor_id=entry.actor_id if entry is not None else None,
            attack_path_id=attack_path.id,
            attack_path=narrative,
            rationale=(
                f"Identified because {component.name} is present in the architecture "
                f"and is exposed to {_stride_category(component.component_type).value}."
            ),
        )
        threats.append(
            StrideThreat(
                id=f"threat-{component.id}",
                name=f"{_stride_category(component.component_type).value} at {component.name}",
                description=(
                    f"The {component.name} component may be exposed to "
                    f"{_stride_category(component.component_type).value}."
                ),
                evidence=component.evidence,
                confidence=component.confidence,
                assumptions=model.assumptions,
                component_id=component.id,
                data_flow_id=crossed_flow.id if crossed_flow is not None else None,
                category=_stride_category(component.component_type),
                status=ThreatStatus.IDENTIFIED,
                attack_preconditions=["The component is reachable by a potential attacker."],
                impact="Security properties of the referenced component could be affected.",
                provenance=provenance,
            )
        )
    register = StrideThreatRegister(
        artifact_id="stride-threat-register",
        title="STRIDE Threat Register",
        description="Mock STRIDE threats derived from validated canonical components.",
        confidence=0.6,
        assumptions=model.assumptions,
        threats=threats,
    )
    return register.model_dump(mode="json")


def _stride_category(component_type: ComponentType) -> StrideCategory:
    if component_type in {ComponentType.DATABASE, ComponentType.STORAGE}:
        return StrideCategory.INFORMATION_DISCLOSURE
    if component_type is ComponentType.IDENTITY_PROVIDER:
        return StrideCategory.SPOOFING
    if component_type in {ComponentType.QUEUE, ComponentType.JOB}:
        return StrideCategory.TAMPERING
    if component_type is ComponentType.EXTERNAL_SERVICE:
        return StrideCategory.REPUDIATION
    return StrideCategory.SPOOFING
