"""Shared deterministic fixtures and test-suite safety policies."""

import socket
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
from pytest import MonkeyPatch
from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.contracts import Evidence, SourceReference, SourceType
from threatmodeler.contracts.base import ExtractedItem
from threatmodeler.contracts.system_model import (
    Actor,
    ActorType,
    ApplicationInfo,
    CanonicalSystemModel,
    Component,
    ComponentType,
    Criticality,
    DataClassification,
    DataFlow,
    DataStore,
    DataStoreType,
    DeploymentModel,
    DeploymentType,
    EntryPoint,
    ExitPoint,
    ExposureType,
    ExternalDependency,
    TrustBoundary,
    TrustBoundaryType,
    TrustLevel,
)
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.architecture_graph_generation import ArchitectureGraphGenerationService
from threatmodeler.domain.attack_tree_generation import AttackTreeGenerationService
from tests.fixtures.mock_asvs_semantic_ranker import create_mock_control_mapping_service
from threatmodeler.domain.dfd_generation import DfdGenerationService
from threatmodeler.domain.downstream_artifact_generation import (
    DeterministicDownstreamArtifactGenerationStrategy,
)
from threatmodeler.domain.inventory_generation import InventoryGenerationService
from threatmodeler.domain.missing_information_policy import PermissiveMissingInformationPolicy
from threatmodeler.domain.mitigation_generation import MitigationGenerationService
from threatmodeler.domain.report_generation import ReportGenerationService
from threatmodeler.domain.threat_model_completeness import ThreatModelCompletenessService
from threatmodeler.domain.risk_scoring import RiskScoringService
from threatmodeler.domain.stride_generation import (
    AgentStrideThreatGenerationStrategy,
    StrideThreatGenerationService,
)
from threatmodeler.errors import AgentProviderError
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.infrastructure.local_system_model_loader import LocalSystemModelLoader
from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider
from threatmodeler.renderers.json_artifact_renderer_factory import (
    JsonArtifactRendererFactory,
)
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

from tests.fixtures.expected_outputs import EXPECTED_ARTIFACT_JSON_NAMES, EXPECTED_RENDERED_PATHS
from tests.fixtures.mock_agent_provider import (
    create_mock_agent_provider_for_agent_assisted,
    create_mock_agent_provider_with_gaps,
    create_mock_agent_provider_without_gaps,
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply strict registered markers based on the physical suite boundary."""
    for item in items:
        path_parts = Path(str(item.path)).parts
        if "integration" in path_parts:
            item.add_marker(pytest.mark.integration)
        elif "unit" in path_parts:
            item.add_marker(pytest.mark.unit)


@pytest.fixture(autouse=True)
def block_network(monkeypatch: MonkeyPatch) -> Generator[None, None, None]:
    """Fail every test that attempts to open a real remote network connection.

    Loopback connects used by ``asyncio`` event-loop self-pipes on Windows remain
    allowed so sync wrappers around async SDKs can be exercised safely.
    """

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection

    def _is_loopback(address: object) -> bool:
        host = address[0] if isinstance(address, tuple) and address else address
        return host in {"127.0.0.1", "::1", "localhost"}

    def blocked_connect(self: socket.socket, address: object) -> None:
        if _is_loopback(address):
            return original_connect(self, cast(Any, address))
        raise AssertionError("Network access is forbidden in the test suite")

    def blocked_connect_ex(self: socket.socket, address: object) -> int:
        if _is_loopback(address):
            return original_connect_ex(self, cast(Any, address))
        raise AssertionError("Network access is forbidden in the test suite")

    def blocked_create_connection(*args: object, **kwargs: object) -> socket.socket:
        address = args[0] if args else kwargs.get("address")
        if _is_loopback(address):
            return original_create_connection(*args, **kwargs)  # type: ignore[arg-type]
        raise AssertionError("Network access is forbidden in the test suite")

    monkeypatch.setattr(socket, "create_connection", blocked_create_connection)
    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked_connect_ex)
    yield


@pytest.fixture
def sample_confluence_html() -> str:
    """Load the checked-in HTML fixture."""
    return (Path(__file__).parent / "fixtures" / "sample_confluence.html").read_text(
        encoding="utf-8"
    )


@pytest.fixture
def sample_confluence_markdown() -> str:
    """Load the checked-in Markdown fixture."""
    return (Path(__file__).parent / "fixtures" / "sample_confluence.md").read_text(encoding="utf-8")


@pytest.fixture
def arb_fixtures_dir() -> Path:
    """Return the directory containing ARB HTML fixtures for integration tests."""
    return Path(__file__).parent / "fixtures" / "arb"


@pytest.fixture
def complete_arb_path(arb_fixtures_dir: Path) -> Path:
    """Return the complete payments ARB fixture path."""
    return arb_fixtures_dir / "complete-payments-arb.html"


@pytest.fixture
def partial_arb_path(arb_fixtures_dir: Path) -> Path:
    """Return the partially documented payments ARB fixture path."""
    return arb_fixtures_dir / "partial-payments-arb.html"


@pytest.fixture
def sparse_arb_path(arb_fixtures_dir: Path) -> Path:
    """Return the sparse payments ARB fixture path."""
    return arb_fixtures_dir / "sparse-payments-arb.html"


@pytest.fixture
def agent_provider_factory() -> Callable[..., Mock]:
    """Return a factory for mocks that produce schema-valid agent downstream artifacts."""
    return create_mock_agent_provider_for_agent_assisted


@pytest.fixture
def expected_artifact_names() -> frozenset[str]:
    """Return the expected model-stage artifact JSON filenames."""
    return EXPECTED_ARTIFACT_JSON_NAMES


@pytest.fixture
def expected_rendered_paths() -> tuple[str, ...]:
    """Return the expected rendered-output relative paths."""
    return EXPECTED_RENDERED_PATHS


@pytest.fixture
def complete_model_provider() -> Mock:
    """Return a provider whose extracted model contains no information gaps."""
    return create_mock_agent_provider_without_gaps()


@pytest.fixture
def blocking_model_provider() -> Mock:
    """Return a provider whose extracted model contains explicit information gaps."""
    return create_mock_agent_provider_with_gaps(
        [
            "Application ownership must be confirmed.",
            "Detailed actors, data flows, trust boundaries, and deployment are unknown.",
        ]
    )


@pytest.fixture
def agent_assisted_provider() -> Mock:
    """Return a provider that produces schema-valid downstream artifacts."""
    return create_mock_agent_provider_for_agent_assisted()


@pytest.fixture
def agent_provider(agent_provider_factory: Callable[..., Mock]) -> Mock:
    """Return a standard provider mock with schema-valid default responses."""
    return agent_provider_factory()


@pytest.fixture
def failing_agent_provider() -> Mock:
    """Return a standard mock configured for a non-retryable provider failure."""
    provider = Mock(spec=["complete", "complete_with_tools"])
    provider.complete.side_effect = AgentProviderError(
        "Injected agent provider failure",
        error_code="FAKE_AGENT_FAILURE",
        retryable=False,
    )
    provider.complete_with_tools.side_effect = AgentProviderError(
        "Injected agent provider failure",
        error_code="FAKE_AGENT_FAILURE",
        retryable=False,
    )
    return provider


@pytest.fixture
def canonical_system_model() -> CanonicalSystemModel:
    """Return a connected canonical model exercising every artifact generator."""
    source = SourceReference(
        source_type=SourceType.CONFLUENCE_PAGE,
        source_id="ARB-100",
        location="Runtime architecture",
        excerpt="Customers call the Payments API over HTTPS.",
    )
    evidence = [
        Evidence(
            summary="The runtime architecture documents this entity.",
            source_references=[source],
        )
    ]

    def extracted_item(entity_id: str, name: str) -> ExtractedItem:
        return ExtractedItem(
            id=entity_id,
            name=name,
            description=f"Canonical entity {name}",
            evidence=evidence,
            confidence=0.9,
            source_reference=source,
        )

    application = ApplicationInfo(
        **extracted_item("application", "Payments Application").model_dump(),
        business_purpose="Process customer payments",
        owner="Payments Engineering",
        criticality=Criticality.CRITICAL,
        environments=["production"],
        data_classification=DataClassification.RESTRICTED,
    )
    actor = Actor(
        **extracted_item("actor-customer", "Customer").model_dump(),
        actor_type=ActorType.HUMAN_USER,
    )
    api = Component(
        **extracted_item("component-api", "Payments API").model_dump(),
        component_type=ComponentType.API,
    )
    store = DataStore(
        **extracted_item("store-payments", "Payment Records").model_dump(),
        data_store_type=DataStoreType.DATABASE,
        data_elements=["payment token", "amount"],
        encrypted_at_rest=True,
    )
    flow = DataFlow(
        **extracted_item("flow-payment", "Persist Payment").model_dump(),
        source_component_id=api.id,
        destination_component_id=store.id,
        protocol="TLS/PostgreSQL",
        authentication_method="workload identity",
        data_elements=["payment token", "amount"],
        encrypted_in_transit=True,
        trust_boundary_crossed=True,
    )
    boundary = TrustBoundary(
        **extracted_item("boundary-production", "Production Boundary").model_dump(),
        boundary_type=TrustBoundaryType.NETWORK,
        component_ids=[api.id],
    )
    external_boundary = TrustBoundary(
        **extracted_item("boundary-internet", "Internet Boundary").model_dump(),
        boundary_type=TrustBoundaryType.EXTERNAL,
        component_ids=[api.id],
    )
    entry = EntryPoint(
        **extracted_item("entry-payments", "Payments Endpoint").model_dump(),
        component_id=api.id,
        protocol="HTTPS",
        authentication_method="OAuth 2.0 with MFA",
        exposure=ExposureType.EXTERNAL,
        actor_id=actor.id,
    )
    deployment = DeploymentModel(
        **extracted_item("deployment", "Cloud Deployment").model_dump(),
        deployment_type=DeploymentType.CLOUD,
        provider="Example Cloud",
        regions=["region-1"],
    )
    trust_level = TrustLevel(
        **extracted_item("trust-level-customer", "Authenticated Customer").model_dump(),
        access_rights=["read payments", "create payments"],
    )
    exit_point = ExitPoint(
        **extracted_item("exit-payment-response", "Payment Response").model_dump(),
        component_id=api.id,
        data_elements=["transaction_id", "status"],
        protocol="HTTPS",
        related_entry_point_id=entry.id,
    )
    external_dep = ExternalDependency(
        **extracted_item("dep-postgresql", "PostgreSQL Database").model_dump(),
        security_assumptions=["Database is hardened per security baseline"],
        version="15.0",
        component_ids=[store.id],
    )
    return CanonicalSystemModel(
        application=application,
        actors=[actor],
        components=[api],
        data_stores=[store],
        data_flows=[flow],
        trust_boundaries=[boundary, external_boundary],
        entry_points=[entry],
        deployment=deployment,
        assumptions=["The architecture document represents production."],
        missing_information=["Token lifetime is not documented."],
        trust_levels=[trust_level],
        exit_points=[exit_point],
        external_dependencies=[external_dep],
    )


@pytest.fixture
def threat_modeling_service_factory() -> Callable[
    [AgentProvider, ArtifactValidator | None], ThreatModelingService
]:
    """Return a factory for the artifact-generation facade under test."""

    def create(
        provider: AgentProvider,
        validator: ArtifactValidator | None = None,
    ) -> ThreatModelingService:
        metadata = ArtifactMetadataService()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                cast(ToolCallingProvider, provider),
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        report_service = ReportGenerationService(metadata)
        completeness_service = ThreatModelCompletenessService(metadata)
        downstream_strategy = DeterministicDownstreamArtifactGenerationStrategy(
            dfd_service=DfdGenerationService(metadata),
            architecture_graph_service=ArchitectureGraphGenerationService(metadata),
            attack_tree_service=AttackTreeGenerationService(metadata),
            stride_service=stride_service,
            risk_service=RiskScoringService(metadata),
            mitigation_service=MitigationGenerationService(metadata),
            control_mapping_service=create_mock_control_mapping_service(metadata),
            report_service=report_service,
        )
        return ThreatModelingService(
            inventory_service=InventoryGenerationService(metadata),
            stride_service=stride_service,
            downstream_strategy=downstream_strategy,
            report_service=report_service,
            completeness_service=completeness_service,
            artifact_validator=validator or PydanticArtifactValidator(),
            metadata=metadata,
            missing_information_policy=PermissiveMissingInformationPolicy(),
        )

    return create


@pytest.fixture
def artifact_generation_service_factory(
    threat_modeling_service_factory: Callable[
        [AgentProvider, ArtifactValidator | None], ThreatModelingService
    ],
) -> Callable[[AgentProvider], ArtifactGenerationService]:
    """Return a factory for the file-based artifact generation workflow."""

    def create(provider: AgentProvider) -> ArtifactGenerationService:
        return ArtifactGenerationService(
            system_model_loader=LocalSystemModelLoader(),
            threat_modeling_service=threat_modeling_service_factory(provider, None),
            renderer_factory=JsonArtifactRendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

    return create
