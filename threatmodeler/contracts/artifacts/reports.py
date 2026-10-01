"""MVP1 executive, technical, and machine-readable report artifacts."""

from typing import Annotated

from pydantic import Field

from threatmodeler.contracts.artifacts.architecture import (
    AuthenticationAuthorizationModel,
    DataFlowDiagramModel,
    DeploymentModelArtifact,
    TrustBoundaryMap,
)
from threatmodeler.contracts.artifacts.graph import ArchitectureGraph
from threatmodeler.contracts.artifacts.base import ArtifactModel
from threatmodeler.contracts.artifacts.governance import (
    AssumptionsRegister,
    MissingInformationReport,
    MitigationPlan,
    RiskRegister,
    SecurityRequirements,
    ThreatModelCompletenessReport,
)
from threatmodeler.contracts.artifacts.inventories import (
    ActorModel,
    AssetInventory,
    ComponentInventory,
    EntryPointInventory,
)
from threatmodeler.contracts.artifacts.threats import (
    AbuseMisuseCases,
    AttackTree,
    StrideThreatRegister,
)


class ExecutiveSummary(ArtifactModel):
    """Business-facing summary of threat-model outcomes."""

    overview: Annotated[str, Field(strict=True, min_length=1)]
    key_findings: list[Annotated[str, Field(strict=True, min_length=1)]]
    top_risk_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Ids of highest-priority risk items from the input payload. "
                    "Each value must match an id field on an input item."
                ),
            ),
        ]
    ]
    recommended_actions: list[Annotated[str, Field(strict=True, min_length=1)]]


class TechnicalReportSection(ArtifactModel):
    """One structured section of a technical threat-model report."""

    content: Annotated[str, Field(strict=True, min_length=1)]
    referenced_artifact_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Ids of artifacts referenced by this section. "
                    "Each value must match an artifact_id from the input payload."
                ),
            ),
        ]
    ] = Field(default_factory=list)


class TechnicalThreatModelReport(ArtifactModel):
    """Engineering-facing report assembled from generated artifacts."""

    scope: Annotated[str, Field(strict=True, min_length=1)]
    methodology: Annotated[str, Field(strict=True, min_length=1)]
    sections: list[TechnicalReportSection]
    conclusion: Annotated[str, Field(strict=True, min_length=1)]


class MachineReadableJsonBundle(ArtifactModel):
    """Complete machine-readable bundle of MVP1 artifacts."""

    component_inventory: ComponentInventory
    asset_inventory: AssetInventory
    actor_model: ActorModel
    data_flow_diagram: DataFlowDiagramModel
    trust_boundary_map: TrustBoundaryMap
    entry_point_inventory: EntryPointInventory
    authentication_authorization_model: AuthenticationAuthorizationModel
    deployment_model: DeploymentModelArtifact
    architecture_graph: ArchitectureGraph
    stride_threat_register: StrideThreatRegister
    attack_tree: AttackTree
    abuse_misuse_cases: AbuseMisuseCases
    risk_register: RiskRegister
    mitigation_plan: MitigationPlan
    security_requirements: SecurityRequirements
    assumptions_register: AssumptionsRegister
    missing_information_report: MissingInformationReport
    executive_summary: ExecutiveSummary
    technical_report: TechnicalThreatModelReport
    completeness_report: ThreatModelCompletenessReport


class ArtifactBundle(MachineReadableJsonBundle):
    """Complete validated result returned by the artifact generation facade."""
