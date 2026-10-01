"""MVP1 STRIDE, attack-tree, and abuse-case artifacts."""

from typing import Annotated, Self

from pydantic import Field, StrictBool, model_validator

from threatmodeler.contracts.artifacts.base import ArtifactModel, ThreatLinkedItem
from threatmodeler.contracts.artifacts.enums import StrideCategory, ThreatStatus
from threatmodeler.contracts.base import ContractModel
from threatmodeler.contracts.source import Evidence

_REF_ID = (
    "Reference to another extracted item's id. Must match an id declared "
    "in a list field or scalar id field within the same output model."
)


class ThreatExploitabilityAssessment(ContractModel):
    """Qualitative exploitability assessment per OWASP risk assessment questions.

    Nested model that inherits traceability from the parent StrideThreat.
    """

    exploitable_remotely: Annotated[
        StrictBool,
        Field(description="Can an attacker exploit this threat remotely without local access?"),
    ]
    requires_authentication: Annotated[
        StrictBool,
        Field(description="Does the attacker need to be authenticated to exploit this threat?"),
    ]
    exploit_automatable: Annotated[
        StrictBool,
        Field(description="Can the exploitation be automated (scripted attack)?"),
    ]


class ThreatImpactAssessment(ContractModel):
    """Qualitative impact assessment per OWASP risk assessment questions.

    Nested model that inherits traceability from the parent StrideThreat.
    """

    full_system_compromise: Annotated[
        StrictBool,
        Field(description="Can an attacker completely take over or destroy the system?"),
    ]
    admin_access_possible: Annotated[
        StrictBool,
        Field(description="Can an attacker gain administration access to the system?"),
    ]
    system_crash_possible: Annotated[
        StrictBool,
        Field(description="Can an attacker crash the system or make it unavailable?"),
    ]
    sensitive_data_exposure: Annotated[
        StrictBool,
        Field(description="Can the attacker obtain access to highly sensitive information?"),
    ]


class ThreatProvenance(ContractModel):
    """Architecture anchors and narrative explaining why a threat was identified."""

    entry_point_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `entry_points`.",
        ),
    ] | None = None
    trust_boundary_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `trust_boundaries`.",
        ),
    ] | None = None
    actor_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `actors`.",
        ),
    ] | None = None
    exit_point_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `exit_points`.",
        ),
    ] | None = None
    attack_path_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                "Reference to an attack path id in the input "
                "`architecture_graph.attack_paths` list."
            ),
        ),
    ]
    attack_path: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(
            min_length=1,
            description="Ordered attacker steps grounded in the architecture input.",
        ),
    ]
    rationale: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description="Why this threat was identified from the supplied evidence.",
        ),
    ]


class StrideThreat(ThreatLinkedItem):
    """One traceable STRIDE threat with explicit provenance."""

    evidence: Annotated[
        list[Evidence],
        Field(
            min_length=1,
            description="Non-empty source evidence explaining why this threat was identified.",
        ),
    ]
    category: StrideCategory
    status: ThreatStatus
    provenance: ThreatProvenance
    attack_preconditions: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )
    impact: Annotated[str, Field(strict=True, min_length=1)]
    exploitability: ThreatExploitabilityAssessment | None = Field(
        default=None,
        description="OWASP-style qualitative exploitability assessment.",
    )
    impact_assessment: ThreatImpactAssessment | None = Field(
        default=None,
        description="OWASP-style qualitative impact assessment.",
    )
    affected_component_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list,
        description=(
            "Components that could be impacted if this threat materializes "
            "(blast radius for qualitative risk assessment)."
        ),
    )

    @model_validator(mode="after")
    def require_architecture_grounding(self) -> Self:
        """Require an architecture link in addition to mandatory evidence.

        Returns:
            Validated threat when architecture grounding is present.

        Raises:
            ValueError: If the threat lacks a component, data-flow, or asset link.
        """
        if not (
            self.component_id
            or self.data_flow_id
            or self.asset_id
            or self.component_ids
            or self.data_flow_ids
            or self.asset_ids
        ):
            raise ValueError(
                "A STRIDE threat must link to a component, data flow, or asset "
                "(evidence alone is not sufficient)"
            )
        return self


class StrideThreatRegister(ArtifactModel):
    """Register of identified STRIDE threats."""

    threats: list[StrideThreat]


class AttackTreeNode(ThreatLinkedItem):
    """A traceable goal or step in an attack tree.

    Supports OWASP-style multi-level decomposition with node type
    differentiation for goals, attack steps, vulnerabilities, and
    countermeasures.
    """

    operator: Annotated[str, Field(pattern=r"^(and|or|leaf)$")]
    children: list["AttackTreeNode"] = Field(default_factory=list)
    node_type: Annotated[
        str,
        Field(
            pattern=r"^(goal|attack_step|vulnerability|countermeasure)$",
            description="OWASP-style node classification for visual differentiation.",
        ),
    ] = "attack_step"
    difficulty: Annotated[
        str,
        Field(
            pattern=r"^(trivial|low|medium|high|expert)$",
            description="Qualitative assessment of attack difficulty.",
        ),
    ] | None = None


class AttackTree(ArtifactModel):
    """Hierarchical attack goals and paths."""

    root_nodes: list[AttackTreeNode]


class AbuseMisuseCase(ThreatLinkedItem):
    """An adversarial or accidental misuse scenario."""

    actor_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(default_factory=list)
    preconditions: list[Annotated[str, Field(strict=True, min_length=1)]]
    steps: list[Annotated[str, Field(strict=True, min_length=1)]]
    impact: Annotated[str, Field(strict=True, min_length=1)]


class AbuseMisuseCases(ArtifactModel):
    """Collection of abuse and misuse scenarios."""

    cases: list[AbuseMisuseCase]
