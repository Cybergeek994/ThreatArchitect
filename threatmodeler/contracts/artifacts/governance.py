"""MVP1 risk, mitigation, requirement, assumption, and control artifacts."""

from datetime import date
from typing import Annotated

from pydantic import Field

from threatmodeler.contracts.artifacts.base import ArtifactItem, ArtifactModel
from threatmodeler.contracts.artifacts.enums import (
    AssumptionStatus,
    CompletenessCheckStatus,
    ControlType,
    MitigationStatus,
    RiskLikelihood,
    RiskResponseType,
    RiskSeverity,
    RiskStatus,
    SecurityRequirementCategory,
    WorkPriority,
)
from threatmodeler.contracts.base import ContractModel


class RiskRecord(ArtifactItem):
    """A risk derived from one or more modeled threats."""

    threat_ids: Annotated[
        list[
            Annotated[
                str,
                Field(
                    strict=True,
                    min_length=1,
                    description=(
                        "Ids of upstream threat items from the input payload. "
                        "Each value must match an id field on an input item."
                    ),
                ),
            ]
        ],
        Field(min_length=1),
    ]
    severity: RiskSeverity
    likelihood: RiskLikelihood
    status: RiskStatus
    owner: Annotated[str, Field(strict=True, min_length=1)] | None = None
    response_type: RiskResponseType | None = Field(
        default=None,
        description=(
            "OWASP risk response category: accept, eliminate, mitigate, or transfer. "
            "When response_type is 'accept', owner should identify who accepted the risk."
        ),
    )


class RiskRegister(ArtifactModel):
    """Prioritized register of threat-model risks."""

    risks: list[RiskRecord]


class Mitigation(ArtifactItem):
    """Planned or implemented risk treatment."""

    risk_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Ids of upstream risk items from the input payload. "
                    "Each value must match an id field on an input item."
                ),
            ),
        ]
    ] = Field(default_factory=list)
    threat_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Ids of upstream threat items from the input payload. "
                    "Each value must match an id field on an input item."
                ),
            ),
        ]
    ] = Field(default_factory=list)
    control_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Ids of control items from the input payload or catalog. "
                    "Each value must match a known control id."
                ),
            ),
        ]
    ] = Field(default_factory=list)
    owner: Annotated[str, Field(strict=True, min_length=1)] | None = None
    status: MitigationStatus
    priority: WorkPriority
    target_date: date | None = None
    response_type: RiskResponseType = Field(
        default=RiskResponseType.MITIGATE,
        description=(
            "OWASP risk response category for this mitigation action. "
            "Default is 'mitigate' (add controls to reduce impact/likelihood)."
        ),
    )
    control_type: ControlType = Field(
        default=ControlType.PREVENTIVE,
        description=(
            "Layered defense category: preventive, detective, corrective, "
            "or compensating."
        ),
    )


class MitigationPlan(ArtifactModel):
    """Plan for treating identified threats and risks."""

    mitigations: list[Mitigation]


class SecurityRequirement(ArtifactItem):
    """A verifiable security requirement derived from the threat model."""

    statement: Annotated[str, Field(strict=True, min_length=1)]
    category: SecurityRequirementCategory
    priority: WorkPriority
    component_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )
    threat_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(default_factory=list)
    verification_method: Annotated[str, Field(strict=True, min_length=1)]


class SecurityRequirements(ArtifactModel):
    """Catalog of derived, verifiable security requirements."""

    requirements: list[SecurityRequirement]


class AssumptionRecord(ArtifactItem):
    """An explicit assumption affecting threat-model conclusions."""

    rationale: Annotated[str, Field(strict=True, min_length=1)]
    impact_if_false: Annotated[str, Field(strict=True, min_length=1)]
    owner: Annotated[str, Field(strict=True, min_length=1)] | None = None
    status: AssumptionStatus


class AssumptionsRegister(ArtifactModel):
    """Register of explicit threat-model assumptions."""

    entries: list[AssumptionRecord]


class MissingInformationItem(ArtifactItem):
    """A question or evidence gap requiring follow-up."""

    question: Annotated[str, Field(strict=True, min_length=1)]
    impact: Annotated[str, Field(strict=True, min_length=1)]
    requested_from: Annotated[str, Field(strict=True, min_length=1)] | None = None
    related_component_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )


class MissingInformationReport(ArtifactModel):
    """Non-fatal architecture information gaps."""

    items: list[MissingInformationItem]


class ThreatModelCompletenessCheck(ContractModel):
    """One verification item from the threat-model completeness assessment."""

    check_id: Annotated[str, Field(strict=True, min_length=1)]
    name: Annotated[str, Field(strict=True, min_length=1)]
    description: Annotated[str, Field(strict=True, min_length=1)]
    status: CompletenessCheckStatus
    related_ids: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )


class ThreatModelCompletenessReport(ArtifactModel):
    """Structured verify-phase checklist for threat-model completeness."""

    checks: list[ThreatModelCompletenessCheck]
    overall_satisfied: Annotated[
        bool,
        Field(description="True when no check has status gap."),
    ]
