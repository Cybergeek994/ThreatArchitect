"""Canonical architecture and threat-modeling contracts."""

from enum import StrEnum
from typing import Annotated

from pydantic import Field, StrictBool

from threatmodeler.contracts.base import ContractModel, ExtractedItem
from threatmodeler.contracts.integration import DiagramTopologySnapshot

_REF_ID = (
    "Reference to another extracted item's id. Must match an id declared "
    "in a list field or scalar id field within the same output model."
)


class Criticality(StrEnum):
    """Business impact rating for an application (low through critical)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassification(StrEnum):
    """Highest data sensitivity handled by an application."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ActorType(StrEnum):
    """Actor categories for people, workload identities, and external parties.

    Prefer ``human_user`` for end users, ``admin`` for privileged operators,
    ``service_account`` for workload identities, ``external_system`` for
    partner/integrated systems, and ``third_party`` for vendor parties.
    """

    HUMAN_USER = "human_user"
    SERVICE_ACCOUNT = "service_account"
    ADMIN = "admin"
    EXTERNAL_SYSTEM = "external_system"
    THIRD_PARTY = "third_party"


class ComponentType(StrEnum):
    """Logical or physical architecture component categories.

    Use the most specific matching category. Prefer ``unknown`` only when the
    source does not support a more specific classification.
    """

    WEB_APP = "web_app"
    API = "api"
    DATABASE = "database"
    QUEUE = "queue"
    JOB = "job"
    STORAGE = "storage"
    SERVERLESS = "serverless"
    CONTAINER = "container"
    EXTERNAL_SERVICE = "external_service"
    IDENTITY_PROVIDER = "identity_provider"
    UNKNOWN = "unknown"


class DataStoreType(StrEnum):
    """Common data persistence categories.

    Prefer the most specific store type supported by the source. Use ``unknown``
    only when the source does not support a more specific classification.
    """

    DATABASE = "database"
    OBJECT_STORAGE = "object_storage"
    FILE_SYSTEM = "file_system"
    CACHE = "cache"
    DATA_WAREHOUSE = "data_warehouse"
    SEARCH_INDEX = "search_index"
    UNKNOWN = "unknown"


class TrustBoundaryType(StrEnum):
    """Security boundary categories.

    Prefer ``external`` for untrusted/public surfaces, ``network`` for network
    segments, ``identity`` for identity planes, and ``organizational`` for
    administrative domains. Use ``unknown`` only when the source does not
    support a more specific classification.
    """

    NETWORK = "network"
    IDENTITY = "identity"
    PROCESS = "process"
    PHYSICAL = "physical"
    ORGANIZATIONAL = "organizational"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class ExposureType(StrEnum):
    """Audience able to reach an entry point.

    Prefer ``external`` for public reachability, ``partner`` for partner-only
    reachability, and ``internal`` for internal-only reachability.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    PARTNER = "partner"
    UNKNOWN = "unknown"

    def is_external_facing(self) -> bool:
        """Return whether threats must cover this exposure via entry-point provenance."""
        return self is ExposureType.EXTERNAL or self is ExposureType.PARTNER


class DeploymentType(StrEnum):
    """Supported high-level deployment models."""

    ON_PREMISES = "on_premises"
    CLOUD = "cloud"
    HYBRID = "hybrid"
    MULTI_CLOUD = "multi_cloud"
    UNKNOWN = "unknown"


class ApplicationInfo(ExtractedItem):
    """Business and operating context for the modeled application."""

    business_purpose: Annotated[str, Field(strict=True, min_length=1)]
    owner: Annotated[str, Field(strict=True, min_length=1)]
    criticality: Criticality
    environments: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(min_length=1),
    ]
    data_classification: DataClassification


class Actor(ExtractedItem):
    """A person or system interacting with the application."""

    actor_type: ActorType
    trust_level_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=f"{_REF_ID} Target list field: `trust_levels`.",
            ),
        ]
    ] = Field(
        default_factory=list,
        description="Trust levels granted to this actor.",
    )


class Component(ExtractedItem):
    """A logical or physical architecture component."""

    component_type: ComponentType


class DataStore(ExtractedItem):
    """A persistence location used by the application."""

    data_store_type: DataStoreType = DataStoreType.UNKNOWN
    data_elements: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list
    )
    encrypted_at_rest: StrictBool | None = None


class DataFlow(ExtractedItem):
    """A directional transfer of data between two components."""

    source_component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                f"{_REF_ID} Target list fields: `components`, `data_stores`."
            ),
        ),
    ]
    destination_component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                f"{_REF_ID} Target list fields: `components`, `data_stores`."
            ),
        ),
    ]
    protocol: Annotated[str, Field(strict=True, min_length=1)]
    authentication_method: Annotated[str, Field(strict=True, min_length=1)]
    data_elements: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(min_length=1),
    ]
    encrypted_in_transit: StrictBool
    trust_boundary_crossed: Annotated[
        StrictBool,
        Field(
            description=(
                "True when source and destination ids belong to no common "
                "`trust_boundaries.component_ids` membership set. Must agree with "
                "actual trust-boundary membership."
            ),
        ),
    ]
    actor_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=f"{_REF_ID} Target list field: `actors`.",
            ),
        ]
    ] = Field(default_factory=list)


class TrustBoundary(ExtractedItem):
    """A security boundary containing architecture components."""

    boundary_type: TrustBoundaryType = TrustBoundaryType.UNKNOWN
    component_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    f"{_REF_ID} Target list fields: `components`, `data_stores`."
                ),
            ),
        ]
    ] = Field(default_factory=list)


class EntryPoint(ExtractedItem):
    """An interface through which an actor can reach a component."""

    component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `components`.",
        ),
    ]
    protocol: Annotated[str, Field(strict=True, min_length=1)]
    authentication_method: Annotated[str, Field(strict=True, min_length=1)]
    exposure: ExposureType = ExposureType.UNKNOWN
    actor_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=(
                f"{_REF_ID} Target list field: `actors`. Set when the source "
                "identifies the primary actor for this entry point."
            ),
        ),
    ] | None = None
    trust_level_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=f"{_REF_ID} Target list field: `trust_levels`.",
            ),
        ]
    ] = Field(
        default_factory=list,
        description="Trust levels required to use this entry point.",
    )


class DeploymentModel(ExtractedItem):
    """The application's deployment topology and hosting context."""

    deployment_type: DeploymentType = DeploymentType.UNKNOWN
    provider: Annotated[str, Field(strict=True, min_length=1)] | None = None
    regions: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(default_factory=list)


class TrustLevel(ExtractedItem):
    """Access rights granted to external entities per OWASP.

    Trust levels represent the access rights that the application will grant
    to external entities and are cross-referenced with entry points and actors.
    """

    access_rights: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(
            min_length=1,
            description="Specific access rights or permissions granted at this trust level.",
        ),
    ]


class ExitPoint(ExtractedItem):
    """An interface through which data leaves the application.

    Per OWASP: Exit points might prove useful when attacking the client
    (e.g., cross-site scripting, information disclosure vulnerabilities).
    """

    component_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `components`.",
        ),
    ]
    data_elements: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(
            min_length=1,
            description="Data elements that may be exposed through this exit point.",
        ),
    ]
    protocol: Annotated[str, Field(strict=True, min_length=1)]
    related_entry_point_id: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            description=f"{_REF_ID} Target list field: `entry_points`. "
            "Set when this exit point correlates with an entry point.",
        ),
    ] | None = None


class ExternalDependency(ExtractedItem):
    """An external item that may pose a threat to the application.

    Per OWASP: External dependencies are items external to the code of the
    application that may pose a threat to the application. Examples include
    operating systems, web servers, databases, and third-party libraries.
    """

    security_assumptions: Annotated[
        list[Annotated[str, Field(strict=True, min_length=1)]],
        Field(
            min_length=1,
            description="Security assumptions about this dependency that must hold.",
        ),
    ]
    version: Annotated[str, Field(strict=True, min_length=1)] | None = None
    component_ids: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=f"{_REF_ID} Target list field: `components`.",
            ),
        ]
    ] = Field(
        default_factory=list,
        description="Components that rely on this external dependency.",
    )


class CanonicalSystemModel(ContractModel):
    """Normalized architecture model consumed by threat analysis workflows."""

    application: ApplicationInfo
    actors: list[Actor]
    components: list[Component]
    data_stores: list[DataStore]
    data_flows: list[DataFlow]
    trust_boundaries: list[TrustBoundary]
    entry_points: list[EntryPoint]
    deployment: DeploymentModel
    assumptions: list[Annotated[str, Field(strict=True, min_length=1)]]
    missing_information: list[
        Annotated[
            str,
            Field(
                strict=True,
                min_length=1,
                description=(
                    "Unresolved facts and linkage gaps. When an extracted item cannot "
                    "be attached via a reference-graph edge, cite that item's `id` here."
                ),
            ),
        ]
    ]
    diagram_evidence: list[Annotated[str, Field(strict=True, min_length=1)]] = Field(
        default_factory=list,
        description=(
            "Deprecated: prefer diagram_topology. Short prose topology summaries "
            "when diagrams are present."
        ),
    )
    diagram_topology: list[DiagramTopologySnapshot] = Field(
        default_factory=list,
        description=(
            "Structured diagram nodes and edges copied from the parsed document. "
            "Host-owned; not constructed via add_* tools."
        ),
        json_schema_extra={"x_host_owned": True},
    )
    trust_levels: list[TrustLevel] = Field(
        default_factory=list,
        description=(
            "OWASP trust levels representing access rights granted to external entities. "
            "Cross-referenced with actors and entry points."
        ),
    )
    exit_points: list[ExitPoint] = Field(
        default_factory=list,
        description=(
            "Interfaces through which data leaves the application. "
            "Useful for identifying information disclosure and XSS vulnerabilities."
        ),
    )
    external_dependencies: list[ExternalDependency] = Field(
        default_factory=list,
        description=(
            "External items that may pose a threat to the application. "
            "Examples: operating systems, web servers, databases, libraries."
        ),
    )
