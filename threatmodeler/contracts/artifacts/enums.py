"""Closed vocabularies used by MVP1 artifacts."""

from enum import StrEnum


class StrideCategory(StrEnum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class RiskSeverity(StrEnum):
    """Risk impact severity."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLikelihood(StrEnum):
    """Qualitative probability of risk realization."""

    RARE = "rare"
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    LIKELY = "likely"
    ALMOST_CERTAIN = "almost_certain"


class RiskStatus(StrEnum):
    """Risk treatment lifecycle state."""

    OPEN = "open"
    ACCEPTED = "accepted"
    MITIGATED = "mitigated"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


class ThreatStatus(StrEnum):
    """Threat analysis lifecycle state."""

    IDENTIFIED = "identified"
    ANALYZED = "analyzed"
    PARTIALLY_MITIGATED = "partially_mitigated"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


class ControlType(StrEnum):
    """Security control categories per layered defense guidance."""

    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class CompletenessCheckStatus(StrEnum):
    """Outcome of a threat-model completeness verification check."""

    SATISFIED = "satisfied"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


class CompletenessCheckId(StrEnum):
    """Stable identifiers for verify-phase completeness checks."""

    DFD_PRESENT = "dfd-present"
    EXTERNAL_ENTRY_COVERAGE = "external-entry-coverage"
    THREAT_MITIGATION_LINKAGE = "threat-mitigation-linkage"
    MISSING_INFORMATION_DOCUMENTED = "missing-information-documented"
    THREAT_EVIDENCE_PRESENT = "threat-evidence-present"
    ARCHITECTURE_GRAPH_ENTRY_PATH_COVERAGE = "architecture-graph-entry-path-coverage"
    THREAT_ATTACK_PATH_GROUNDED = "threat-attack-path-grounded"


class ProvenanceConstraintKey(StrEnum):
    """Prompt constraint keys for STRIDE threat provenance guidance."""

    RATIONALE = "coverage_provenance_rationale"
    ATTACK_PATH = "coverage_provenance_attack_path"
    ATTACK_PATH_ID = "coverage_provenance_attack_path_id"
    ENTRY_POINTS = "coverage_provenance_entry_points"
    TRUST_BOUNDARY = "coverage_provenance_trust_boundary"
    ACTOR = "coverage_provenance_actor"
    EVIDENCE = "coverage_provenance_evidence"


class GraphNodeKind(StrEnum):
    """Typed architecture graph node categories."""

    ACTOR = "actor"
    SERVICE = "service"
    API = "api"
    DATABASE = "database"
    QUEUE = "queue"
    STORAGE = "storage"
    IDENTITY = "identity"
    SECRET = "secret"
    EXTERNAL_SERVICE = "external_service"
    AGENT = "agent"
    LLM = "llm"
    TOOL = "tool"
    ENTRY_SURFACE = "entry_surface"


class GraphEdgeKind(StrEnum):
    """Typed architecture graph edge categories."""

    CALLS = "calls"
    AUTHENTICATES_TO = "authenticates_to"
    READS = "reads"
    WRITES = "writes"
    TRUSTS = "trusts"
    EXECUTES = "executes"
    ASSUMES_ROLE = "assumes_role"
    USES_SECRET = "uses_secret"
    SENDS_DATA_TO = "sends_data_to"
    EXPOSES = "exposes"
    ROUTES_TO = "routes_to"
    ENQUEUES = "enqueues"
    DEQUEUES = "dequeues"
    DEPENDS_ON = "depends_on"
    INVOKES = "invokes"
    DELEGATES_TO = "delegates_to"
    CROSSES = "crosses"


class StrideInputPayloadField(StrEnum):
    """Serialized keys for STRIDE agent input payload fields."""

    SYSTEM_MODEL = "system_model"
    DIAGRAM_EVIDENCE = "diagram_evidence"
    DIAGRAM_TOPOLOGY = "diagram_topology"
    COMPONENT_INVENTORY = "component_inventory"
    ASSET_INVENTORY = "asset_inventory"
    ACTOR_MODEL = "actor_model"
    DATA_FLOW_DIAGRAM = "data_flow_diagram"
    TRUST_BOUNDARY_MAP = "trust_boundary_map"
    ENTRY_POINT_INVENTORY = "entry_point_inventory"
    AUTHENTICATION_AUTHORIZATION_MODEL = "authentication_authorization_model"
    DEPLOYMENT_MODEL = "deployment_model"
    ARCHITECTURE_GRAPH = "architecture_graph"


class GraphListField(StrEnum):
    """List field names on ArchitectureGraph construction tools."""

    NODES = "nodes"
    EDGES = "edges"
    ATTACK_PATHS = "attack_paths"


class AssetType(StrEnum):
    """Security-relevant asset categories."""

    DATA = "data"
    CREDENTIAL = "credential"
    SERVICE = "service"
    INFRASTRUCTURE = "infrastructure"
    FINANCIAL = "financial"
    REPUTATION = "reputation"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    OTHER = "other"


class AuthenticationType(StrEnum):
    """Authentication mechanism categories."""

    PASSWORD = "password"
    MULTI_FACTOR = "multi_factor"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    WORKLOAD_IDENTITY = "workload_identity"
    NONE = "none"
    UNKNOWN = "unknown"


class AuthorizationModelType(StrEnum):
    """Authorization policy models."""

    RBAC = "rbac"
    ABAC = "abac"
    ACL = "acl"
    POLICY_BASED = "policy_based"
    CUSTOM = "custom"
    NONE = "none"
    UNKNOWN = "unknown"


class MitigationStatus(StrEnum):
    """Mitigation delivery state."""

    PROPOSED = "proposed"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    DEFERRED = "deferred"


class WorkPriority(StrEnum):
    """Delivery priority for requirements and mitigations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityRequirementCategory(StrEnum):
    """Security requirement categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    ACCOUNTABILITY = "accountability"
    PRIVACY = "privacy"
    LOGGING_MONITORING = "logging_monitoring"
    SECURE_CONFIGURATION = "secure_configuration"


class AssumptionStatus(StrEnum):
    """Assumption verification state."""

    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    INVALIDATED = "invalidated"


class AttackTreeNodeType(StrEnum):
    """Attack tree node types per OWASP threat tree guidance.

    OWASP threat trees distinguish between goals, attack steps,
    vulnerabilities, and countermeasures for visual differentiation.
    """

    GOAL = "goal"
    ATTACK_STEP = "attack_step"
    VULNERABILITY = "vulnerability"
    COUNTERMEASURE = "countermeasure"


class AttackDifficulty(StrEnum):
    """Qualitative attack difficulty assessment."""

    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXPERT = "expert"


class RiskResponseType(StrEnum):
    """Risk mitigation response categories per OWASP.

    Options for addressing identified risks:
    - ACCEPT: Document acceptance and responsible party
    - ELIMINATE: Remove the vulnerable component entirely
    - MITIGATE: Add controls to reduce impact or likelihood
    - TRANSFER: Transfer risk to insurer or customer
    """

    ACCEPT = "accept"
    ELIMINATE = "eliminate"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
