"""Shared string enumerations used in place of module-level constants."""

from enum import StrEnum


class LogLevel(StrEnum):
    """Supported application log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ControlFramework(StrEnum):
    """Configuration identifiers for supported control catalogs."""

    OWASP_ASVS = "owasp_asvs"


class ControlFrameworkName(StrEnum):
    """Human-readable control-framework labels used in artifacts and prompts."""

    OWASP_ASVS = "OWASP ASVS 5.0.0"


class AsvsFrameworkVersion(StrEnum):
    """Supported OWASP ASVS release versions for catalog snapshots."""

    V5_0_0 = "5.0.0"


class AsvsChapter(StrEnum):
    """Legacy ASVS 4.0 chapter identifiers used by the curated catalog matcher."""

    V1 = "V1"
    V2 = "V2"
    V4 = "V4"
    V5 = "V5"
    V8 = "V8"
    V12 = "V12"


class AsvsCatalogFetchUrl(StrEnum):
    """Remote URLs for official OWASP ASVS flat exports."""

    V5_0_0_FLAT = (
        "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/OWASP%20Application"
        "%20Security%20Verification%20Standard%205.0.0-en.flat.json"
    )


class PlaceholderAuthentication(StrEnum):
    """Authentication labels treated as placeholders on external entry points."""

    UNKNOWN = "unknown"
    NOT_APPLICABLE = "n/a"
    NONE = "none"
    PLACEHOLDER = "placeholder"
    TO_BE_DETERMINED = "tbd"


class PackagedDataFile(StrEnum):
    """Filenames and package names for packaged static data."""

    PACKAGE = "threatmodeler.data"
    OWASP_ASVS_CONTROLS = "owasp_asvs_controls.json"
    OWASP_ASVS_FLAT = "owasp_asvs_5.0.0.flat.json"


class AgentProviderName(StrEnum):
    """Supported agent-provider strategy names."""

    OPENAI = "openai"
    AZURE = "azure"
    AZURE_OPENAI = "azure_openai"
    GITHUB_COPILOT = "github_copilot"
    COPILOT = "copilot"


class OutputFormat(StrEnum):
    """Deterministic renderer format names accepted by the CLI and rendering service."""

    JSON = "json"
    MERMAID = "mermaid"
    MARKDOWN = "markdown"
    FLOW = "flow"

    @classmethod
    def csv(cls) -> str:
        """Return the default comma-separated format list in definition order.

        Returns:
            Format names joined by commas, matching the CLI ``--formats`` default.
        """
        return ",".join(member.value for member in cls)


class ArtifactKind(StrEnum):
    """Renderer artifact-kind identifiers paired with output formats."""

    ARTIFACT_BUNDLE = "artifact-bundle"
    DFD = "dfd"
    ARCHITECTURE_GRAPH = "architecture-graph"
    ATTACK_TREE = "attack-tree"
    TRUST_BOUNDARIES = "trust-boundaries"
    TECHNICAL_REPORT = "technical-report"


class EnvironmentVariable(StrEnum):
    """Environment variable names consumed by settings and provider factories."""

    PREFIX = "THREATMODELER_"
    OPENAI_API_KEY = "THREATMODELER_OPENAI_API_KEY"
    AGENT_API_KEY = "THREATMODELER_AGENT_API_KEY"
    AZURE_OPENAI_API_KEY = "THREATMODELER_AZURE_OPENAI_API_KEY"
    AZURE_OPENAI_ENDPOINT = "THREATMODELER_AZURE_OPENAI_ENDPOINT"
    GITHUB_TOKEN = "THREATMODELER_GITHUB_TOKEN"


class DefaultPathName(StrEnum):
    """Default filesystem path names used when settings or CLI flags are omitted."""

    OUTPUT_DIR = "artifacts"
    JOURNAL_DIR = "journal"


class JournalEventType(StrEnum):
    """Durable construction-journal event names written during tool-calling runs."""

    TOOL_CALL_RECEIVED = "tool_call_received"
    TOOL_CALL_ACCEPTED = "tool_call_accepted"
    TOOL_CALL_REJECTED = "tool_call_rejected"
    FINISH_ATTEMPTED = "finish_attempted"
    FINISH_REJECTED = "finish_rejected"
    FINISH_ACCEPTED = "finish_accepted"
    TURN_BUDGET_EXCEEDED = "turn_budget_exceeded"
    TURN_COMPLETED = "turn_completed"
    SCHEMA_REPAIR_ATTEMPTED = "schema_repair_attempted"
    ASSEMBLED = "assembled"


class AzureOpenAiApiVersion(StrEnum):
    """Azure OpenAI REST API versions accepted by the configured SDK client."""

    PREVIEW_2024_08_01 = "2024-08-01-preview"


class VisionMediaType(StrEnum):
    """Image MIME types accepted by OpenAI vision endpoints."""

    PNG = "image/png"
    JPEG = "image/jpeg"
    JPG = "image/jpg"
    GIF = "image/gif"
    WEBP = "image/webp"


class StopWord(StrEnum):
    """English stop words excluded from evidence token overlap checks."""

    A = "a"
    AN = "an"
    AND = "and"
    AS = "as"
    AT = "at"
    BY = "by"
    FOR = "for"
    FROM = "from"
    IN = "in"
    IS = "is"
    OF = "of"
    ON = "on"
    OR = "or"
    THE = "the"
    TO = "to"
    WITH = "with"


class CopilotModelName(StrEnum):
    """Configured Copilot model names and SDK placeholders."""

    AUTO = "auto"
    PLACEHOLDER = "agent-model"
