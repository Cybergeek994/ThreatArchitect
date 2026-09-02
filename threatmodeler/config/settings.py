"""Environment-backed application settings."""

from pathlib import Path
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from threatmodeler.shared.constants import (
    AgentProviderName,
    AsvsFrameworkVersion,
    AzureOpenAiApiVersion,
    ControlFramework,
    DefaultPathName,
    EnvironmentVariable,
    LogLevel,
)


class Settings(BaseSettings):
    """Provide immutable configuration from ``THREATMODELER_*`` environment values."""

    model_config = SettingsConfigDict(
        env_prefix=EnvironmentVariable.PREFIX,
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        str_strip_whitespace=True,
    )

    agent_provider_name: Annotated[str, Field(min_length=1)] = AgentProviderName.OPENAI
    agent_model_name: Annotated[str, Field(min_length=1)] = "agent-model"
    agent_provider_max_attempts: Annotated[int, Field(ge=1)] = 3
    agent_schema_repair_attempts: Annotated[int, Field(ge=0)] = 1
    agent_request_timeout_seconds: Annotated[float, Field(gt=0)] = 300.0
    agent_tool_calling_max_turns: Annotated[int, Field(ge=1)] = 32
    agent_tool_calling_stall_after_repeats: Annotated[int, Field(ge=1)] = 2
    agent_journal_enabled: bool = True
    agent_low_confidence_threshold: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    fail_on_missing_information: bool = False
    control_framework: ControlFramework = ControlFramework.OWASP_ASVS
    control_framework_version: Annotated[str, Field(min_length=1)] = AsvsFrameworkVersion.V5_0_0
    asvs_catalog_cache_dir: Path = Path(".cache/asvs-catalog")
    asvs_catalog_ttl_hours: Annotated[int, Field(ge=1)] = 168
    asvs_catalog_fetch_url: Annotated[str, Field(min_length=1)] | None = None
    azure_openai_api_version: Annotated[str, Field(min_length=1)] = (
        AzureOpenAiApiVersion.PREVIEW_2024_08_01
    )
    output_dir: Path = Path(DefaultPathName.OUTPUT_DIR)
    log_level: LogLevel = LogLevel.INFO
    confluence_base_url: AnyHttpUrl | None = None
    confluence_user_email: Annotated[str, Field(min_length=3)] | None = None
    confluence_api_key: SecretStr | None = None
    confluence_attachment_max_bytes: Annotated[int, Field(ge=1)] = 10_000_000
    confluence_attachment_max_count: Annotated[int, Field(ge=1)] = 50
    agent_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    azure_openai_api_key: SecretStr | None = None
    azure_openai_endpoint: AnyHttpUrl | None = None
    github_token: SecretStr | None = None

    @field_validator("control_framework", mode="before")
    @classmethod
    def require_supported_control_framework(cls, control_framework: object) -> object:
        """Restrict control mapping to the supported OWASP ASVS catalog.

        Args:
            control_framework: Candidate framework identifier from configuration.

        Returns:
            Normalized framework identifier.

        Raises:
            ValueError: If the framework is not the supported OWASP ASVS catalog.
        """
        if isinstance(control_framework, str):
            return control_framework.strip().lower()
        return control_framework  # pragma: no cover

    @field_validator("output_dir")
    @classmethod
    def require_directory_path(cls, output_dir: Path) -> Path:
        """Validate that the configured output path is not an existing file.

        Args:
            output_dir: Candidate directory path loaded from configuration.

        Returns:
            Original output path after validation.

        Raises:
            ValueError: If the path already exists as a regular file.
        """
        expanded_path = output_dir.expanduser()
        if expanded_path.exists() and not expanded_path.is_dir():
            raise ValueError("output_dir must identify a directory, not a file")
        return output_dir
