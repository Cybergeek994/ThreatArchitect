"""Tests for shared StrEnum constants."""

from threatmodeler.shared.constants import (
    AgentProviderName,
    EnvironmentVariable,
    OutputFormat,
    PlaceholderAuthentication,
)


class TestSharedConstantsPositive:
    """Verify shared enumerations expose stable identifier values."""

    def test_placeholder_authentication_contains_known_labels(self) -> None:
        assert "unknown" in PlaceholderAuthentication
        assert "n/a" in PlaceholderAuthentication
        assert "concrete-auth" not in PlaceholderAuthentication

    def test_output_format_csv_preserves_definition_order(self) -> None:
        assert OutputFormat.csv() == "json,mermaid,markdown,flow"

    def test_agent_provider_names_include_github_copilot_alias(self) -> None:
        assert AgentProviderName.GITHUB_COPILOT.value == "github_copilot"
        assert AgentProviderName.COPILOT.value == "copilot"
        assert EnvironmentVariable.GITHUB_TOKEN.value == "THREATMODELER_GITHUB_TOKEN"
