"""Tests for shared StrEnum constants."""

from threatmodeler.shared.constants import (
    AgentProviderName,
    AsvsChapter,
    ControlFramework,
    ControlFrameworkName,
    EnvironmentVariable,
    OutputFormat,
    PlaceholderAuthentication,
)


class TestSharedConstantsPositive:
    """Verify shared enumerations expose stable identifier values."""

    def test_control_framework_identifiers_match_expected_values(self) -> None:
        assert ControlFramework.OWASP_ASVS.value == "owasp_asvs"
        assert ControlFrameworkName.OWASP_ASVS.value == "OWASP ASVS 4.0"

    def test_placeholder_authentication_contains_known_labels(self) -> None:
        assert "unknown" in PlaceholderAuthentication
        assert "n/a" in PlaceholderAuthentication
        assert "concrete-auth" not in PlaceholderAuthentication

    def test_output_format_csv_preserves_definition_order(self) -> None:
        assert OutputFormat.csv() == "json,mermaid,markdown,flow"

    def test_asvs_chapters_use_catalog_identifiers(self) -> None:
        assert AsvsChapter.V2 == "V2"
        assert AsvsChapter.V4 == "V4"

    def test_agent_provider_names_include_github_copilot_alias(self) -> None:
        assert AgentProviderName.GITHUB_COPILOT.value == "github_copilot"
        assert AgentProviderName.COPILOT.value == "copilot"
        assert EnvironmentVariable.GITHUB_TOKEN.value == "THREATMODELER_GITHUB_TOKEN"
