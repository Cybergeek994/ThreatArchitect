"""Integration coverage for settings-driven analyze workflows."""

from pathlib import Path
from unittest.mock import Mock

from threatmodeler.cli.main import build_app
from threatmodeler.config.settings import Settings
from typer.testing import CliRunner

from tests.fixtures.expected_outputs import assert_expected_artifact_json_files


class TestSettingsWorkflowsPositive:
    """Verify supported settings combinations succeed."""

    def test_analyze_succeeds_with_permissive_agent_defaults(
        self,
        tmp_path: Path,
        complete_arb_path: Path,
        agent_provider: Mock,
    ) -> None:
        output_dir = tmp_path / "out"
        app = build_app(Settings(), lambda: agent_provider)

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(complete_arb_path),
                "--output",
                str(output_dir),
                "--formats",
                "json",
            ],
        )

        assert result.exit_code == 0
        assert_expected_artifact_json_files(output_dir)


class TestSettingsWorkflowsErrors:
    """Verify settings combinations that must fail remain controlled."""

    def test_blocking_policy_fails_analyze_when_gaps_exist(
        self,
        tmp_path: Path,
        complete_arb_path: Path,
        blocking_model_provider: Mock,
    ) -> None:
        output_dir = tmp_path / "out"
        app = build_app(
            Settings(fail_on_missing_information=True),
            lambda: blocking_model_provider,
        )

        result = CliRunner().invoke(
            app,
            ["analyze", "--input", str(complete_arb_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 1
        assert "[MISSING_INFORMATION_BLOCKING]" in result.stderr
        assert not (output_dir / "artifact-bundle.json").is_file()

    def test_cli_fail_on_missing_information_flag_blocks_extract(
        self,
        tmp_path: Path,
        complete_arb_path: Path,
        blocking_model_provider: Mock,
    ) -> None:
        output_dir = tmp_path / "out"
        app = build_app(Settings(), lambda: blocking_model_provider)

        result = CliRunner().invoke(
            app,
            [
                "--fail-on-missing-information",
                "analyze",
                "--input",
                str(complete_arb_path),
                "--output",
                str(output_dir),
            ],
        )

        assert result.exit_code == 1
        assert "[MISSING_INFORMATION_BLOCKING]" in result.stderr
