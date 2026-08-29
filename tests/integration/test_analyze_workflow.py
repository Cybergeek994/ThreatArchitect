"""End-to-end acceptance test for the analyze command."""

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from threatmodeler.cli.main import build_app
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import AnalysisSummary
from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.contracts.system_model import CanonicalSystemModel
from typer.testing import CliRunner

from tests.fixtures.expected_outputs import (
    EXPECTED_ANALYZE_JSON_COUNT,
    EXPECTED_ARTIFACT_JSON_NAMES,
    assert_expected_artifact_json_files,
    assert_expected_rendered_outputs,
)
from tests.fixtures.sample_arb import write_sample_arb


class TestAnalyzeWorkflowPositive:
    """Verify supported inputs and successful behavior."""

    def test_analyze_runs_complete_mock_workflow(
        self,
        tmp_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        source_path = write_sample_arb(tmp_path)
        output_dir = tmp_path / "out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(source_path),
                "--output",
                str(output_dir),
                "--formats",
                "json,mermaid,markdown,flow",
            ],
        )

        assert result.exit_code == 0
        assert "Application: Sample Payments ARB" in result.stdout
        assert "Components: 1" in result.stdout
        assert "Data flows: 0" in result.stdout
        assert "Threats: 1" in result.stdout
        assert "Missing information: 2" in result.stdout
        assert f"Output directory: {output_dir.resolve()}" in result.stdout

        assert (output_dir / "parsed-document.json").is_file()
        assert (output_dir / "system-model.json").is_file()
        assert_expected_artifact_json_files(output_dir)
        assert {path.name for path in output_dir.glob("*.json")} == EXPECTED_ARTIFACT_JSON_NAMES | {
            "parsed-document.json",
            "system-model.json",
        }
        assert len(list(output_dir.glob("*.json"))) == EXPECTED_ANALYZE_JSON_COUNT
        assert_expected_rendered_outputs(output_dir / "rendered")

        system_model = CanonicalSystemModel.model_validate_json(
            (output_dir / "system-model.json").read_text()
        )
        bundle = ArtifactBundle.model_validate_json(
            (output_dir / "artifact-bundle.json").read_text()
        )
        assert system_model.application.name == "Sample Payments ARB"
        assert len(system_model.components) == 1
        assert len(system_model.missing_information) == 2
        assert bundle.artifact_id == "artifact-bundle"
        assert len(bundle.stride_threat_register.threats) == 1
        assert len(bundle.missing_information_report.items) == 2

    def test_analyze_succeeds_when_fail_on_missing_and_no_gaps(
        self,
        tmp_path: Path,
        complete_model_provider: Mock,
    ) -> None:
        source_path = write_sample_arb(tmp_path)
        output_dir = tmp_path / "out"
        app = build_app(
            Settings(fail_on_missing_information=True),
            lambda: complete_model_provider,
        )

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(source_path),
                "--output",
                str(output_dir),
                "--formats",
                "json,mermaid,markdown,flow",
            ],
        )

        assert result.exit_code == 0
        assert "Missing information: 0" in result.stdout
        assert_expected_artifact_json_files(output_dir)
        assert_expected_rendered_outputs(output_dir / "rendered")

    def test_analyze_with_agent_assisted_generation(
        self,
        tmp_path: Path,
        agent_assisted_provider: Mock,
    ) -> None:
        source_path = write_sample_arb(tmp_path)
        output_dir = tmp_path / "out"
        app = build_app(Settings(), lambda: agent_assisted_provider)

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(source_path),
                "--output",
                str(output_dir),
                "--formats",
                "json,mermaid,markdown,flow",
            ],
        )

        assert result.exit_code == 0
        assert_expected_artifact_json_files(output_dir)
        task_names = [
            call.args[0].task_name for call in agent_assisted_provider.complete.call_args_list
        ]
        assert "extract_canonical_system_model" in task_names
        assert "generate_stride_threats" in task_names
        assert "generate_attack_tree" in task_names
        assert "generate_dfd" in task_names

    def test_analysis_summary_is_a_strict_pydantic_contract(self, tmp_path: Path) -> None:
        summary = AnalysisSummary(
            application_name="Payments",
            component_count=2,
            data_flow_count=1,
            threat_count=3,
            missing_information_count=1,
            output_directory=tmp_path,
        )

        assert AnalysisSummary.model_validate_json(summary.model_dump_json()) == summary


class TestAnalyzeWorkflowNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_analysis_summary_rejects_negative_counts(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="threat_count"):
            AnalysisSummary(
                application_name="Payments",
                component_count=1,
                data_flow_count=1,
                threat_count=-1,
                missing_information_count=0,
                output_directory=tmp_path,
            )


class TestAnalyzeWorkflowErrors:
    """Verify dependency and application failures remain controlled."""

    def test_analyze_reports_missing_input_without_partial_outputs(
        self,
        tmp_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        missing_source = tmp_path / "missing-arb.html"
        output_dir = tmp_path / "out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(missing_source),
                "--output",
                str(output_dir),
            ],
        )

        assert result.exit_code == 1
        assert "Unable to read the local Confluence export" in result.stderr
        assert "Traceback" not in result.stderr
        assert not output_dir.exists()

    def test_analyze_blocks_when_fail_on_missing(
        self,
        tmp_path: Path,
        blocking_model_provider: Mock,
    ) -> None:
        source_path = write_sample_arb(tmp_path)
        output_dir = tmp_path / "out"
        app = build_app(
            Settings(fail_on_missing_information=True),
            lambda: blocking_model_provider,
        )

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(source_path),
                "--output",
                str(output_dir),
            ],
        )

        assert result.exit_code == 1
        assert "[MISSING_INFORMATION_BLOCKING]" in result.stderr
        assert "Architecture information gaps" in result.stderr
        assert "Traceback" not in result.stderr
        assert (output_dir / "parsed-document.json").is_file()
        assert not (output_dir / "system-model.json").is_file()
        assert not (output_dir / "artifact-bundle.json").is_file()

    def test_analyze_surfaces_agent_failure(
        self,
        tmp_path: Path,
        failing_agent_provider: Mock,
    ) -> None:
        source_path = write_sample_arb(tmp_path)
        output_dir = tmp_path / "out"
        app = build_app(Settings(), lambda: failing_agent_provider)

        result = CliRunner().invoke(
            app,
            [
                "analyze",
                "--input",
                str(source_path),
                "--output",
                str(output_dir),
            ],
        )

        assert result.exit_code == 1
        assert "[FAKE_AGENT_FAILURE]" in result.stderr
        assert "Traceback" not in result.stderr
        assert (output_dir / "parsed-document.json").is_file()
        assert not (output_dir / "artifact-bundle.json").is_file()
