"""Local-file integration coverage for every staged CLI workflow."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

from threatmodeler.cli.main import build_app
from threatmodeler.config.settings import Settings
from threatmodeler.contracts.system_model import CanonicalSystemModel
from typer.testing import CliRunner

from tests.fixtures.expected_outputs import (
    assert_expected_artifact_json_files,
    assert_expected_rendered_outputs,
)


class TestPipelineCommandsPositive:
    """Verify supported inputs and successful behavior."""

    def test_local_pipeline_commands_create_validated_stage_outputs(
        self,
        tmp_path: Path,
        sample_confluence_html: str,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        source_path = tmp_path / "fixture-arb.html"
        output_dir = tmp_path / "out"
        rendered_dir = output_dir / "rendered"
        source_path.write_text(sample_confluence_html, encoding="utf-8")
        app = build_app(Settings(output_dir=output_dir), agent_provider_factory)
        runner = CliRunner()

        ingest_result = runner.invoke(
            app,
            ["ingest", "--input", str(source_path), "--output", str(output_dir)],
        )
        extract_result = runner.invoke(
            app,
            [
                "extract",
                "--input",
                str(output_dir / "parsed-document.json"),
                "--output",
                str(output_dir),
            ],
        )
        model_result = runner.invoke(
            app,
            [
                "model",
                "--input",
                str(output_dir / "system-model.json"),
                "--output",
                str(output_dir),
            ],
        )
        render_result = runner.invoke(
            app,
            [
                "render",
                "--input",
                str(output_dir / "artifact-bundle.json"),
                "--formats",
                "json,mermaid,markdown,flow",
                "--output",
                str(rendered_dir),
            ],
        )

        assert ingest_result.exit_code == 0
        assert extract_result.exit_code == 0
        assert model_result.exit_code == 0
        assert render_result.exit_code == 0
        assert (output_dir / "parsed-document.json").is_file()
        assert (output_dir / "system-model.json").is_file()
        assert_expected_artifact_json_files(output_dir)
        assert_expected_rendered_outputs(rendered_dir)

    def test_staged_pipeline_with_partial_arb_fixture(
        self,
        tmp_path: Path,
        partial_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "out"
        rendered_dir = output_dir / "rendered"
        app = build_app(Settings(), agent_provider_factory)
        runner = CliRunner()

        ingest_result = runner.invoke(
            app,
            ["ingest", "--input", str(partial_arb_path), "--output", str(output_dir)],
        )
        extract_result = runner.invoke(
            app,
            [
                "extract",
                "--input",
                str(output_dir / "parsed-document.json"),
                "--output",
                str(output_dir),
            ],
        )
        model_result = runner.invoke(
            app,
            [
                "model",
                "--input",
                str(output_dir / "system-model.json"),
                "--output",
                str(output_dir),
            ],
        )
        render_result = runner.invoke(
            app,
            [
                "render",
                "--input",
                str(output_dir / "artifact-bundle.json"),
                "--formats",
                "json,mermaid,markdown,flow",
                "--output",
                str(rendered_dir),
            ],
        )

        assert ingest_result.exit_code == 0
        assert extract_result.exit_code == 0
        assert model_result.exit_code == 0
        assert render_result.exit_code == 0
        payload = json.loads((output_dir / "parsed-document.json").read_text())
        assert payload["title"] == "Payments Platform ARB (Draft)"
        assert any("open questions" in heading["text"].lower() for heading in payload["headings"])
        assert_expected_artifact_json_files(output_dir)
        assert_expected_rendered_outputs(rendered_dir)


class TestPipelineCommandsNegative:
    """Verify invalid staged inputs are rejected."""

    def test_render_rejects_missing_bundle(
        self,
        tmp_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        missing_bundle = tmp_path / "missing-bundle.json"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            [
                "render",
                "--input",
                str(missing_bundle),
                "--formats",
                "json",
                "--output",
                str(tmp_path / "rendered"),
            ],
        )

        assert result.exit_code == 1
        assert "Traceback" not in result.stderr


class TestPipelineCommandsErrors:
    """Verify dependency and application failures remain controlled."""

    def test_ingest_missing_input_fails_cleanly(
        self,
        tmp_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        missing_source = tmp_path / "missing-arb.html"
        output_dir = tmp_path / "out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(missing_source), "--output", str(output_dir)],
        )

        assert result.exit_code == 1
        assert "Unable to read the local Confluence export" in result.stderr
        assert "Traceback" not in result.stderr
        assert not output_dir.exists()

    def test_extract_blocks_when_fail_on_missing(
        self,
        tmp_path: Path,
        sample_confluence_html: str,
        blocking_model_provider: Mock,
    ) -> None:
        source_path = tmp_path / "fixture-arb.html"
        output_dir = tmp_path / "out"
        source_path.write_text(sample_confluence_html, encoding="utf-8")
        app = build_app(
            Settings(fail_on_missing_information=True),
            lambda: blocking_model_provider,
        )
        runner = CliRunner()

        ingest_result = runner.invoke(
            app,
            ["ingest", "--input", str(source_path), "--output", str(output_dir)],
        )
        extract_result = runner.invoke(
            app,
            [
                "extract",
                "--input",
                str(output_dir / "parsed-document.json"),
                "--output",
                str(output_dir),
            ],
        )

        assert ingest_result.exit_code == 0
        assert extract_result.exit_code == 1
        assert "[MISSING_INFORMATION_BLOCKING]" in extract_result.stderr
        assert (output_dir / "parsed-document.json").is_file()
        assert not (output_dir / "system-model.json").is_file()

    def test_model_blocks_when_fail_on_missing(
        self,
        tmp_path: Path,
        canonical_system_model: CanonicalSystemModel,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        system_model_path = output_dir / "system-model.json"
        system_model_path.write_text(canonical_system_model.model_dump_json(indent=2))
        app = build_app(
            Settings(fail_on_missing_information=True),
            agent_provider_factory,
        )

        result = CliRunner().invoke(
            app,
            ["model", "--input", str(system_model_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 1
        assert "[MISSING_INFORMATION_BLOCKING]" in result.stderr
        assert {path.name for path in output_dir.glob("*.json")} == {"system-model.json"}
        assert not (output_dir / "artifact-bundle.json").is_file()
