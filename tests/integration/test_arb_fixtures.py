"""Integration coverage for complete, partial, and sparse ARB fixtures."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from threatmodeler.cli.main import build_app
from threatmodeler.config.settings import Settings
from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.contracts.integration import ParsedDocument
from typer.testing import CliRunner

from tests.fixtures.expected_outputs import (
    EXPECTED_ANALYZE_JSON_COUNT,
    EXPECTED_ARTIFACT_JSON_NAMES,
    assert_expected_artifact_json_files,
    assert_expected_rendered_outputs,
)


@pytest.fixture
def full_sample_arb_path() -> Path:
    """Return the full root-level Payments ARB used for e2e regression."""
    return Path(__file__).resolve().parents[2] / "sample-arb.full.html"


class TestFullSampleArbIngestPositive:
    """Verify the full sample ARB parses with expected section richness."""

    def test_full_arb_ingest_preserves_section_structure_and_topology(
        self,
        tmp_path: Path,
        full_sample_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        assert full_sample_arb_path.is_file()
        output_dir = tmp_path / "full-arb-out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(full_sample_arb_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads((output_dir / "parsed-document.json").read_text(encoding="utf-8"))
        document = ParsedDocument.model_validate(payload)
        heading_texts = [heading.text for heading in document.headings]
        assert document.title == "Payments Platform ARB"
        assert "Users and actors" in heading_texts
        assert "Components" in heading_texts
        assert "Data stores" in heading_texts
        assert "Data flows" in heading_texts
        assert "Trust boundaries" in heading_texts
        assert "Entry points" in heading_texts
        assert "Deployment" in heading_texts
        assert "Architecture diagram" in heading_texts
        assert len(document.tables) >= 6
        assert "Retail customer" in document.raw_text
        assert "payments-api-workload" in document.raw_text
        assert (
            "Internet / untrusted clients" in document.raw_text or "Internet" in document.raw_text
        )
        assert document.diagram_topology
        assert any(snapshot.nodes for snapshot in document.diagram_topology)
        assert any(snapshot.edges for snapshot in document.diagram_topology)
        assert any(
            attachment.filename == "payments-runtime.drawio" for attachment in document.attachments
        )


class TestArbFixtureIngestPositive:
    """Verify ARB fixtures produce parsed documents with expected richness."""

    def test_complete_arb_ingest_extracts_rich_architecture_content(
        self,
        tmp_path: Path,
        complete_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "complete-out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(complete_arb_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 0
        payload = json.loads((output_dir / "parsed-document.json").read_text())
        document = ParsedDocument.model_validate(payload)
        heading_texts = [heading.text for heading in document.headings]
        assert document.title == "Payments Platform ARB"
        assert "Actors" in heading_texts
        assert any("Deployment" in text for text in heading_texts)
        assert len(document.tables) >= 1
        assert len(document.tables[0].rows) >= 6
        assert len(document.paragraphs) >= 10
        assert any(paragraph.text.startswith("Diagram:") for paragraph in document.paragraphs)
        assert len(document.attachments) == 1
        assert document.attachments[0].filename == "payments-runtime.drawio"
        assert "Payments API" in document.raw_text
        assert "Trust boundaries" in document.raw_text
        assert "OAuth 2.0" in document.raw_text
        assert "Example Cloud" in document.raw_text
        assert document.diagram_topology
        assert any(snapshot.edges for snapshot in document.diagram_topology)
        assert any(
            edge.source_id == "1" and edge.target_id == "2"
            for snapshot in document.diagram_topology
            for edge in snapshot.edges
        )

    def test_partial_arb_ingest_preserves_known_gaps(
        self,
        tmp_path: Path,
        partial_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "partial-out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(partial_arb_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 0
        payload = json.loads((output_dir / "parsed-document.json").read_text())
        document = ParsedDocument.model_validate(payload)
        table_text = " ".join(cell for row in document.tables[0].rows for cell in row)
        paragraph_text = " ".join(paragraph.text for paragraph in document.paragraphs)
        assert document.title == "Payments Platform ARB (Draft)"
        assert len(document.tables) == 1
        assert "Web checkout" in table_text
        assert "Payment database" in table_text
        assert any("Token lifetime" in paragraph.text for paragraph in document.paragraphs)
        assert any("open questions" in heading.text.lower() for heading in document.headings)
        assert "disaster recovery" in paragraph_text.lower()
        assert "trust boundaries" in paragraph_text.lower()
        assert len(document.attachments) == 1
        assert document.attachments[0].filename == "payments-runtime.drawio"
        assert "Administrator MFA" in document.raw_text
        assert len(document.paragraphs) < 20

    def test_sparse_arb_ingest_keeps_minimal_extractable_content(
        self,
        tmp_path: Path,
        sparse_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "sparse-out"
        app = build_app(Settings(), agent_provider_factory)

        result = CliRunner().invoke(
            app,
            ["ingest", "--input", str(sparse_arb_path), "--output", str(output_dir)],
        )

        assert result.exit_code == 0
        payload = json.loads((output_dir / "parsed-document.json").read_text())
        document = ParsedDocument.model_validate(payload)
        assert document.title == "Payments Initiative"
        assert document.tables == []
        assert len(document.headings) == 2
        assert len(document.paragraphs) <= 3
        assert document.attachments == []
        assert "remain to be determined" in document.raw_text
        assert "PostgreSQL" not in document.raw_text


class TestArbFixtureAnalyzePositive:
    """Verify each ARB fixture runs the full mocked analyze workflow."""

    @pytest.mark.parametrize(
        ("fixture_path", "expected_title"),
        [
            ("complete-payments-arb.html", "Payments Platform ARB"),
            ("partial-payments-arb.html", "Payments Platform ARB (Draft)"),
            ("sparse-payments-arb.html", "Payments Initiative"),
        ],
    )
    def test_analyze_succeeds_for_arb_fixtures(
        self,
        tmp_path: Path,
        arb_fixtures_dir: Path,
        agent_provider_factory: Callable[..., Mock],
        fixture_path: str,
        expected_title: str,
    ) -> None:
        source_path = arb_fixtures_dir / fixture_path
        output_dir = tmp_path / fixture_path.replace(".html", "-out")
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
        assert f"Application: {expected_title}" in result.stdout
        assert "Components:" in result.stdout
        assert "Threats:" in result.stdout
        assert "Missing information: 2" in result.stdout
        assert (output_dir / "parsed-document.json").is_file()
        assert (output_dir / "system-model.json").is_file()
        assert_expected_artifact_json_files(output_dir)
        assert len(list(output_dir.glob("*.json"))) == EXPECTED_ANALYZE_JSON_COUNT
        assert_expected_rendered_outputs(output_dir / "rendered")
        bundle = ArtifactBundle.model_validate_json(
            (output_dir / "artifact-bundle.json").read_text()
        )
        assert bundle.artifact_id == "artifact-bundle"
        assert len(bundle.missing_information_report.items) == 2


class TestArbFixturePipelinePositive:
    """Verify staged CLI commands succeed for a complete ARB fixture."""

    def test_staged_pipeline_succeeds_for_complete_arb(
        self,
        tmp_path: Path,
        complete_arb_path: Path,
        agent_provider_factory: Callable[..., Mock],
    ) -> None:
        output_dir = tmp_path / "out"
        rendered_dir = output_dir / "rendered"
        app = build_app(Settings(), agent_provider_factory)
        runner = CliRunner()

        ingest_result = runner.invoke(
            app,
            ["ingest", "--input", str(complete_arb_path), "--output", str(output_dir)],
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
        assert EXPECTED_ARTIFACT_JSON_NAMES.issubset(
            {path.name for path in output_dir.glob("*.json")}
        )
        assert_expected_rendered_outputs(rendered_dir)
