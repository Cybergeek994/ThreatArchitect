"""Typer application construction."""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from threatmodeler.application.analysis_workflow import AnalysisWorkflowService
from threatmodeler.application.artifact_generation_service import ArtifactGenerationService
from threatmodeler.application.extraction_service import SystemModelExtractionService
from threatmodeler.application.ingestion_service import ConfluenceIngestionService
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.shared.constants import DefaultPathName, OutputFormat


def create_app(
    ingestion_service_factory: Callable[[str], ConfluenceIngestionService],
    extraction_service_factory: Callable[[], SystemModelExtractionService],
    artifact_generation_service_factory: Callable[[], ArtifactGenerationService],
    rendering_service_factory: Callable[[], RenderingService],
    analysis_workflow_factory: Callable[[str], AnalysisWorkflowService],
    error_handler: CliErrorHandler,
    *,
    debug: bool = False,
    default_output_dir: Path | None = None,
    apply_cli_settings: Callable[[bool], None] | None = None,
) -> typer.Typer:
    """Create an isolated CLI application with injected dependencies.

    Args:
        ingestion_service_factory: Creates ingestion services for an input reference.
        extraction_service_factory: Creates canonical-model extraction services.
        artifact_generation_service_factory: Creates artifact generation services.
        rendering_service_factory: Creates deterministic output rendering services.
        analysis_workflow_factory: Creates end-to-end analysis workflows.
        error_handler: Applies safe CLI error and debug-output policy.
        debug: Enables detailed error output by default when true.
        default_output_dir: Default output directory when ``--output`` is omitted.
        apply_cli_settings: Optional callback that applies root-flag settings overrides.

    Returns:
        Configured Typer application without executing it.
    """
    resolved_default_output = default_output_dir or Path(DefaultPathName.OUTPUT_DIR)
    app = typer.Typer(
        name="threatmodeler",
        help="Agent-driven architecture threat modeling.",
        no_args_is_help=True,
    )

    debug_enabled = debug

    @app.callback()
    def root(
        debug_option: Annotated[
            bool,
            typer.Option("--debug", help="Show detailed error information."),
        ] = False,
        fail_on_missing_information: Annotated[
            bool,
            typer.Option(
                "--fail-on-missing-information",
                help="Fail extract, model, and analyze when architecture gaps remain.",
            ),
        ] = False,
    ) -> None:
        """Agent-driven architecture threat modeling."""
        nonlocal debug_enabled
        debug_enabled = debug_enabled or debug_option
        if apply_cli_settings is not None:
            apply_cli_settings(fail_on_missing_information)

    @app.command()
    def ingest(
        input_reference: Annotated[
            str,
            typer.Option("--input", help="Local export path, page URL, or page ID."),
        ],
        output_dir: Annotated[
            Path,
            typer.Option(
                "--output",
                help="Directory for generated artifacts.",
                default_factory=lambda: resolved_default_output,
            ),
        ],
    ) -> None:
        """Parse a local export or configured Confluence page."""
        result = error_handler.execute(
            lambda: str(
                ingestion_service_factory(input_reference).ingest(input_reference, output_dir).path
            ),
            debug=debug_enabled,
        )
        typer.echo(result)

    @app.command()
    def extract(
        input_path: Annotated[
            Path,
            typer.Option("--input", help="Path to parsed-document.json."),
        ],
        output_dir: Annotated[
            Path,
            typer.Option(
                "--output",
                help="Directory for generated artifacts.",
                default_factory=lambda: resolved_default_output,
            ),
        ],
    ) -> None:
        """Extract a canonical system model from a parsed document."""
        result = error_handler.execute(
            lambda: str(extraction_service_factory().extract(input_path, output_dir).path),
            debug=debug_enabled,
        )
        typer.echo(result)

    @app.command("model")
    def model_command(
        input_path: Annotated[
            Path,
            typer.Option("--input", help="Path to system-model.json."),
        ],
        output_dir: Annotated[
            Path,
            typer.Option(
                "--output",
                help="Directory for generated artifacts.",
                default_factory=lambda: resolved_default_output,
            ),
        ],
    ) -> None:
        """Generate the complete MVP1 threat-model artifact bundle."""

        def generate_artifacts() -> str:
            result = artifact_generation_service_factory().generate(input_path, output_dir)
            return "\n".join(str(artifact.path) for artifact in result.artifacts)

        typer.echo(error_handler.execute(generate_artifacts, debug=debug_enabled))

    @app.command("render")
    def render_command(
        input_path: Annotated[
            Path,
            typer.Option("--input", help="Path to artifact-bundle.json."),
        ],
        formats: Annotated[
            str,
            typer.Option(
                "--formats",
                help=f"Comma-separated formats: {OutputFormat.csv()}.",
            ),
        ],
        output_dir: Annotated[
            Path,
            typer.Option("--output", help="Directory for rendered outputs."),
        ],
    ) -> None:
        """Render deterministic views from a validated artifact bundle."""

        def render_artifacts() -> str:
            saved = rendering_service_factory().render(
                input_path,
                formats.split(","),
                output_dir,
            )
            return "\n".join(str(artifact.path) for artifact in saved)

        typer.echo(error_handler.execute(render_artifacts, debug=debug_enabled))

    @app.command("analyze")
    def analyze_command(
        input_reference: Annotated[
            str,
            typer.Option("--input", help="Local export path, page URL, or page ID."),
        ],
        output_dir: Annotated[
            Path,
            typer.Option(
                "--output",
                help="Directory for analysis outputs.",
                default_factory=lambda: resolved_default_output,
            ),
        ],
        formats: Annotated[
            str,
            typer.Option(
                "--formats",
                help=f"Comma-separated formats: {OutputFormat.csv()}.",
            ),
        ] = OutputFormat.csv(),
    ) -> None:
        """Run ingestion, extraction, modeling, and rendering end to end."""

        def run_analysis() -> str:
            summary = analysis_workflow_factory(input_reference).analyze(
                input_reference,
                output_dir,
                formats.split(","),
            )
            return "\n".join(
                [
                    f"Application: {summary.application_name}",
                    f"Components: {summary.component_count}",
                    f"Data flows: {summary.data_flow_count}",
                    f"Threats: {summary.threat_count}",
                    f"Missing information: {summary.missing_information_count}",
                    f"Output directory: {summary.output_directory}",
                ]
            )

        typer.echo(error_handler.execute(run_analysis, debug=debug_enabled))

    return app
