"""File-oriented deterministic artifact rendering workflow."""

from pathlib import Path

from threatmodeler.contracts.artifacts import ArtifactBundle, ArtifactModel
from threatmodeler.contracts.integration import SavedArtifact
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.ports.artifact_bundle_loader import ArtifactBundleLoader
from threatmodeler.ports.artifact_repository import ArtifactRepository
from threatmodeler.ports.output_renderer_factory import OutputRendererFactory
from threatmodeler.shared.constants import ArtifactKind, OutputFormat


class RenderingService:
    """Render selected deterministic views from a validated artifact bundle.

    Bundle loading, renderer selection, and persistence are injected ports; the service
    only coordinates format selection and output placement.
    """

    def __init__(
        self,
        bundle_loader: ArtifactBundleLoader,
        renderer_factory: OutputRendererFactory,
        artifact_repository: ArtifactRepository,
    ) -> None:
        self._bundle_loader = bundle_loader
        self._renderer_factory = renderer_factory
        self._artifact_repository = artifact_repository

    def render(
        self,
        input_path: Path,
        formats: list[str],
        output_dir: Path,
    ) -> list[SavedArtifact]:
        """Render requested deterministic formats into format-specific folders.

        Args:
            input_path: Path to a validated artifact-bundle JSON document.
            formats: Requested format names such as ``json`` or ``mermaid``.
            output_dir: Root directory for format-specific rendered outputs.

        Returns:
            Metadata for every rendered file in deterministic format order.

        Raises:
            ArtifactRenderingError: If no format is supplied or a format is unsupported.

        Examples:
            Render a bundle into Mermaid and Markdown outputs::

                saved = service.render(
                    Path("artifact-bundle.json"),
                    ["mermaid", "markdown"],
                    Path("rendered"),
                )
        """
        bundle = self._bundle_loader.load(input_path)
        normalized_formats = self._normalize_formats(formats)
        saved: list[SavedArtifact] = []
        for format_name in normalized_formats:
            format_output_dir = output_dir / format_name
            for artifact_kind, artifact in self._artifacts_for_format(format_name, bundle):
                renderer = self._renderer_factory.create(format_name, artifact_kind)
                saved.append(
                    self._artifact_repository.save(
                        renderer.render(artifact),
                        format_output_dir,
                    )
                )
        return saved

    def _normalize_formats(self, formats: list[str]) -> list[str]:
        normalized: list[str] = []
        for format_name in formats:
            value = format_name.strip().lower()
            if not value:
                continue
            if value not in OutputFormat:
                raise ArtifactRenderingError(
                    "Unsupported output format",
                    error_code="OUTPUT_FORMAT_UNSUPPORTED",
                    retryable=False,
                    context={"format": format_name},
                )
            if value not in normalized:
                normalized.append(value)
        if not normalized:
            raise ArtifactRenderingError(
                "At least one output format is required",
                error_code="OUTPUT_FORMAT_REQUIRED",
                retryable=False,
            )
        return normalized

    def _artifacts_for_format(
        self,
        format_name: str,
        bundle: ArtifactBundle,
    ) -> list[tuple[str, ArtifactModel]]:
        if format_name == OutputFormat.JSON:
            return [(ArtifactKind.ARTIFACT_BUNDLE, bundle)]
        if format_name == OutputFormat.MERMAID:
            return [
                (ArtifactKind.DFD, bundle.data_flow_diagram),
                (ArtifactKind.ARCHITECTURE_GRAPH, bundle.architecture_graph),
                (ArtifactKind.ATTACK_TREE, bundle.attack_tree),
                (ArtifactKind.TRUST_BOUNDARIES, bundle.trust_boundary_map),
            ]
        if format_name == OutputFormat.MARKDOWN:
            return [(ArtifactKind.TECHNICAL_REPORT, bundle)]
        if format_name == OutputFormat.FLOW:
            return [(ArtifactKind.DFD, bundle.data_flow_diagram)]
        raise AssertionError("Format normalization allowed an unsupported format")
