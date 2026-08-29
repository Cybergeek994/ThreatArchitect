"""Registry of deterministic renderer strategies by format and artifact kind."""

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from threatmodeler.ports.artifact_renderer import ArtifactRenderer
from threatmodeler.renderers.flow_diagram_renderer import FlowDiagramRenderer
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer
from threatmodeler.renderers.markdown_report_renderer import MarkdownReportRenderer
from threatmodeler.renderers.mermaid_attack_tree_renderer import MermaidAttackTreeRenderer
from threatmodeler.renderers.mermaid_dfd_renderer import MermaidDfdRenderer
from threatmodeler.renderers.mermaid_trust_boundary_renderer import MermaidTrustBoundaryRenderer
from threatmodeler.shared.constants import ArtifactKind, OutputFormat


class RendererRegistryEntry(BaseModel):
    """One supported output-format and artifact-kind renderer pairing."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    output_format: OutputFormat
    artifact_kind: ArtifactKind
    factory: Callable[[], ArtifactRenderer]


DEFAULT_RENDERER_ENTRIES: tuple[RendererRegistryEntry, ...] = (
    RendererRegistryEntry(
        output_format=OutputFormat.JSON,
        artifact_kind=ArtifactKind.ARTIFACT_BUNDLE,
        factory=lambda: JsonArtifactRenderer(ArtifactKind.ARTIFACT_BUNDLE),
    ),
    RendererRegistryEntry(
        output_format=OutputFormat.MERMAID,
        artifact_kind=ArtifactKind.DFD,
        factory=MermaidDfdRenderer,
    ),
    RendererRegistryEntry(
        output_format=OutputFormat.MERMAID,
        artifact_kind=ArtifactKind.ATTACK_TREE,
        factory=MermaidAttackTreeRenderer,
    ),
    RendererRegistryEntry(
        output_format=OutputFormat.MERMAID,
        artifact_kind=ArtifactKind.TRUST_BOUNDARIES,
        factory=MermaidTrustBoundaryRenderer,
    ),
    RendererRegistryEntry(
        output_format=OutputFormat.MARKDOWN,
        artifact_kind=ArtifactKind.TECHNICAL_REPORT,
        factory=MarkdownReportRenderer,
    ),
    RendererRegistryEntry(
        output_format=OutputFormat.FLOW,
        artifact_kind=ArtifactKind.DFD,
        factory=FlowDiagramRenderer,
    ),
)


def resolve_renderer_entry(
    format_name: str,
    artifact_kind: str,
    entries: tuple[RendererRegistryEntry, ...] = DEFAULT_RENDERER_ENTRIES,
) -> RendererRegistryEntry | None:
    """Return the registry entry matching normalized format and artifact kind."""
    normalized_format = format_name.strip().lower()
    normalized_kind = artifact_kind.strip().lower()
    for entry in entries:
        if entry.output_format == normalized_format and entry.artifact_kind == normalized_kind:
            return entry
    return None
