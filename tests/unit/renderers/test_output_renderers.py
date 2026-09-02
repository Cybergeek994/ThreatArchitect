"""Tests for deterministic JSON, Mermaid, Markdown, and flow renderers."""

import json
from collections.abc import Callable
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.cli.app import create_app
from threatmodeler.cli.error_handler import CliErrorHandler
from threatmodeler.contracts import FlowDiagramGraph
from threatmodeler.contracts.artifacts import ArtifactBundle, TrustBoundaryMap
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.infrastructure.local_artifact_bundle_loader import LocalArtifactBundleLoader
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.logging_config.structured import StandardLoggerFactory
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.renderers.flow_diagram_renderer import FlowDiagramRenderer
from threatmodeler.renderers.json_artifact_renderer import JsonArtifactRenderer
from threatmodeler.renderers.markdown_report_renderer import MarkdownReportRenderer
from threatmodeler.renderers.mermaid_architecture_graph_renderer import (
    MermaidArchitectureGraphRenderer,
)
from threatmodeler.renderers.mermaid_attack_tree_renderer import (
    MermaidAttackTreeRenderer,
)
from threatmodeler.renderers.mermaid_dfd_renderer import MermaidDfdRenderer
from threatmodeler.renderers.mermaid_trust_boundary_renderer import (
    MermaidTrustBoundaryRenderer,
)
from threatmodeler.renderers.renderer_factory import RendererFactory
from threatmodeler.shared.constants import LogLevel
from typer.testing import CliRunner


@pytest.fixture
def artifact_bundle(
    agent_provider: Mock,
    canonical_system_model: CanonicalSystemModel,
    threat_modeling_service_factory: Callable[
        [AgentProvider, ArtifactValidator | None], ThreatModelingService
    ],
) -> ArtifactBundle:
    """Generate a connected validated bundle for renderer tests."""
    return threat_modeling_service_factory(agent_provider, None).generate(canonical_system_model)


@pytest.fixture
def rendering_service_factory() -> Callable[[], RenderingService]:
    """Return a factory for the local deterministic rendering workflow."""

    def create() -> RenderingService:
        return RenderingService(
            bundle_loader=LocalArtifactBundleLoader(),
            renderer_factory=RendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

    return create


class TestOutputRenderersPositive:
    """Verify supported inputs and successful behavior."""

    def test_json_renderer_outputs_valid_deterministic_json(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        bundle = artifact_bundle
        renderer = JsonArtifactRenderer("artifact-bundle")

        first = renderer.render(bundle)
        second = renderer.render(bundle)

        assert first.content == second.content
        assert first.file_extension == ".json"
        payload = json.loads(first.content)
        assert payload["artifact_id"] == "artifact-bundle"
        assert ArtifactBundle.model_validate_json(first.content) == bundle

    def test_mermaid_dfd_renderer_renders_nodes_and_edges(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        dfd = artifact_bundle.data_flow_diagram
        renderer = MermaidDfdRenderer()

        rendered = renderer.render(dfd)

        assert rendered.content.startswith("flowchart LR\n")
        assert "Payments API" in rendered.content
        assert "Payment Records" in rendered.content
        assert "TLS/PostgreSQL" in rendered.content
        assert "==>" in rendered.content or "-->" in rendered.content
        assert renderer.render(dfd).content == rendered.content

    def test_mermaid_architecture_graph_renderer_renders_nodes_and_edges(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        graph = artifact_bundle.architecture_graph
        rendered = MermaidArchitectureGraphRenderer().render(graph)

        assert rendered.content.startswith("flowchart TD\n")
        assert "(entry_surface)" in rendered.content or "(api)" in rendered.content
        assert "-->" in rendered.content
        assert rendered.file_extension == ".mmd"

    def test_mermaid_attack_tree_renderer_renders_traceable_tree(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        attack_tree = artifact_bundle.attack_tree

        rendered = MermaidAttackTreeRenderer().render(attack_tree)

        assert rendered.content.startswith("flowchart TD\n")
        assert "Realize" in rendered.content
        assert "[leaf]" in rendered.content
        assert rendered.file_extension == ".mmd"

    def test_mermaid_trust_boundary_renderer_renders_subgraphs(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        trust_boundary_map = artifact_bundle.trust_boundary_map

        rendered = MermaidTrustBoundaryRenderer().render(trust_boundary_map)

        assert rendered.content.startswith("flowchart TB\n")
        assert "subgraph" in rendered.content
        assert "Production Boundary" in rendered.content
        assert "component_api" in rendered.content
        assert "-.->" in rendered.content or "-->" in rendered.content

    def test_markdown_report_renderer_renders_enriched_bundle(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        rendered = MarkdownReportRenderer().render(artifact_bundle)

        assert rendered.content.startswith("# Technical Threat Model Report\n")
        assert "## Scope" in rendered.content
        assert "## Methodology" in rendered.content
        assert "## STRIDE Threat Findings" in rendered.content
        assert "## Qualitative Risk Findings" in rendered.content
        assert "## Architecture Scope" in rendered.content
        assert "## System Architecture Details" in rendered.content
        assert "### Components" in rendered.content
        assert "### Entry Points" in rendered.content
        assert "### Assets" in rendered.content
        assert "## Detailed Threats" in rendered.content
        assert "## Risk Register Details" in rendered.content
        assert "## Mitigations" in rendered.content
        assert "## Security Requirements" in rendered.content
        assert "## Attack Scenarios" in rendered.content
        assert "### Attack Tree Summary" in rendered.content
        assert "### Abuse Cases" in rendered.content
        assert "## Control Mappings" in rendered.content
        assert "## Completeness and Gaps" in rendered.content
        assert "### Verify Phase Completeness" in rendered.content
        assert "### Missing Information" in rendered.content
        assert "### Assumptions Register" in rendered.content
        assert "## Conclusion" in rendered.content
        assert rendered.file_extension == ".md"
        assert rendered.content.index("## Detailed Threats") < rendered.content.index(
            "## Conclusion"
        )

    def test_markdown_renderer_accepts_standalone_technical_report(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        report = artifact_bundle.technical_report

        rendered = MarkdownReportRenderer().render(report)

        assert rendered.content.startswith("# Technical Threat Model Report\n")
        assert "## Scope" in rendered.content
        assert "## Conclusion" in rendered.content
        assert "## System Architecture Details" not in rendered.content
        assert "## Detailed Threats" not in rendered.content

    def test_markdown_renderer_includes_assumptions_and_referenced_artifacts(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        report = artifact_bundle.technical_report.model_copy(
            update={
                "assumptions": ["Production traffic only."],
                "sections": [
                    section.model_copy(
                        update={"referenced_artifact_ids": ["stride-threat-register"]}
                    )
                    for section in artifact_bundle.technical_report.sections[:1]
                ]
                + artifact_bundle.technical_report.sections[1:],
            }
        )

        rendered = MarkdownReportRenderer().render(report)

        assert "## Assumptions" in rendered.content
        assert "Production traffic only." in rendered.content
        assert "stride-threat-register" in rendered.content

    def test_markdown_renderer_omits_assumptions_section_when_empty(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        report = artifact_bundle.technical_report.model_copy(update={"assumptions": []})

        rendered = MarkdownReportRenderer().render(report)

        assert "## Assumptions" not in rendered.content

    def test_markdown_enriched_bundle_emits_freeform_assumptions_when_register_empty(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        empty_register = artifact_bundle.assumptions_register.model_copy(update={"entries": []})
        bundle = artifact_bundle.model_copy(
            update={
                "assumptions_register": empty_register,
                "technical_report": artifact_bundle.technical_report.model_copy(
                    update={"assumptions": ["Fallback assumption text."]}
                ),
            }
        )

        rendered = MarkdownReportRenderer().render(bundle)

        assert "## Assumptions" in rendered.content
        assert "Fallback assumption text." in rendered.content

    def test_markdown_enriched_skips_narrative_verify_sections(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        llm_section = artifact_bundle.technical_report.sections[0].model_copy(
            update={
                "artifact_id": "technical-report-verify-llm",
                "title": "Verify Phase and Completeness Check",
                "content": "Agent-authored verify narrative.",
            }
        )
        bundle = artifact_bundle.model_copy(
            update={
                "technical_report": artifact_bundle.technical_report.model_copy(
                    update={
                        "sections": [
                            llm_section,
                            *artifact_bundle.technical_report.sections[1:],
                        ]
                    }
                )
            }
        )

        rendered = MarkdownReportRenderer().render(bundle)

        assert "## Verify Phase and Completeness Check" not in rendered.content
        assert "### Verify Phase Completeness" in rendered.content

    def test_flow_diagram_renderer_outputs_valid_graph_json(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        dfd = artifact_bundle.data_flow_diagram

        rendered = FlowDiagramRenderer().render(dfd)
        graph = FlowDiagramGraph.model_validate_json(rendered.content)

        assert [node.id for node in graph.nodes] == ["component-api", "store-payments"]
        assert graph.edges[0].source == "component-api"
        assert graph.edges[0].target == "store-payments"
        assert graph.edges[0].encrypted_in_transit is True

    def test_renderer_factory_selects_each_strategy(self) -> None:
        factory = RendererFactory()

        assert isinstance(factory.create("json", "artifact-bundle"), JsonArtifactRenderer)
        assert isinstance(factory.create("mermaid", "dfd"), MermaidDfdRenderer)
        assert isinstance(
            factory.create("mermaid", "architecture-graph"),
            MermaidArchitectureGraphRenderer,
        )
        assert isinstance(factory.create("mermaid", "attack-tree"), MermaidAttackTreeRenderer)
        assert isinstance(
            factory.create("mermaid", "trust-boundaries"),
            MermaidTrustBoundaryRenderer,
        )
        assert isinstance(factory.create("markdown", "technical-report"), MarkdownReportRenderer)
        assert isinstance(factory.create("flow", "dfd"), FlowDiagramRenderer)

    def test_render_cli_writes_expected_format_folders(
        self,
        tmp_path: Path,
        artifact_bundle: ArtifactBundle,
        rendering_service_factory: Callable[[], RenderingService],
    ) -> None:
        input_path = tmp_path / "artifact-bundle.json"
        output_dir = tmp_path / "rendered"
        input_path.write_text(artifact_bundle.model_dump_json(indent=2))
        logger = StandardLoggerFactory(LogLevel.INFO, StringIO()).create("test.render")

        unused_ingestion_factory = Mock(
            side_effect=AssertionError("Ingestion should not run during rendering")
        )
        unused_extraction_factory = Mock(
            side_effect=AssertionError("Extraction should not run during rendering")
        )
        unused_artifact_factory = Mock(
            side_effect=AssertionError("Artifact generation should not run during rendering")
        )
        unused_analysis_factory = Mock(
            side_effect=AssertionError("Analysis should not run during rendering")
        )

        app = create_app(
            unused_ingestion_factory,
            unused_extraction_factory,
            unused_artifact_factory,
            rendering_service_factory,
            unused_analysis_factory,
            CliErrorHandler(logger),
        )

        result = CliRunner().invoke(
            app,
            [
                "render",
                "--input",
                str(input_path),
                "--formats",
                "json,mermaid,markdown,flow",
                "--output",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert (output_dir / "json" / "artifact-bundle.json").is_file()
        assert (output_dir / "mermaid" / "dfd.mmd").is_file()
        assert (output_dir / "mermaid" / "architecture-graph.mmd").is_file()
        assert (output_dir / "mermaid" / "attack-tree.mmd").is_file()
        assert (output_dir / "mermaid" / "trust-boundaries.mmd").is_file()
        assert (output_dir / "markdown" / "technical-report.md").is_file()
        assert (output_dir / "flow" / "dfd.json").is_file()
        unused_ingestion_factory.assert_not_called()
        unused_extraction_factory.assert_not_called()
        unused_artifact_factory.assert_not_called()
        unused_analysis_factory.assert_not_called()
        assert "flow" in result.stdout


class TestOutputRenderersNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_renderer_rejects_the_wrong_validated_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        bundle = artifact_bundle

        with pytest.raises(ArtifactRenderingError) as captured:
            MermaidDfdRenderer().render(bundle.attack_tree)

        assert captured.value.error_code == "MERMAID_DFD_TYPE_INVALID"

    def test_json_renderer_wraps_serialization_failures(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        renderer = JsonArtifactRenderer("artifact-bundle")
        broken = Mock()
        broken.model_dump_json.side_effect = RuntimeError("serialize failed")

        with pytest.raises(ArtifactRenderingError) as captured:
            renderer.render(broken)

        assert captured.value.error_code == "ARTIFACT_JSON_RENDER_FAILED"

    def test_flow_diagram_renderer_rejects_wrong_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            FlowDiagramRenderer().render(artifact_bundle.attack_tree)

        assert captured.value.error_code == "FLOW_DIAGRAM_TYPE_INVALID"

    def test_markdown_renderer_rejects_wrong_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            MarkdownReportRenderer().render(artifact_bundle.data_flow_diagram)

        assert captured.value.error_code == "MARKDOWN_REPORT_TYPE_INVALID"

    def test_mermaid_attack_tree_renderer_rejects_wrong_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            MermaidAttackTreeRenderer().render(artifact_bundle.data_flow_diagram)

        assert captured.value.error_code == "MERMAID_ATTACK_TREE_TYPE_INVALID"

    def test_mermaid_architecture_graph_renderer_rejects_wrong_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            MermaidArchitectureGraphRenderer().render(artifact_bundle.data_flow_diagram)

        assert captured.value.error_code == "MERMAID_ARCHITECTURE_GRAPH_TYPE_INVALID"

    def test_mermaid_trust_boundary_renderer_rejects_wrong_artifact_type(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            MermaidTrustBoundaryRenderer().render(artifact_bundle.data_flow_diagram)

        assert captured.value.error_code == "MERMAID_TRUST_BOUNDARY_TYPE_INVALID"

    def test_renderer_factory_rejects_unknown_combination(self) -> None:
        with pytest.raises(ArtifactRenderingError) as captured:
            RendererFactory().create("pdf", "artifact-bundle")

        assert captured.value.error_code == "RENDERER_NOT_SUPPORTED"

    def test_mermaid_renderer_includes_unassigned_components(self) -> None:
        trust_map = TrustBoundaryMap.model_construct(
            trust_boundaries=[],
            crossing_flows=[],
            unassigned_component_ids=["orphan-component"],
        )
        rendered = MermaidTrustBoundaryRenderer().render(trust_map)
        assert "orphan-component" in rendered.content


class TestMermaidRendererOwaspFeatures:
    """Verify OWASP-aligned Mermaid rendering features."""

    def test_dfd_renderer_uses_thick_arrow_for_encrypted_flows(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        dfd = artifact_bundle.data_flow_diagram
        renderer = MermaidDfdRenderer()

        rendered = renderer.render(dfd)

        assert "==>" in rendered.content

    def test_dfd_renderer_uses_dotted_arrow_for_boundary_crossing(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import DataFlowDiagramModel
        from threatmodeler.contracts.system_model import (
            Component,
            ComponentType,
            DataFlow,
        )

        component = Component.model_construct(
            id="comp-1",
            name="Test Component",
            component_type=ComponentType.API,
        )
        flow = DataFlow.model_construct(
            id="flow-1",
            name="Test Flow",
            source_component_id="comp-1",
            destination_component_id="comp-1",
            protocol="HTTP",
            encrypted_in_transit=False,
            trust_boundary_crossed=True,
        )
        dfd = DataFlowDiagramModel.model_construct(
            components=[component],
            data_stores=[],
            data_flows=[flow],
        )

        rendered = MermaidDfdRenderer().render(dfd)

        assert "-.->" in rendered.content
        assert "⚠" in rendered.content

    def test_dfd_renderer_uses_regular_arrow_for_unencrypted_same_boundary(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import DataFlowDiagramModel
        from threatmodeler.contracts.system_model import (
            Component,
            ComponentType,
            DataFlow,
        )

        component = Component.model_construct(
            id="comp-1",
            name="Test Component",
            component_type=ComponentType.API,
        )
        flow = DataFlow.model_construct(
            id="flow-1",
            name="Test Flow",
            source_component_id="comp-1",
            destination_component_id="comp-1",
            protocol="HTTP",
            encrypted_in_transit=False,
            trust_boundary_crossed=False,
        )
        dfd = DataFlowDiagramModel.model_construct(
            components=[component],
            data_stores=[],
            data_flows=[flow],
        )

        rendered = MermaidDfdRenderer().render(dfd)

        assert "-->" in rendered.content
        assert "==>" not in rendered.content
        assert "-.->" not in rendered.content

    def test_attack_tree_renders_or_operator_edges(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import AttackTree, AttackTreeNode

        child = AttackTreeNode.model_construct(
            id="child-1",
            name="Child Step",
            operator="leaf",
            node_type="attack_step",
            children=[],
        )
        root = AttackTreeNode.model_construct(
            id="root-1",
            name="Root Goal",
            operator="or",
            node_type="goal",
            children=[child],
        )
        tree = AttackTree.model_construct(root_nodes=[root])

        rendered = MermaidAttackTreeRenderer().render(tree)

        assert "OR" in rendered.content

    def test_attack_tree_renders_leaf_nodes_without_edge_labels(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import AttackTree, AttackTreeNode

        leaf = AttackTreeNode.model_construct(
            id="leaf-1",
            name="Leaf Step",
            operator="leaf",
            node_type="attack_step",
            children=[],
        )
        parent = AttackTreeNode.model_construct(
            id="parent-1",
            name="Parent",
            operator="leaf",
            node_type="goal",
            children=[leaf],
        )
        tree = AttackTree.model_construct(root_nodes=[parent])

        rendered = MermaidAttackTreeRenderer().render(tree)

        assert "parent_1 --> " in rendered.content.replace("node_", "")

    def test_attack_tree_renders_difficulty_in_label(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import AttackTree, AttackTreeNode

        node = AttackTreeNode.model_construct(
            id="node-1",
            name="Difficult Attack",
            operator="leaf",
            node_type="vulnerability",
            difficulty="high",
            children=[],
        )
        tree = AttackTree.model_construct(root_nodes=[node])

        rendered = MermaidAttackTreeRenderer().render(tree)

        assert "(high)" in rendered.content

    def test_trust_boundary_renders_unknown_type_without_prefix(
        self,
    ) -> None:
        from threatmodeler.contracts.artifacts import TrustBoundaryMap
        from threatmodeler.contracts.system_model import TrustBoundary, TrustBoundaryType

        boundary = TrustBoundary.model_construct(
            id="bound-1",
            name="Unknown Boundary",
            boundary_type=TrustBoundaryType.UNKNOWN,
            component_ids=["comp-1"],
        )
        trust_map = TrustBoundaryMap.model_construct(
            trust_boundaries=[boundary],
            crossing_flows=[],
            unassigned_component_ids=[],
        )

        rendered = MermaidTrustBoundaryRenderer().render(trust_map)

        assert "Unknown Boundary" in rendered.content
        assert "🌐" not in rendered.content
        assert "🔒" not in rendered.content
