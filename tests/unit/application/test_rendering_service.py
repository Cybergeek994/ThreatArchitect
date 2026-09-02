"""Tests for the rendering application service."""

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from threatmodeler.application.rendering_service import RenderingService
from threatmodeler.application.threat_modeling_service import ThreatModelingService
from threatmodeler.contracts.artifacts import ArtifactBundle
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import ArtifactRenderingError
from threatmodeler.infrastructure.local_artifact_bundle_loader import LocalArtifactBundleLoader
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository
from threatmodeler.ports.agent_provider import AgentProvider
from threatmodeler.ports.artifact_validator import ArtifactValidator
from threatmodeler.renderers.renderer_factory import RendererFactory


@pytest.fixture
def artifact_bundle(
    agent_provider: Mock,
    canonical_system_model: CanonicalSystemModel,
    threat_modeling_service_factory: Callable[
        [AgentProvider, ArtifactValidator | None], ThreatModelingService
    ],
) -> ArtifactBundle:
    """Generate a connected validated bundle for rendering-service tests."""
    return threat_modeling_service_factory(agent_provider, None).generate(canonical_system_model)


class TestRenderingServicePositive:
    """Verify supported inputs and successful behavior."""

    def test_render_deduplicates_and_normalizes_formats(
        self,
        tmp_path: Path,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        input_path = tmp_path / "artifact-bundle.json"
        output_dir = tmp_path / "rendered"
        input_path.write_text(artifact_bundle.model_dump_json(), encoding="utf-8")
        service = RenderingService(
            bundle_loader=LocalArtifactBundleLoader(),
            renderer_factory=RendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

        saved = service.render(input_path, [" JSON ", "json", "mermaid"], output_dir)

        assert len(saved) == 5
        assert (output_dir / "json" / "artifact-bundle.json").is_file()
        assert (output_dir / "mermaid" / "dfd.mmd").is_file()
        assert (output_dir / "mermaid" / "architecture-graph.mmd").is_file()


class TestRenderingServiceNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_render_rejects_unsupported_format(
        self,
        tmp_path: Path,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        input_path = tmp_path / "artifact-bundle.json"
        input_path.write_text(artifact_bundle.model_dump_json(), encoding="utf-8")
        service = RenderingService(
            bundle_loader=LocalArtifactBundleLoader(),
            renderer_factory=RendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

        with pytest.raises(ArtifactRenderingError) as captured:
            service.render(input_path, ["pdf"], tmp_path / "rendered")

        assert captured.value.error_code == "OUTPUT_FORMAT_UNSUPPORTED"


class TestRenderingServiceErrors:
    """Verify dependency and application failures remain controlled."""

    def test_render_requires_at_least_one_format(
        self,
        tmp_path: Path,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        input_path = tmp_path / "artifact-bundle.json"
        input_path.write_text(artifact_bundle.model_dump_json(), encoding="utf-8")
        service = RenderingService(
            bundle_loader=LocalArtifactBundleLoader(),
            renderer_factory=RendererFactory(),
            artifact_repository=LocalArtifactRepository(),
        )

        with pytest.raises(ArtifactRenderingError) as captured:
            service.render(input_path, ["", "   "], tmp_path / "rendered")

        assert captured.value.error_code == "OUTPUT_FORMAT_REQUIRED"

    def test_artifacts_for_format_assertion_is_unreachable_after_normalization(
        self,
        artifact_bundle: ArtifactBundle,
    ) -> None:
        service = RenderingService(
            bundle_loader=Mock(),
            renderer_factory=Mock(),
            artifact_repository=Mock(),
        )

        with pytest.raises(AssertionError):
            service._artifacts_for_format("pdf", artifact_bundle)
