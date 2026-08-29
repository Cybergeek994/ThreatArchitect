"""Tests for workflow result contracts."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from threatmodeler.contracts import ArtifactGenerationResult
from threatmodeler.contracts.integration import SavedArtifact

_VALID_SHA256 = "a" * 64


class TestWorkflowContractsNegative:
    """Verify invalid workflow contracts are rejected."""

    def test_generation_result_rejects_duplicate_paths(self, tmp_path: Path) -> None:
        artifact = SavedArtifact(
            path=tmp_path / "artifact-bundle.json",
            size_bytes=1,
            sha256=_VALID_SHA256,
        )
        duplicate = SavedArtifact(
            path=tmp_path / "artifact-bundle.json",
            size_bytes=2,
            sha256="b" * 64,
        )

        with pytest.raises(ValidationError, match="unique"):
            ArtifactGenerationResult(artifacts=(artifact, duplicate), bundle=artifact)

    def test_generation_result_requires_bundle_in_artifacts(self, tmp_path: Path) -> None:
        bundle = SavedArtifact(
            path=tmp_path / "artifact-bundle.json",
            size_bytes=1,
            sha256=_VALID_SHA256,
        )
        other = SavedArtifact(
            path=tmp_path / "other.json",
            size_bytes=1,
            sha256="c" * 64,
        )

        with pytest.raises(ValidationError, match="included in generated artifacts"):
            ArtifactGenerationResult(artifacts=(other,), bundle=bundle)
