"""Tests for local artifact and system-model JSON loaders."""

from pathlib import Path

import pytest
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import AgentSchemaValidationError, ArtifactValidationError
from threatmodeler.infrastructure.local_artifact_bundle_loader import LocalArtifactBundleLoader
from threatmodeler.infrastructure.local_system_model_loader import LocalSystemModelLoader


class TestLocalArtifactBundleLoaderErrors:
    """Verify bundle loader failures are normalized."""

    def test_missing_bundle_raises_validation_error(self, tmp_path: Path) -> None:
        with pytest.raises(ArtifactValidationError) as captured:
            LocalArtifactBundleLoader().load(tmp_path / "missing.json")

        assert captured.value.error_code == "ARTIFACT_BUNDLE_LOAD_FAILED"

    def test_invalid_bundle_json_includes_validation_errors(
        self,
        tmp_path: Path,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        path = tmp_path / "artifact-bundle.json"
        path.write_text('{"artifact_id": ""}', encoding="utf-8")

        with pytest.raises(ArtifactValidationError) as captured:
            LocalArtifactBundleLoader().load(path)

        assert captured.value.error_code == "ARTIFACT_BUNDLE_LOAD_FAILED"
        context = captured.value.context
        assert context is not None
        assert "validation_errors" in context


class TestLocalSystemModelLoaderPositive:
    """Verify supported inputs and successful behavior."""

    def test_load_returns_validated_system_model(
        self,
        tmp_path: Path,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        path = tmp_path / "system-model.json"
        path.write_text(canonical_system_model.model_dump_json(), encoding="utf-8")

        loaded = LocalSystemModelLoader().load(path)

        assert loaded.application.name == canonical_system_model.application.name


class TestLocalSystemModelLoaderErrors:
    """Verify system-model loader failures are normalized."""

    def test_invalid_system_model_json_raises_schema_error(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "system-model.json"
        path.write_text('{"application": {}}', encoding="utf-8")

        with pytest.raises(AgentSchemaValidationError) as captured:
            LocalSystemModelLoader().load(path)

        assert captured.value.error_code == "SYSTEM_MODEL_LOAD_FAILED"
        context = captured.value.context
        assert context is not None
        assert "validation_errors" in context

    def test_missing_system_model_file_raises_schema_error(self, tmp_path: Path) -> None:
        with pytest.raises(AgentSchemaValidationError) as captured:
            LocalSystemModelLoader().load(tmp_path / "missing.json")

        assert captured.value.error_code == "SYSTEM_MODEL_LOAD_FAILED"
