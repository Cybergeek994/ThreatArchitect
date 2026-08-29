"""Tests for local artifact persistence."""

from pathlib import Path
from unittest.mock import patch

import pytest
from threatmodeler.contracts.integration import RenderedArtifact
from threatmodeler.errors import ArtifactStorageError
from threatmodeler.infrastructure.local_artifact_repository import LocalArtifactRepository


class TestLocalArtifactRepositoryPositive:
    """Verify supported inputs and successful behavior."""

    def test_save_writes_artifact_atomically(self, tmp_path: Path) -> None:
        artifact = RenderedArtifact(
            name="parsed-document",
            content='{"title":"Sample"}',
            media_type="application/json",
            file_extension=".json",
        )

        saved = LocalArtifactRepository().save(artifact, tmp_path)

        assert saved.path == (tmp_path / "parsed-document.json").resolve()
        assert saved.path.read_text(encoding="utf-8") == artifact.content


class TestLocalArtifactRepositoryErrors:
    """Verify dependency and application failures remain controlled."""

    def test_save_rejects_paths_that_escape_output_directory(self, tmp_path: Path) -> None:
        artifact = RenderedArtifact(
            name="../escape",
            content="unsafe",
            media_type="text/plain",
            file_extension=".txt",
        )

        with pytest.raises(ArtifactStorageError) as captured:
            LocalArtifactRepository().save(artifact, tmp_path)

        assert captured.value.error_code == "ARTIFACT_LOCAL_SAVE_FAILED"

    def test_save_cleans_up_temporary_file_on_failure(self, tmp_path: Path) -> None:
        artifact = RenderedArtifact(
            name="parsed-document",
            content="content",
            media_type="application/json",
            file_extension=".json",
        )
        repository = LocalArtifactRepository()

        with (
            patch(
                "threatmodeler.infrastructure.local_artifact_repository.NamedTemporaryFile",
                side_effect=OSError("disk full"),
            ),
            pytest.raises(ArtifactStorageError),
        ):
            repository.save(artifact, tmp_path)

        assert list(tmp_path.glob("*.tmp")) == []

    def test_save_cleans_up_temporary_file_when_replace_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        artifact = RenderedArtifact(
            name="parsed-document",
            content="content",
            media_type="application/json",
            file_extension=".json",
        )
        repository = LocalArtifactRepository()

        def failing_replace(self: Path, target: Path) -> Path:
            raise OSError("replace failed")

        monkeypatch.setattr(Path, "replace", failing_replace)

        with pytest.raises(ArtifactStorageError):
            repository.save(artifact, tmp_path)

        assert list(tmp_path.glob("*.tmp")) == []
