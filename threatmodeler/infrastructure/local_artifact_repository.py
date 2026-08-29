"""Local filesystem artifact repository."""

import hashlib
import os
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile

from threatmodeler.contracts.integration import RenderedArtifact, SavedArtifact
from threatmodeler.errors.application import ArtifactStorageError


class LocalArtifactRepository:
    """Persist rendered artifacts atomically beneath an explicit output directory."""

    def save(self, artifact: RenderedArtifact, output_dir: Path) -> SavedArtifact:
        """Write an artifact through a same-directory temporary file and atomic replace.

        Args:
            artifact: Rendered content and canonical output filename metadata.
            output_dir: Directory beneath which the artifact must remain.

        Returns:
            Resolved path, encoded size, and SHA-256 digest of the saved artifact.

        Raises:
            ArtifactStorageError: If validation, encoding, or filesystem operations fail.
        """
        temporary_path: Path | None = None
        try:
            resolved_output_dir = output_dir.expanduser().resolve()
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            destination = (
                resolved_output_dir / f"{artifact.name}{artifact.file_extension}"
            ).resolve()
            if not destination.is_relative_to(resolved_output_dir):
                raise ValueError("Artifact path escapes the output directory")
            encoded_content = artifact.content.encode("utf-8")
            with NamedTemporaryFile(
                mode="wb",
                dir=resolved_output_dir,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                temporary_file.write(encoded_content)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            temporary_path.replace(destination)
            temporary_path = None
            return SavedArtifact(
                path=destination,
                size_bytes=len(encoded_content),
                sha256=hashlib.sha256(encoded_content).hexdigest(),
            )
        except (OSError, UnicodeError, ValueError) as error:
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)
            raise ArtifactStorageError(
                "Unable to save the rendered artifact",
                error_code="ARTIFACT_LOCAL_SAVE_FAILED",
                retryable=False,
                context={"output_dir": str(output_dir), "artifact_name": artifact.name},
            ) from error
