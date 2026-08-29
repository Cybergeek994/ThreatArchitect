"""Schema field descriptions that guide tool-calling agents."""

from types import SimpleNamespace

from threatmodeler.contracts.artifacts.base import ArtifactItem
from threatmodeler.contracts.base import ExtractedItem
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class TestSchemaDescriptionsPositive:
    """Verify id and confidence guidance propagates into JSON Schema."""

    def test_extracted_item_id_has_kebab_case_guidance(self) -> None:
        schema = ExtractedItem.model_json_schema()
        desc = schema["properties"]["id"].get("description", "")
        assert "kebab-case" in desc
        assert "component1" in desc

    def test_extracted_item_confidence_has_scale_guidance(self) -> None:
        schema = ExtractedItem.model_json_schema()
        desc = schema["properties"]["confidence"].get("description", "")
        assert "1.0" in desc and "0.8" in desc

    def test_artifact_item_id_has_semantic_guidance(self) -> None:
        schema = ArtifactItem.model_json_schema()
        desc = schema["properties"]["id"].get("description", "")
        assert "kebab-case" in desc
        assert "sequential" in desc.lower() or "generic" in desc.lower()

    def test_artifact_item_confidence_has_scale_guidance(self) -> None:
        schema = ArtifactItem.model_json_schema()
        desc = schema["properties"]["confidence"].get("description", "")
        assert "evidence" in desc.lower()


class TestArtifactConfidenceInheritancePositive:
    """Verify artifact-level confidence is inherited from source items."""

    def test_compute_confidence_returns_minimum_of_items(self) -> None:
        metadata = ArtifactMetadataService()
        items = [
            SimpleNamespace(confidence=0.9),
            SimpleNamespace(confidence=0.6),
            SimpleNamespace(confidence=0.8),
        ]
        assert metadata.compute_confidence(items, when_empty=0.95) == 0.6

    def test_compute_confidence_uses_caller_source_when_empty(self) -> None:
        metadata = ArtifactMetadataService()
        assert metadata.compute_confidence([], when_empty=0.92) == 0.92

    def test_compute_confidence_uses_caller_source_when_items_lack_confidence(
        self,
    ) -> None:
        metadata = ArtifactMetadataService()
        items = [SimpleNamespace(name="no-confidence")]
        assert metadata.compute_confidence(items, when_empty=0.88) == 0.88

    def test_artifact_fields_requires_explicit_confidence(self) -> None:
        metadata = ArtifactMetadataService()
        fields = metadata.artifact_fields(
            "artifact-id",
            "Title",
            "Description",
            ["assumption"],
            confidence=0.65,
        )
        assert fields.model_dump()["confidence"] == 0.65
