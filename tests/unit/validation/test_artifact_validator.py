"""Tests for generated artifact revalidation."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError
from threatmodeler.contracts.artifacts import ComponentInventory
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
from threatmodeler.domain.inventory_generation import InventoryGenerationService
from threatmodeler.errors import ArtifactValidationError
from threatmodeler.validation.artifact_validator import PydanticArtifactValidator


class TestArtifactValidatorPositive:
    """Verify valid artifacts pass revalidation."""

    def test_validate_accepts_valid_artifact(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        inventory = InventoryGenerationService(
            ArtifactMetadataService()
        ).generate_component_inventory(canonical_system_model)

        PydanticArtifactValidator().validate(inventory)


class TestArtifactValidatorErrors:
    """Verify invalid artifacts are rejected."""

    def test_validate_raises_for_broken_serialized_payload(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        inventory = InventoryGenerationService(
            ArtifactMetadataService()
        ).generate_component_inventory(canonical_system_model)
        with pytest.raises(ValidationError) as validation_error:
            ComponentInventory.model_validate({"artifact_id": ""})

        with (
            patch.object(
                ComponentInventory,
                "model_validate",
                side_effect=validation_error.value,
            ),
            pytest.raises(ArtifactValidationError) as captured,
        ):
            PydanticArtifactValidator().validate(inventory)

        assert captured.value.error_code == "GENERATED_ARTIFACT_INVALID"
        context = captured.value.context
        assert context is not None
        assert context["artifact_id"] == "component-inventory"
        assert "validation_errors" in context
