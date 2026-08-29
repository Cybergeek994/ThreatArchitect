"""Schema-neutral structural completeness checks for extraction fixtures."""

from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.orchestration.prompts.schema_guidance import (
    discover_list_fields,
    discover_reference_fields,
)
from threatmodeler.validation.system_model_validator import (
    CanonicalSystemModelValidator,
    production_system_model_rules,
)


class TestExtractionCompletenessPositive:
    """Verify fixture models are structurally complete and referentially sound."""

    def _entity_list_fields(self) -> tuple[str, ...]:
        names: list[str] = []
        for field_name in discover_list_fields(CanonicalSystemModel):
            items = getattr(
                CanonicalSystemModel.model_fields[field_name].annotation,
                "__args__",
                (),
            )
            if not items:
                continue
            item_type = items[0]
            if hasattr(item_type, "model_fields") and "id" in getattr(
                item_type, "model_fields", {}
            ):
                names.append(field_name)
        return tuple(names)

    def _collect_model_ids(self, model: CanonicalSystemModel) -> set[str]:
        ids = {model.application.id, model.deployment.id}
        for field_name in discover_list_fields(CanonicalSystemModel):
            for item in getattr(model, field_name):
                item_id = getattr(item, "id", None)
                if isinstance(item_id, str) and item_id:
                    ids.add(item_id)
        return ids

    def _collect_reference_values(
        self,
        model: CanonicalSystemModel,
    ) -> list[tuple[str, str]]:
        refs: list[tuple[str, str]] = []
        descriptors = discover_reference_fields(CanonicalSystemModel)
        field_names = {descriptor.field_name for descriptor in descriptors}
        for list_field in discover_list_fields(CanonicalSystemModel):
            for item in getattr(model, list_field):
                for field_name in field_names:
                    raw = getattr(item, field_name, None)
                    if isinstance(raw, str) and raw:
                        refs.append((field_name, raw))
                    elif isinstance(raw, list):
                        for value in raw:
                            if isinstance(value, str) and value:
                                refs.append((field_name, value))
        return refs

    def test_list_fields_are_non_empty_for_fixture(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        for field_name in self._entity_list_fields():
            assert len(getattr(canonical_system_model, field_name)) >= 1, field_name

    def test_ids_are_unique_across_list_fields(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        ids: list[str] = [
            canonical_system_model.application.id,
            canonical_system_model.deployment.id,
        ]
        for field_name in self._entity_list_fields():
            for item in getattr(canonical_system_model, field_name):
                ids.append(item.id)
        assert len(ids) == len(set(ids))

    def test_reference_fields_resolve_to_known_ids(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        known = self._collect_model_ids(canonical_system_model)
        for field_name, value in self._collect_reference_values(canonical_system_model):
            assert value in known, f"{field_name}={value}"

    def test_production_rules_accept_fixture(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        validated = CanonicalSystemModelValidator(production_system_model_rules()).validate(
            canonical_system_model
        )
        assert validated is canonical_system_model
