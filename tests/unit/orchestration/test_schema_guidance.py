"""Tests for schema-driven prompt constraint generation."""

from pydantic import BaseModel
from threatmodeler.contracts.schema_introspection import discover_reference_fields
from threatmodeler.contracts.system_model import CanonicalSystemModel, DataFlow
from threatmodeler.orchestration.prompts.artifact_builders import _merge_constraints
from threatmodeler.orchestration.prompts.schema_guidance import (
    PromptConstraint,
    SchemaDrivenConstraintCatalog,
    _dedupe_by_key,
    build_finish_order_constraints,
    build_coverage_constraints,
    build_reference_integrity_constraints,
    discover_list_fields,
    reference_fields_for_models,
)


class TestDiscoverListFieldsPositive:
    """Verify top-level list field discovery."""

    def test_discovers_canonical_list_fields(self) -> None:
        fields = discover_list_fields(CanonicalSystemModel)

        assert "actors" in fields
        assert "components" in fields
        assert "data_flows" in fields
        assert "diagram_topology" not in fields


class TestDiscoverReferenceFieldsPositive:
    """Verify *_id / *_ids discovery across nested models."""

    def test_discovers_data_flow_and_entry_point_refs(self) -> None:
        fields = {descriptor.field_name for descriptor in discover_reference_fields(CanonicalSystemModel)}

        assert "source_component_id" in fields
        assert "destination_component_id" in fields
        assert "actor_ids" in fields
        assert "component_id" in fields
        assert "actor_id" in fields
        assert "id" not in fields

    def test_reference_fields_for_models_includes_nested(self) -> None:
        fields = reference_fields_for_models(CanonicalSystemModel, DataFlow)

        assert "source_component_id" in fields
        assert "actor_ids" in fields


class TestSchemaDrivenConstraintCatalogPositive:
    """Verify catalogs emit schema-neutral constraints."""

    def test_for_extraction_includes_source_complete(self) -> None:
        catalog = SchemaDrivenConstraintCatalog.for_extraction(CanonicalSystemModel)
        texts = " ".join(catalog.as_texts())

        assert "Source-complete" in texts
        assert "`actors`" in texts
        assert "actors table" not in texts

    def test_for_tool_calling_includes_incremental_guidance(self) -> None:
        catalog = SchemaDrivenConstraintCatalog.for_tool_calling(CanonicalSystemModel)
        texts = " ".join(catalog.as_texts())

        assert "add_*" in texts
        assert "Source-complete" in texts
        assert "Emit all actors" not in texts

    def test_for_generation_includes_traceability(self) -> None:
        catalog = SchemaDrivenConstraintCatalog.for_generation(CanonicalSystemModel)
        texts = " ".join(catalog.as_texts())

        assert "traceability" in texts.lower() or "*_id" in texts


class TestSchemaGuidanceModels:
    """Nested models kept off the test-module body."""

    class ScalarOnly(BaseModel):
        title: str


class TestSchemaGuidanceHelperBranches:
    """Cover schema guidance helpers and introspection branches."""

    def test_reference_integrity_constraints_without_reference_fields(self) -> None:
        constraints = build_reference_integrity_constraints(TestSchemaGuidanceModels.ScalarOnly)
        assert len(constraints) == 1
        assert constraints[0].key == "id_uniqueness"

    def test_finish_order_constraints_without_list_fields(self) -> None:
        assert build_finish_order_constraints(TestSchemaGuidanceModels.ScalarOnly) == ()

    def test_dedupe_by_key_skips_duplicate_keys(self) -> None:
        first = PromptConstraint(key="dup", text="first")
        second = PromptConstraint(key="dup", text="second")
        deduped = _dedupe_by_key((first, second))
        assert deduped == (first,)

    def test_nested_model_reference_discovery_via_optional_union(self) -> None:
        class NestedRef(BaseModel):
            child_id: str

        class ParentWithOptionalNested(BaseModel):
            child: NestedRef | None = None

        fields = {descriptor.field_name for descriptor in discover_reference_fields(ParentWithOptionalNested)}
        assert "child_id" in fields

    def test_merge_constraints_skips_duplicates(self) -> None:
        merged = _merge_constraints(("a", "b"), ("b", "c"))
        assert merged == ("a", "b", "c")

    def test_business_repair_catalog_deduplicates_shared_keys(self) -> None:
        catalog = SchemaDrivenConstraintCatalog.for_business_repair(CanonicalSystemModel)
        keys = [item.key for item in catalog.constraints]
        assert len(keys) == len(set(keys))

    def test_build_coverage_constraints_lists_input_review_bullets(self) -> None:
        constraints = build_coverage_constraints()
        keys = {item.key for item in constraints}
        assert "coverage_entry_points" in keys
        assert "coverage_affected_components" in keys
        texts = " ".join(item.text for item in constraints)
        assert "system_model.entry_points" in texts
        assert "partially_mitigated" in texts
