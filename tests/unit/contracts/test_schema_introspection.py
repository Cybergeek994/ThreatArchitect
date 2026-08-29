"""Tests for schema reference-field introspection."""

from pydantic import BaseModel
from threatmodeler.contracts.schema_introspection import discover_reference_fields


class TestDiscoverReferenceFieldsBranches:
    """Verify reference discovery across union and nested model shapes."""

    def test_schema_introspection_union_nested_models(self) -> None:
        class Leaf(BaseModel):
            ref_id: str

        class Root(BaseModel):
            child: Leaf | None = None

        fields = {item.field_name for item in discover_reference_fields(Root)}
        assert "ref_id" in fields

    def test_schema_introspection_generic_union_branch(self) -> None:
        class Leaf(BaseModel):
            ref_id: str

        class Root(BaseModel):
            items: list[Leaf] | None = None

        fields = {item.field_name for item in discover_reference_fields(Root)}
        assert "ref_id" in fields

    def test_schema_introspection_skips_duplicate_reference_fields(self) -> None:
        def make_leaf_model() -> type[BaseModel]:
            class Leaf(BaseModel):
                ref_id: str

            return Leaf

        LeafA = make_leaf_model()
        LeafB = make_leaf_model()

        class Root(BaseModel):
            first: LeafA
            second: LeafB

        fields = discover_reference_fields(Root)
        ref_ids = [item for item in fields if item.field_name == "ref_id"]
        assert len(ref_ids) == 1