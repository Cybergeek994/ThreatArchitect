"""Tests for artifact builder session mutation and validation branches."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import pytest
from pydantic import BaseModel, Field, JsonValue
from threatmodeler.contracts.artifacts import AttackTree
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import (
    ArtifactBuilderSession,
    _find_item_index,
    _lists_excluding,
    _singular_label,
)

class TestToolCallingFixtureModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class OnlyLists(BaseModel):
        items: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class ScalarOnly(BaseModel):
        title: str

    class OptionalIdItem(BaseModel):
        id: str | None = None
        name: str

    class MultiFinish(BaseModel):
        title: str
        items: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class ProcessesArtifact(BaseModel):
        title: str
        processes: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)
        entries: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class BareListModel(BaseModel):
        rows: list = Field(default_factory=list)
        title: str

    class DataFieldModel(BaseModel):
        data: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)
        title: str


TestToolCallingFixtureModels.Item.model_rebuild()
TestToolCallingFixtureModels.OnlyLists.model_rebuild()
TestToolCallingFixtureModels.MultiFinish.model_rebuild()
TestToolCallingFixtureModels.ProcessesArtifact.model_rebuild()


class TestArtifactBuilderSessionBranches:
    """Cover remaining builder-session mutation and finish branches."""

    def test_replace_and_remove_validation_branches(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.ProcessesArtifact)
        )
        assert "id" in session.apply("replace_process", {"name": "Login"}).message.lower()
        session.apply("add_process", {"id": "proc-1", "name": "Login"})
        wrong_field = session.apply("remove_entry", {"id": "proc-1"})
        assert wrong_field.accepted is False
        assert "belongs to processes" in wrong_field.message

        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish)
        )
        assert "id" in session.apply("remove_item", {}).message.lower()

        validated_session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
        )
        validated_session.apply("add_item", {"id": "item-1", "name": "Login"})

        def reject_on_replace(
            list_field: str,
            payload: dict[str, JsonValue],
            existing_lists: Mapping[str, list[dict[str, JsonValue]]],
        ) -> list[str]:
            del list_field, payload, existing_lists
            return ["Rejected by validator"]

        object.__setattr__(validated_session, "_item_validator", reject_on_replace)
        replace_rejected = validated_session.apply("replace_item", {"id": "item-1", "name": "Logout"})
        assert replace_rejected.accepted is False
        assert "Rejected by validator" in replace_rejected.message

    def test_finish_validator_and_validation_error_paths(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
            finish_validator=lambda _payload: ["Finish blocked"],
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        blocked = session.apply("finish_multi_finish", {"title": "Demo"})
        assert blocked.accepted is False
        assert "Finish blocked" in blocked.message

        invalid_finish = session.apply("finish_multi_finish", {"title": ""})
        assert invalid_finish.accepted is False

    def test_singular_label_and_lists_excluding_helpers(self) -> None:
        assert _singular_label("classes") == "class"
        assert _singular_label("metadata") == "metadata"
        lists = {
            "entries": [{"id": "entry-1"}],
            "addresses": [{"id": "addr-1"}, {"id": "addr-2"}],
        }
        excluded = _lists_excluding(lists, "addresses", 0)
        assert excluded["entries"] == [{"id": "entry-1"}]
        assert len(excluded["addresses"]) == 1

    def test_builder_session_remaining_mutation_paths(self) -> None:
        from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSpec

        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.ProcessesArtifact)
        )
        assert "id" in session.apply("replace_process", {"name": "x"}).message.lower()
        session.apply("add_process", {"id": "proc-1", "name": "Login"})
        assert "belongs to processes" in session.apply("replace_entry", {"id": "proc-1", "name": "x"}).message
        assert "id" in session.apply("remove_process", {}).message.lower()

        optional_replace = ArtifactToolSpec.model_construct(
            name="replace_item",
            description="replace",
            parameter_model=TestToolCallingFixtureModels.OptionalIdItem,
            kind="replace_item",
            list_field="items",
        )
        optional_remove = ArtifactToolSpec.model_construct(
            name="remove_item",
            description="remove",
            parameter_model=TestToolCallingFixtureModels.OptionalIdItem,
            kind="remove_item",
            list_field="items",
        )
        optional_session = ArtifactBuilderSession(
            ArtifactToolSet(
                output_model=TestToolCallingFixtureModels.MultiFinish,
                tools=(optional_replace, optional_remove),
            )
        )
        optional_session.apply("replace_item", {"name": "missing-id"})
        optional_session.apply("remove_item", {"name": "missing-id"})

        optional_remove_node = ArtifactToolSpec.model_construct(
            name="remove_node",
            description="remove node",
            parameter_model=TestToolCallingFixtureModels.OptionalIdItem,
            kind="remove_node",
            list_field="root_nodes",
            node_model=None,
        )
        optional_tree_session = ArtifactBuilderSession(
            ArtifactToolSet(
                output_model=TestToolCallingFixtureModels.MultiFinish,
                tools=(optional_remove_node,),
            )
        )
        assert "requires a non-empty id" in optional_tree_session.apply(
            "remove_node",
            {"name": "orphan"},
        ).message

        from threatmodeler.contracts.artifacts import AttackTree

        tree_session = ArtifactBuilderSession(ArtifactToolSet.from_model(AttackTree))
        tree_session.apply(
            "add_node",
            {
                "id": "root-1",
                "name": "Root",
                "description": "Root",
                "confidence": 0.9,
                "operator": "or",
                "component_id": "payments-api",
            },
        )
        assert tree_session.apply(
            "replace_node",
            {"id": "missing", "name": "x", "description": "x", "confidence": 0.9, "operator": "or"},
        ).accepted is False
        assert "id" in tree_session.apply("remove_node", {"id": ""}).message.lower()

        finish_session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
            finish_validator=lambda _payload: ["Finish blocked"],
        )
        finish_session.apply("add_item", {"id": "item-1", "name": "Login"})
        invalid_finish = finish_session.apply("finish_multi_finish", {})
        assert invalid_finish.accepted is False
        assert "title" in invalid_finish.message
        blocked_finish = finish_session.apply("finish_multi_finish", {"title": "Demo"})
        assert blocked_finish.accepted is False
        assert "Finish blocked" in blocked_finish.message

    def test_builder_session_remaining_branch_paths(self) -> None:
        from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSpec

        optional_add = ArtifactToolSpec.model_construct(
            name="add_item",
            description="add",
            parameter_model=TestToolCallingFixtureModels.OptionalIdItem,
            kind="add_item",
            list_field="items",
        )
        optional_session = ArtifactBuilderSession(
            ArtifactToolSet(
                output_model=TestToolCallingFixtureModels.MultiFinish,
                tools=(optional_add,),
            )
        )
        assert optional_session.apply("add_item", {"name": "no-id"}).accepted is True

        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        duplicate = session.apply("add_item", {"id": "item-1", "name": "Login"})
        assert duplicate.accepted is True
        assert "already recorded" in duplicate.message

        session._lists["items"].append({"name": "missing-id"})
        assert session.apply("remove_item", {"id": "missing-id"}).accepted is False

        passing_finish = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
            finish_validator=lambda _payload: [],
        )
        passing_finish.apply("add_item", {"id": "item-1", "name": "Login"})
        finish = passing_finish.apply("finish_multi_finish", {"title": "Demo"})
        assert finish.accepted is True
        assert passing_finish.is_complete() is True
        assert passing_finish.assemble()["title"] == "Demo"

    def test_finish_validation_error_when_assembled_payload_invalid(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        session._lists["items"] = [{"id": "item-1"}]
        invalid_finish = session.apply("finish_multi_finish", {"title": "Demo"})
        assert invalid_finish.accepted is False
        assert "name" in invalid_finish.message

    def test_builder_session_find_item_index_skips_non_string_ids(self) -> None:
        from threatmodeler.domain.tool_calling.builder_session import _find_item_index

        lists = {"items": [{"id": 123}, {"name": "missing-id"}]}
        assert _find_item_index(lists, "missing-id") is None