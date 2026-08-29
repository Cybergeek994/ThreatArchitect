"""Tests for schema-derived artifact construction tools."""

from collections.abc import Mapping
from typing import cast

import pytest
from pydantic import BaseModel, Field, JsonValue
from threatmodeler.contracts.artifacts import AttackTree
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.ports.artifact_construction_session_factory import ItemValidator


class TestArtifactConstructionModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class Artifact(BaseModel):
        title: str
        items: list["TestArtifactConstructionModels.Item"] = Field(default_factory=list)


TestArtifactConstructionModels.Artifact.model_rebuild()


class TestArtifactToolSetPositive:
    """Verify supported tool catalogs derived from output models."""

    def test_list_fields_become_add_tools_and_scalars_go_to_finish(self) -> None:
        tool_set = ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        names = [tool.name for tool in tool_set.tools]
        assert "add_item" in names
        assert "replace_item" in names
        assert "remove_item" in names
        assert "finish_artifact" in names

    def test_canonical_system_model_exposes_entity_add_tools(self) -> None:
        names = [tool.name for tool in ArtifactToolSet.from_model(CanonicalSystemModel).tools]
        assert "add_actor" in names
        assert "replace_actor" in names
        assert "remove_actor" in names
        assert "finish_canonical_system_model" in names
        assert "add_diagram_topology" not in names
        assert "add_diagram_evidence" not in names

    def test_attack_tree_uses_recursive_add_node_tool(self) -> None:
        names = [tool.name for tool in ArtifactToolSet.from_model(AttackTree).tools]
        assert names[0] == "add_node"
        assert "replace_node" in names
        assert "remove_node" in names
        assert "finish_attack_tree" in names


class TestArtifactBuilderSessionPositive:
    """Verify accepted pieces assemble into a valid artifact."""

    def test_add_then_finish_assembles_payload(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        added = session.apply("add_item", {"id": "item-1", "name": "Login"})
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert added.accepted is True
        assert finished.accepted is True
        assert finished.finished is True
        payload = session.assemble()
        items = cast(list[dict[str, JsonValue]], payload["items"])
        assert items[0]["id"] == "item-1"


class TestArtifactBuilderSessionNegative:
    """Verify rejected pieces never enter assembled state."""

    def test_invalid_item_is_rejected_and_omitted(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        result = session.apply("add_item", {"name": "Login"})
        assert result.accepted is False
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        assert session.assemble()["items"] == []


class TestArtifactBuilderSessionIdDedupe:
    """Verify generic id-uniqueness and idempotent resubmission handling."""

    def test_identical_resubmission_is_accepted_without_duplicating(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        first = session.apply("add_item", {"id": "item-1", "name": "Login"})
        second = session.apply("add_item", {"id": "item-1", "name": "Login"})
        assert first.accepted is True
        assert second.accepted is True
        assert "already recorded" in second.message
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        items = cast(list[dict[str, JsonValue]], session.assemble()["items"])
        assert len(items) == 1

    def test_colliding_id_with_different_content_is_rejected(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        result = session.apply("add_item", {"id": "item-1", "name": "Logout"})
        assert result.accepted is False
        assert "already used" in result.message
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        items = cast(list[dict[str, JsonValue]], session.assemble()["items"])
        assert items[0]["name"] == "Login"


class TestArtifactBuilderSessionItemValidator:
    """Verify optional per-item validation hook behavior."""

    def test_item_validator_rejects_before_append(self) -> None:
        def reject_all(
            list_field: str,
            payload: dict[str, JsonValue],
            existing_lists: Mapping[str, list[dict[str, JsonValue]]],
        ) -> list[str]:
            del list_field, payload, existing_lists
            return ["Rejected by test validator"]

        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact),
            item_validator=cast(ItemValidator, reject_all),
        )
        result = session.apply("add_item", {"id": "item-1", "name": "Login"})
        assert result.accepted is False
        assert "Rejected by test validator" in result.message
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        assert session.assemble()["items"] == []


class TestArtifactBuilderSessionMutation:
    """Verify replace/remove tools repair session state in place."""

    def test_replace_overwrites_content(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        replaced = session.apply("replace_item", {"id": "item-1", "name": "Logout"})
        assert replaced.accepted is True
        assert "Replaced" in replaced.message
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        items = cast(list[dict[str, JsonValue]], session.assemble()["items"])
        assert items[0]["name"] == "Logout"

    def test_replace_unknown_id_is_rejected(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        result = session.apply("replace_item", {"id": "missing", "name": "Login"})
        assert result.accepted is False
        assert "No existing item" in result.message

    def test_remove_deletes_and_allows_readd(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        removed = session.apply("remove_item", {"id": "item-1"})
        assert removed.accepted is True
        readded = session.apply("add_item", {"id": "item-1", "name": "Login"})
        assert readded.accepted is True
        finished = session.apply("finish_artifact", {"title": "Demo"})
        assert finished.accepted is True
        items = cast(list[dict[str, JsonValue]], session.assemble()["items"])
        assert len(items) == 1

    def test_remove_unknown_id_is_rejected(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        result = session.apply("remove_item", {"id": "missing"})
        assert result.accepted is False
        assert "to remove" in result.message

    def test_replace_runs_item_validator_against_state_without_old_item(self) -> None:
        calls: list[list[dict[str, JsonValue]]] = []

        def capture(
            list_field: str,
            payload: dict[str, JsonValue],
            existing_lists: Mapping[str, list[dict[str, JsonValue]]],
        ) -> list[str]:
            del list_field, payload
            calls.append(list(existing_lists.get("items", [])))
            return []

        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact),
            item_validator=cast(ItemValidator, capture),
        )
        session.apply("add_item", {"id": "item-1", "name": "Login"})
        session.apply("replace_item", {"id": "item-1", "name": "Logout"})
        assert calls[-1] == []


class TestAttackTreeBuilderSession:
    """Verify recursive node validation and mutation tools."""

    def test_add_node_rejects_missing_traceability(self) -> None:
        session = ArtifactBuilderSession(ArtifactToolSet.from_model(AttackTree))
        result = session.apply(
            "add_node",
            {
                "id": "root-1",
                "name": "Compromise platform",
                "description": "Top-level attack goal",
                "confidence": 0.9,
                "operator": "or",
            },
        )
        assert result.accepted is False
        assert "threat-related item must link" in result.message

    def test_add_node_accepts_component_link_and_replace_fixes_content(self) -> None:
        session = ArtifactBuilderSession(ArtifactToolSet.from_model(AttackTree))
        added = session.apply(
            "add_node",
            {
                "id": "root-1",
                "name": "Compromise platform",
                "description": "Top-level attack goal",
                "confidence": 0.9,
                "operator": "or",
                "component_id": "payments-api",
            },
        )
        assert added.accepted is True
        replaced = session.apply(
            "replace_node",
            {
                "id": "root-1",
                "name": "Compromise payments API",
                "description": "Top-level attack goal against payments-api",
                "confidence": 0.95,
                "operator": "or",
                "component_id": "payments-api",
            },
        )
        assert replaced.accepted is True
        finished = session.apply(
            "finish_attack_tree",
            {
                "artifact_id": "attack-tree-1",
                "title": "Attack Tree",
                "description": "Demo tree",
                "confidence": 0.9,
            },
        )
        assert finished.accepted is True
        roots = cast(list[dict[str, JsonValue]], session.assemble()["root_nodes"])
        assert roots[0]["name"] == "Compromise payments API"

    def test_remove_node_removes_subtree(self) -> None:
        session = ArtifactBuilderSession(ArtifactToolSet.from_model(AttackTree))
        session.apply(
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
        session.apply(
            "add_node",
            {
                "parent_id": "root-1",
                "id": "child-1",
                "name": "Child",
                "description": "Child",
                "confidence": 0.9,
                "operator": "leaf",
                "component_id": "payments-api",
            },
        )
        removed = session.apply("remove_node", {"id": "root-1"})
        assert removed.accepted is True
        finished = session.apply(
            "finish_attack_tree",
            {
                "artifact_id": "attack-tree-1",
                "title": "Attack Tree",
                "description": "Demo tree",
                "confidence": 0.9,
            },
        )
        assert finished.accepted is True
        assert session.assemble()["root_nodes"] == []


class TestArtifactBuilderSessionEdgeCases:
    """Verify builder-session error paths and label edge cases."""

    class Entry(BaseModel):
        id: str
        name: str

    class MultiListArtifact(BaseModel):
        title: str
        entries: list["TestArtifactBuilderSessionEdgeCases.Entry"] = Field(default_factory=list)
        addresses: list["TestArtifactBuilderSessionEdgeCases.Entry"] = Field(
            default_factory=list
        )

    class BrokenParameter(BaseModel):
        value: str


TestArtifactBuilderSessionEdgeCases.MultiListArtifact.model_rebuild()


class TestArtifactBuilderSessionEdgeCasesNegative:
    """Verify rejected builder-session operations."""

    def test_unknown_tool_name_is_rejected(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        result = session.apply("missing_tool", {"id": "item-1"})
        assert result.accepted is False
        assert "Unknown construction tool" in result.message

    def test_unsupported_tool_kind_is_rejected(self) -> None:
        from typing import Literal, cast

        from threatmodeler.domain.tool_calling.artifact_tool_set import (
            ArtifactToolSet,
            ArtifactToolSpec,
        )

        broken_spec = ArtifactToolSpec.model_construct(
            name="broken_tool",
            description="Unsupported kind",
            parameter_model=TestArtifactBuilderSessionEdgeCases.BrokenParameter,
            kind=cast(
                Literal[
                    "add_item",
                    "replace_item",
                    "remove_item",
                    "add_node",
                    "replace_node",
                    "remove_node",
                    "finish",
                ],
                "unsupported_kind",
            ),
        )
        tool_set = ArtifactToolSet(
            output_model=TestArtifactConstructionModels.Artifact,
            tools=(broken_spec,),
        )
        session = ArtifactBuilderSession(tool_set)
        result = session.apply("broken_tool", {"value": "demo"})
        assert result.accepted is False
        assert "Unsupported construction tool kind" in result.message

    def test_tool_parameter_model_raises_key_error_for_unknown_name(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        with pytest.raises(KeyError):
            session.tool_parameter_model("missing_tool")

    def test_assemble_before_finish_raises_runtime_error(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactConstructionModels.Artifact)
        )
        with pytest.raises(RuntimeError, match="not complete"):
            session.assemble()

    def test_remove_item_rejects_id_from_other_list_field(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactBuilderSessionEdgeCases.MultiListArtifact)
        )
        session.apply("add_entry", {"id": "entry-1", "name": "Entry"})
        result = session.apply("remove_address", {"id": "entry-1"})
        assert result.accepted is False
        assert "belongs to entries" in result.message
        assert "remove_entry" in result.message

    def test_singular_label_edge_cases_surface_in_messages(self) -> None:
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestArtifactBuilderSessionEdgeCases.MultiListArtifact)
        )
        missing_entry = session.apply("remove_entry", {"id": "missing"})
        missing_address = session.apply("remove_address", {"id": "missing"})
        assert "No existing entry with id" in missing_entry.message
        assert "No existing address with id" in missing_address.message


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
TestToolCallingFixtureModels.DataFieldModel.model_rebuild()


class TestArtifactToolSetDerivationEdgeCases:
    """Cover tool-set derivation edge cases."""

    def test_only_list_fields_produce_finish_tool_with_empty_args(self) -> None:
        tool_set = ArtifactToolSet.from_model(TestToolCallingFixtureModels.OnlyLists)
        finish_tool = next(tool for tool in tool_set.tools if tool.kind == "finish")
        assert finish_tool.parameter_model.model_fields == {}

    def test_get_returns_none_for_unknown_tool(self) -> None:
        tool_set = ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish)
        assert tool_set.get("missing") is None

    def test_singularize_addresses_list_field(self) -> None:
        tool_set = ArtifactToolSet.from_model(TestToolCallingFixtureModels.ProcessesArtifact)
        assert any(tool.name == "add_process" for tool in tool_set.tools)

    def test_artifact_tool_set_edge_cases(self) -> None:
        assert ArtifactToolSet.from_model(TestToolCallingFixtureModels.BareListModel).output_model is TestToolCallingFixtureModels.BareListModel
        tool_set = ArtifactToolSet.from_model(TestToolCallingFixtureModels.DataFieldModel)
        assert any(tool.name == "add_data" for tool in tool_set.tools)
        assert tool_set.definitions()

    def test_artifact_tool_set_list_item_model_empty_args(self) -> None:
        from typing import List

        from threatmodeler.domain.tool_calling.artifact_tool_set import _list_item_model

        assert _list_item_model(List) is None
        assert _list_item_model(list) is None
        assert ArtifactToolSet.from_model(TestToolCallingFixtureModels.BareListModel).tools

    def test_artifact_tool_set_list_mutation_tools_helper(self) -> None:
        from threatmodeler.domain.tool_calling.artifact_tool_set import _list_mutation_tools

        tools = _list_mutation_tools(
            "items",
            "item",
            TestToolCallingFixtureModels.Item,
        )
        assert {tool.kind for tool in tools} == {"add_item", "replace_item", "remove_item"}

    def test_artifact_tool_set_unwrap_multi_union(self) -> None:
        from threatmodeler.domain.tool_calling.artifact_tool_set import _list_item_model

        class Root(BaseModel):
            items: str | int | None = None

        assert _list_item_model(Root.model_fields["items"].annotation) is None
