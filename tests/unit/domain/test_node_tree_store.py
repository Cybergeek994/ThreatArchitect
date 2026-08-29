"""Tests for recursive attack-tree node storage."""

import pytest
from pydantic import BaseModel, Field
from threatmodeler.domain.tool_calling.node_tree_store import NodeTreeStore


class TestNodeTreeStoreModels:
    """Nested models kept off the test-module body."""

    class SimpleNode(BaseModel):
        id: str
        name: str
        children: list["TestNodeTreeStoreModels.SimpleNode"] = Field(default_factory=list)


TestNodeTreeStoreModels.SimpleNode.model_rebuild()


class TestNodeTreeStorePositive:
    """Verify accepted nodes assemble into nested trees."""

    @pytest.fixture
    def store(self) -> NodeTreeStore:
        return NodeTreeStore(TestNodeTreeStoreModels.SimpleNode)

    def test_add_root_and_child_assembles_nested_tree(self, store: NodeTreeStore) -> None:
        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        store.add({"id": "child-1", "name": "Child"}, parent_id="root-1")

        assembled = store.assemble()
        assert len(assembled) == 1
        assert assembled[0]["id"] == "root-1"
        children = assembled[0]["children"]
        assert isinstance(children, list)
        assert children[0]["id"] == "child-1"

    def test_replace_updates_existing_node(self, store: NodeTreeStore) -> None:
        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        accepted, message, _node = store.replace({"id": "root-1", "name": "Updated Root"})
        assert accepted is True
        assert "Replaced" in message
        assert store.assemble()[0]["name"] == "Updated Root"

    def test_remove_deletes_descendant_subtree(self, store: NodeTreeStore) -> None:
        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        store.add({"id": "child-1", "name": "Child"}, parent_id="root-1")
        store.add({"id": "grandchild-1", "name": "Grandchild"}, parent_id="child-1")

        accepted, message = store.remove("root-1")
        assert accepted is True
        assert "Removed" in message
        assert store.assemble() == []


class TestNodeTreeStoreNegative:
    """Verify invalid node operations are rejected."""

    @pytest.fixture
    def store(self) -> NodeTreeStore:
        return NodeTreeStore(TestNodeTreeStoreModels.SimpleNode)

    def test_add_rejects_missing_id(self, store: NodeTreeStore) -> None:
        accepted, message, node = store.add({"name": "Root"}, parent_id=None)
        assert accepted is False
        assert "non-empty id" in message
        assert node is None

    def test_add_rejects_duplicate_id(self, store: NodeTreeStore) -> None:
        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        accepted, message, node = store.add({"id": "root-1", "name": "Duplicate"}, parent_id=None)
        assert accepted is False
        assert "Duplicate node id" in message
        assert node is None

    def test_add_rejects_unknown_parent(self, store: NodeTreeStore) -> None:
        accepted, message, node = store.add(
            {"id": "child-1", "name": "Child"},
            parent_id="missing",
        )
        assert accepted is False
        assert "Unknown parent_id" in message
        assert node is None

    def test_add_rejects_invalid_payload(self, store: NodeTreeStore) -> None:
        accepted, message, node = store.add({"id": "root-1"}, parent_id=None)
        assert accepted is False
        assert "name" in message
        assert node is None

    def test_replace_rejects_unknown_id(self, store: NodeTreeStore) -> None:
        accepted, message, node = store.replace({"id": "missing", "name": "Root"})
        assert accepted is False
        assert "Use add_node instead" in message
        assert node is None

    def test_remove_rejects_unknown_id(self, store: NodeTreeStore) -> None:
        accepted, message = store.remove("missing")
        assert accepted is False
        assert "to remove" in message

    def test_validate_payload_without_node_model(self) -> None:
        store = NodeTreeStore(None)
        accepted, message, node = store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        assert accepted is False
        assert "Node model is not configured" in message
        assert node is None


from pydantic import BaseModel, Field


class TestNodeTreeStoreBranchCoverage:
    """Verify node tree store validation and traversal branches."""

    def test_node_tree_store_replace_branches(self) -> None:
        class Node(BaseModel):
            id: str
            name: str
            children: list["Node"] = Field(default_factory=list)

        Node.model_rebuild()
        store = NodeTreeStore(Node)
        accepted, message, node = store.replace({"name": "Root"})
        assert accepted is False and "non-empty id" in message and node is None
        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        accepted, message, node = store.replace({"id": "root-1"})
        assert accepted is False and "name" in message and node is None

        store.add({"id": "root-1", "name": "Root"}, parent_id=None)
        store.add({"id": "child-1", "name": "Child"}, parent_id="root-1")
        duplicate, message, node = store.add({"id": "child-1", "name": "Duplicate Child"}, parent_id="root-1")
        assert duplicate is False
        assert "Duplicate node id" in message
        assert node is None

    def test_node_tree_store_skips_revisited_descendants(self) -> None:
        class Node(BaseModel):
            id: str
            name: str
            children: list["Node"] = Field(default_factory=list)

        Node.model_rebuild()
        store = NodeTreeStore(Node)
        store.add({"id": "root", "name": "Root"}, parent_id=None)
        store.add({"id": "left", "name": "Left"}, parent_id="root")
        store.add({"id": "right", "name": "Right"}, parent_id="root")
        store.add({"id": "shared", "name": "Shared"}, parent_id="left")
        store._children.setdefault("right", []).append("shared")
        descendants = store._collect_descendant_ids("root")
        assert "shared" in descendants

    def test_node_tree_store_keeps_parent_when_sibling_remains(self) -> None:
        class Node(BaseModel):
            id: str
            name: str
            children: list["Node"] = Field(default_factory=list)

        Node.model_rebuild()
        store = NodeTreeStore(Node)
        store.add({"id": "root", "name": "Root"}, parent_id=None)
        store.add({"id": "left", "name": "Left"}, parent_id="root")
        store.add({"id": "right", "name": "Right"}, parent_id="root")
        assert store.remove("left")[0] is True
        assert "root" in store._children
        assert store._children["root"] == ["right"]
