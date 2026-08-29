"""In-memory store for recursive attack-tree node construction."""

from __future__ import annotations

from typing import cast

from pydantic import BaseModel, JsonValue, ValidationError


class NodeTreeStore:
    """Track parent-child node payloads during incremental tree construction."""

    def __init__(self, node_model: type[BaseModel] | None) -> None:
        self._node_model = node_model
        self._nodes: dict[str, dict[str, JsonValue]] = {}
        self._children: dict[str, list[str]] = {}
        self._root_ids: list[str] = []

    def add(
        self,
        values: dict[str, JsonValue],
        *,
        parent_id: str | None,
    ) -> tuple[bool, str, BaseModel | None]:
        """Validate and store one node."""
        node_id = values.get("id")
        if not isinstance(node_id, str) or not node_id:
            return False, "add_node requires a non-empty id", None
        if node_id in self._nodes:
            return False, f"Duplicate node id '{node_id}'", None
        validated_node, validation_error = self._validate_payload(values)
        if validated_node is None:
            return False, validation_error or "Invalid node", None
        if parent_id is None:
            self._root_ids.append(node_id)
        elif parent_id not in self._nodes:
            return False, f"Unknown parent_id '{parent_id}'", None
        else:
            self._children.setdefault(parent_id, []).append(node_id)
        self._nodes[node_id] = cast(
            dict[str, JsonValue],
            validated_node.model_dump(mode="json"),
        )
        self._nodes[node_id].pop("children", None)
        return True, f"Accepted node {node_id}", validated_node

    def replace(self, values: dict[str, JsonValue]) -> tuple[bool, str, BaseModel | None]:
        """Replace an existing node payload by id."""
        node_id = values.get("id")
        if not isinstance(node_id, str) or not node_id:
            return False, "replace_node requires a non-empty id", None
        if node_id not in self._nodes:
            return (
                False,
                f"No existing node with id '{node_id}'. Use add_node instead.",
                None,
            )
        validated_node, validation_error = self._validate_payload(values)
        if validated_node is None:
            return False, validation_error or "Invalid node", None
        payload = cast(dict[str, JsonValue], validated_node.model_dump(mode="json"))
        payload.pop("children", None)
        self._nodes[node_id] = payload
        return True, f"Replaced node {node_id}", validated_node

    def remove(self, node_id: str) -> tuple[bool, str]:
        """Remove a node and its descendant subtree."""
        if node_id not in self._nodes:
            return False, f"No existing node with id '{node_id}' to remove."
        to_remove = self._collect_descendant_ids(node_id)
        to_remove.add(node_id)
        self._root_ids = [root_id for root_id in self._root_ids if root_id not in to_remove]
        for parent_id, child_ids in list(self._children.items()):
            self._children[parent_id] = [
                child_id for child_id in child_ids if child_id not in to_remove
            ]
            if not self._children[parent_id]:
                del self._children[parent_id]
        for removed_id in to_remove:
            self._nodes.pop(removed_id, None)
            self._children.pop(removed_id, None)
        return True, f"Removed node {node_id}"

    def assemble(self) -> list[dict[str, JsonValue]]:
        """Build nested node trees from stored flat nodes."""

        def build(current_id: str) -> dict[str, JsonValue]:
            node = dict(self._nodes[current_id])
            child_ids = self._children.get(current_id, [])
            node["children"] = [build(child_id) for child_id in child_ids]
            return node

        return [build(root_id) for root_id in self._root_ids]

    def _validate_payload(
        self,
        values: dict[str, JsonValue],
    ) -> tuple[BaseModel | None, str | None]:
        if self._node_model is None:
            return None, "Node model is not configured"
        try:
            return self._node_model.model_validate({**values, "children": []}), None
        except ValidationError as error:
            return None, _format_validation_error(error)

    def _collect_descendant_ids(self, node_id: str) -> set[str]:
        descendants: set[str] = set()
        stack = list(self._children.get(node_id, []))
        while stack:
            current = stack.pop()
            if current in descendants:
                continue
            descendants.add(current)
            stack.extend(self._children.get(current, []))
        return descendants


def _format_validation_error(error: ValidationError) -> str:
    parts: list[str] = []
    for item in error.errors(include_url=False, include_input=False):
        location = ".".join(str(part) for part in item.get("loc", ()))
        message = str(item.get("msg", "invalid"))
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "Validation failed"
