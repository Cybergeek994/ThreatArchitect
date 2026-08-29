"""Host-owned builder state for piece-by-piece artifact construction."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from pydantic import BaseModel, JsonValue, ValidationError

from threatmodeler.contracts.tool_calling import ToolApplicationResult, ToolDefinition
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet, ArtifactToolSpec
from threatmodeler.domain.tool_calling.node_tree_store import NodeTreeStore
from threatmodeler.ports.artifact_construction_session_factory import (
    FinishValidator,
    ItemValidator,
)
from threatmodeler.validation.evidence_grounding import EvidenceGroundingChecker


class ArtifactBuilderSession:
    """Accumulate validated pieces and assemble a complete output payload."""

    def __init__(
        self,
        tool_set: ArtifactToolSet,
        *,
        source_text: str = "",
        finish_validator: FinishValidator | None = None,
        item_validator: ItemValidator | None = None,
        grounding_checker: EvidenceGroundingChecker | None = None,
        low_confidence_threshold: float = 0.5,
    ) -> None:
        self._tool_set = tool_set
        self._source_text = source_text
        self._finish_validator = finish_validator
        self._item_validator = item_validator
        self._grounding_checker = grounding_checker or EvidenceGroundingChecker()
        self._low_confidence_threshold = low_confidence_threshold
        self._lists: dict[str, list[dict[str, JsonValue]]] = {
            tool.list_field: []
            for tool in tool_set.tools
            if tool.kind == "add_item" and tool.list_field is not None
        }
        self._node_list_field: str | None = next(
            (tool.list_field for tool in tool_set.tools if tool.kind == "add_node"),
            None,
        )
        node_model: type[BaseModel] | None = next(
            (tool.node_model for tool in tool_set.tools if tool.kind == "add_node"),
            None,
        )
        self._node_tree = NodeTreeStore(node_model)
        self._assembled: dict[str, JsonValue] | None = None

    def tool_definitions(self) -> list[ToolDefinition]:
        """Return the provider-neutral tool catalog."""
        return self._tool_set.definitions()

    def tool_parameter_model(self, name: str) -> type[BaseModel]:
        """Return the Pydantic parameter model for a named tool.

        Args:
            name: Tool name from the catalog.

        Returns:
            Parameter model for ``name``.

        Raises:
            KeyError: If the tool name is unknown.
        """
        spec = self._tool_set.get(name)
        if spec is None:
            raise KeyError(name)
        return spec.parameter_model

    def apply(self, name: str, arguments: dict[str, JsonValue]) -> ToolApplicationResult:
        """Validate one tool invocation and merge accepted data into builder state.

        Args:
            name: Tool name invoked by the provider.
            arguments: JSON-compatible tool arguments.

        Returns:
            Acceptance result. Rejected items never enter assembled state.
        """
        spec = self._tool_set.get(name)
        if spec is None:
            return ToolApplicationResult(
                accepted=False,
                message=f"Unknown construction tool '{name}'",
            )
        try:
            parsed = spec.parameter_model.model_validate(arguments)
        except ValidationError as error:
            return ToolApplicationResult(
                accepted=False,
                message=_format_validation_error(error),
            )
        command = self._command_for(spec)
        return command(spec, parsed)

    def assemble(self) -> dict[str, JsonValue]:
        """Return the payload accepted by a successful finish tool.

        Returns:
            Assembled JSON object.

        Raises:
            RuntimeError: If finish has not been accepted.
        """
        if self._assembled is None:
            raise RuntimeError("Artifact construction is not complete")
        return self._assembled

    def is_complete(self) -> bool:
        """Return whether the finish tool has been accepted."""
        return self._assembled is not None

    def _command_for(
        self,
        spec: ArtifactToolSpec,
    ) -> Callable[[ArtifactToolSpec, BaseModel], ToolApplicationResult]:
        commands: dict[str, Callable[[ArtifactToolSpec, BaseModel], ToolApplicationResult]] = {
            "add_item": self._add_item,
            "replace_item": self._replace_item,
            "remove_item": self._remove_item,
            "add_node": lambda _spec, parsed: self._add_node(parsed),
            "replace_node": lambda _spec, parsed: self._replace_node(parsed),
            "remove_node": lambda _spec, parsed: self._remove_node(parsed),
            "finish": lambda _spec, parsed: self._finish(parsed),
        }
        command = commands.get(spec.kind)
        if command is None:
            return lambda _spec, _parsed: ToolApplicationResult(
                accepted=False,
                message=f"Unsupported construction tool kind '{spec.kind}'",
            )
        return command

    def _add_item(self, spec: ArtifactToolSpec, parsed: BaseModel) -> ToolApplicationResult:
        assert spec.list_field is not None
        payload = cast(dict[str, JsonValue], parsed.model_dump(mode="json"))
        item_id = _item_id(parsed)
        if item_id is not None:
            duplicate = _find_item_by_id(self._lists, item_id)
            if duplicate is not None:
                existing_field, existing_payload = duplicate
                if existing_payload == payload:
                    return ToolApplicationResult(
                        accepted=True,
                        message=f"Item '{item_id}' already recorded — no changes made.",
                        evidence_grounded=self._grounding_checker.is_grounded(
                            parsed,
                            self._source_text,
                        ),
                        item_id=item_id,
                        confidence=_item_confidence(parsed),
                    )
                return ToolApplicationResult(
                    accepted=False,
                    message=(
                        f"Id '{item_id}' is already used by a different {existing_field} item "
                        "with different content. Choose a new id or confirm which version "
                        "is correct."
                    ),
                    item_id=item_id,
                )
        if self._item_validator is not None:
            violations = self._item_validator(spec.list_field, payload, self._lists)
            if violations:
                return ToolApplicationResult(
                    accepted=False,
                    message="; ".join(violations),
                    item_id=item_id,
                )
        self._lists[spec.list_field].append(payload)
        return ToolApplicationResult(
            accepted=True,
            message=f"Accepted item for {spec.list_field}",
            evidence_grounded=self._grounding_checker.is_grounded(parsed, self._source_text),
            item_id=item_id,
            confidence=_item_confidence(parsed),
        )

    def _replace_item(self, spec: ArtifactToolSpec, parsed: BaseModel) -> ToolApplicationResult:
        assert spec.list_field is not None
        payload = cast(dict[str, JsonValue], parsed.model_dump(mode="json"))
        item_id = _item_id(parsed)
        if item_id is None:
            return ToolApplicationResult(
                accepted=False,
                message=f"replace_{_singular_label(spec.list_field)} requires a non-empty id",
            )
        located = _find_item_index(self._lists, item_id)
        if located is None:
            return ToolApplicationResult(
                accepted=False,
                message=(
                    f"No existing {_singular_label(spec.list_field)} with id '{item_id}'. "
                    f"Use add_{_singular_label(spec.list_field)} instead."
                ),
            )
        existing_field, index = located
        if existing_field != spec.list_field:
            return ToolApplicationResult(
                accepted=False,
                message=(
                    f"Id '{item_id}' belongs to {existing_field}, not {spec.list_field}. "
                    "Remove it there first or choose a different id."
                ),
            )
        if self._item_validator is not None:
            lists_without = _lists_excluding(self._lists, spec.list_field, index)
            violations = self._item_validator(spec.list_field, payload, lists_without)
            if violations:
                return ToolApplicationResult(
                    accepted=False,
                    message="; ".join(violations),
                    item_id=item_id,
                )
        self._lists[spec.list_field][index] = payload
        return ToolApplicationResult(
            accepted=True,
            message=f"Replaced item '{item_id}' in {spec.list_field}",
            evidence_grounded=self._grounding_checker.is_grounded(parsed, self._source_text),
            item_id=item_id,
            confidence=_item_confidence(parsed),
        )

    def _remove_item(self, spec: ArtifactToolSpec, parsed: BaseModel) -> ToolApplicationResult:
        assert spec.list_field is not None
        item_id = _item_id(parsed)
        if item_id is None:
            return ToolApplicationResult(
                accepted=False,
                message=f"remove_{_singular_label(spec.list_field)} requires a non-empty id",
            )
        items = self._lists[spec.list_field]
        for index, item in enumerate(items):
            existing_id = item.get("id")
            if isinstance(existing_id, str) and existing_id == item_id:
                del items[index]
                return ToolApplicationResult(
                    accepted=True,
                    message=f"Removed item '{item_id}' from {spec.list_field}",
                    item_id=item_id,
                )
        elsewhere = _find_item_by_id(self._lists, item_id)
        if elsewhere is not None:
            other_field, _payload = elsewhere
            return ToolApplicationResult(
                accepted=False,
                message=(
                    f"Id '{item_id}' belongs to {other_field}, not {spec.list_field}. "
                    f"Use remove_{_singular_label(other_field)} instead."
                ),
            )
        return ToolApplicationResult(
            accepted=False,
            message=(
                f"No existing {_singular_label(spec.list_field)} with id '{item_id}' to remove."
            ),
        )

    def _add_node(self, parsed: BaseModel) -> ToolApplicationResult:
        values = parsed.model_dump(mode="json")
        parent_id = values.pop("parent_id", None)
        node_id = values.get("id")
        accepted, message, validated_node = self._node_tree.add(
            cast(dict[str, JsonValue], values),
            parent_id=parent_id if isinstance(parent_id, str) else None,
        )
        if not accepted or validated_node is None:
            return ToolApplicationResult(
                accepted=False,
                message=message,
                item_id=node_id if isinstance(node_id, str) else None,
            )
        return ToolApplicationResult(
            accepted=True,
            message=message,
            evidence_grounded=self._grounding_checker.is_grounded(
                validated_node,
                self._source_text,
            ),
            item_id=node_id if isinstance(node_id, str) else None,
            confidence=_item_confidence(validated_node),
        )

    def _replace_node(self, parsed: BaseModel) -> ToolApplicationResult:
        values = parsed.model_dump(mode="json")
        node_id = values.get("id")
        accepted, message, validated_node = self._node_tree.replace(
            cast(dict[str, JsonValue], values),
        )
        if not accepted or validated_node is None:
            return ToolApplicationResult(
                accepted=False,
                message=message,
                item_id=node_id if isinstance(node_id, str) else None,
            )
        return ToolApplicationResult(
            accepted=True,
            message=message,
            evidence_grounded=self._grounding_checker.is_grounded(
                validated_node,
                self._source_text,
            ),
            item_id=node_id if isinstance(node_id, str) else None,
            confidence=_item_confidence(validated_node),
        )

    def _remove_node(self, parsed: BaseModel) -> ToolApplicationResult:
        node_id = getattr(parsed, "id", None)
        if not isinstance(node_id, str) or not node_id:
            return ToolApplicationResult(
                accepted=False,
                message="remove_node requires a non-empty id",
            )
        accepted, message = self._node_tree.remove(node_id)
        return ToolApplicationResult(
            accepted=accepted,
            message=message,
            item_id=node_id,
        )

    def _finish(self, parsed: BaseModel) -> ToolApplicationResult:
        payload = cast(dict[str, JsonValue], parsed.model_dump(mode="json"))
        payload.update(cast(dict[str, JsonValue], self._lists))
        if self._node_list_field is not None:
            payload[self._node_list_field] = cast(JsonValue, self._node_tree.assemble())
        try:
            validated = self._tool_set.output_model.model_validate(payload)
        except ValidationError as error:
            return ToolApplicationResult(
                accepted=False,
                message=_format_validation_error(error),
                finished=False,
            )
        assembled = cast(dict[str, JsonValue], validated.model_dump(mode="json"))
        if self._finish_validator is not None:
            violations = self._finish_validator(assembled)
            if violations:
                return ToolApplicationResult(
                    accepted=False,
                    message="; ".join(violations),
                    finished=False,
                )
        self._assembled = assembled
        return ToolApplicationResult(
            accepted=True,
            message="Artifact construction finished",
            finished=True,
            evidence_grounded=self._grounding_checker.is_grounded(validated, self._source_text),
            confidence=_item_confidence(validated),
        )


def _find_item_by_id(
    lists: dict[str, list[dict[str, JsonValue]]],
    item_id: str,
) -> tuple[str, dict[str, JsonValue]] | None:
    for list_field, items in lists.items():
        for item in items:
            existing_id = item.get("id")
            if isinstance(existing_id, str) and existing_id == item_id:
                return list_field, item
    return None


def _find_item_index(
    lists: dict[str, list[dict[str, JsonValue]]],
    item_id: str,
) -> tuple[str, int] | None:
    for list_field, items in lists.items():
        for index, item in enumerate(items):
            existing_id = item.get("id")
            if isinstance(existing_id, str) and existing_id == item_id:
                return list_field, index
    return None


def _lists_excluding(
    lists: dict[str, list[dict[str, JsonValue]]],
    list_field: str,
    index: int,
) -> dict[str, list[dict[str, JsonValue]]]:
    result: dict[str, list[dict[str, JsonValue]]] = {}
    for field, items in lists.items():
        if field != list_field:
            result[field] = items
            continue
        result[field] = [item for position, item in enumerate(items) if position != index]
    return result


def _singular_label(list_field: str) -> str:
    if list_field.endswith("ies"):
        return f"{list_field[:-3]}y"
    if list_field.endswith("sses"):
        return list_field[:-2]
    if list_field.endswith("s") and not list_field.endswith("ss"):
        return list_field[:-1]
    return list_field


def _item_id(item: BaseModel) -> str | None:
    value = getattr(item, "id", None)
    return value if isinstance(value, str) and value else None


def _item_confidence(item: BaseModel) -> float | None:
    value = getattr(item, "confidence", None)
    return value if isinstance(value, int | float) else None


def _format_validation_error(error: ValidationError) -> str:
    parts: list[str] = []
    for item in error.errors(include_url=False, include_input=False):
        location = ".".join(str(part) for part in item.get("loc", ()))
        message = str(item.get("msg", "invalid"))
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "Validation failed"
