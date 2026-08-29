"""Derive typed construction tools from a Pydantic artifact model."""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import UnionType
from typing import Annotated, Any, Literal, Union, cast, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, create_model
from pydantic.fields import FieldInfo

from threatmodeler.contracts.tool_calling import ToolDefinition


class ArtifactToolSpec(BaseModel):
    """One construction tool derived from an output-model field."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    description: str
    parameter_model: type[BaseModel]
    kind: Literal[
        "add_item",
        "replace_item",
        "remove_item",
        "add_node",
        "replace_node",
        "remove_node",
        "finish",
    ]
    list_field: str | None = None
    node_model: type[BaseModel] | None = None


class ArtifactToolSet:
    """Catalog of add/finish tools for one Pydantic output model."""

    def __init__(self, output_model: type[BaseModel], tools: tuple[ArtifactToolSpec, ...]) -> None:
        self.output_model = output_model
        self.tools = tools
        self._by_name = {tool.name: tool for tool in tools}

    @classmethod
    def from_model(cls, output_model: type[BaseModel]) -> ArtifactToolSet:
        """Build add/replace/remove or add-node tools plus one finish tool.

        Args:
            output_model: Pydantic model produced by the agent task.

        Returns:
            Tool catalog covering list fields and remaining finish fields.
        """
        list_tools: list[ArtifactToolSpec] = []
        finish_fields: dict[str, object] = {}
        for name, field_info in output_model.model_fields.items():
            if _is_host_owned_field(field_info):
                continue
            item_model = _list_item_model(field_info.annotation)
            if item_model is None:
                finish_fields[name] = field_info
                continue
            if _is_recursive_node(item_model):
                list_tools.extend(_node_mutation_tools(name, item_model))
                continue
            singular = _singularize(name)
            list_tools.extend(_list_mutation_tools(name, singular, item_model))
        finish_model = _finish_parameter_model(output_model, finish_fields)
        finish_name = f"finish_{_snake_case(output_model.__name__)}"
        tools = (
            *list_tools,
            ArtifactToolSpec(
                name=finish_name,
                description=(
                    f"Finish {output_model.__name__} by supplying remaining non-list fields. "
                    "The host validates the assembled object before accepting this call."
                ),
                parameter_model=finish_model,
                kind="finish",
            ),
        )
        return cls(output_model, tools)

    def get(self, name: str) -> ArtifactToolSpec | None:
        """Return a tool spec by name.

        Args:
            name: Tool name advertised to the provider.

        Returns:
            Matching spec, or ``None`` when the name is unknown.
        """
        return self._by_name.get(name)

    def definitions(self) -> list[ToolDefinition]:
        """Return provider-neutral tool definitions.

        Returns:
            JSON-schema tool catalog for both OpenAI and Copilot drivers.
        """
        return [
            ToolDefinition(
                name=tool.name,
                description=tool.description,
                parameters_schema=tool.parameter_model.model_json_schema(),
                is_terminal=tool.kind == "finish",
            )
            for tool in self.tools
        ]


def _list_mutation_tools(
    list_field: str,
    singular: str,
    item_model: type[BaseModel],
) -> list[ArtifactToolSpec]:
    remove_model = create_model(
        f"{item_model.__name__}RemoveArgs",
        **cast(
            dict[str, Any],
            {
                "id": (
                    Annotated[str, Field(strict=True, min_length=1)],
                    Field(description=f"Id of the {item_model.__name__} item to remove"),
                )
            },
        ),
    )
    return [
        ArtifactToolSpec(
            name=f"add_{singular}",
            description=(
                f"Add one validated {item_model.__name__} item to `{list_field}`. "
                "Rejected items are not stored."
            ),
            parameter_model=item_model,
            kind="add_item",
            list_field=list_field,
        ),
        ArtifactToolSpec(
            name=f"replace_{singular}",
            description=(
                f"Replace an existing {item_model.__name__} in `{list_field}` by id. "
                "Use this to correct content after a finish rejection."
            ),
            parameter_model=item_model,
            kind="replace_item",
            list_field=list_field,
        ),
        ArtifactToolSpec(
            name=f"remove_{singular}",
            description=(
                f"Remove an existing {item_model.__name__} from `{list_field}` by id. "
                "Use this to discard a mistaken item."
            ),
            parameter_model=remove_model,
            kind="remove_item",
            list_field=list_field,
        ),
    ]


def _finish_parameter_model(
    output_model: type[BaseModel],
    finish_fields: Mapping[str, object],
) -> type[BaseModel]:
    definitions: dict[str, tuple[object, object]] = {}
    for name, field_info in finish_fields.items():
        definitions[name] = (output_model.model_fields[name].annotation, field_info)
    if not definitions:
        return create_model(f"{output_model.__name__}FinishArgs")
    return create_model(
        f"{output_model.__name__}FinishArgs",
        **cast(dict[str, Any], definitions),
    )


def _node_mutation_tools(
    list_field: str,
    item_model: type[BaseModel],
) -> list[ArtifactToolSpec]:
    add_args = _node_parameter_model(item_model, include_parent_id=True)
    replace_args = _node_parameter_model(item_model, include_parent_id=False)
    remove_args = create_model(
        f"{item_model.__name__}RemoveNodeArgs",
        **cast(
            dict[str, Any],
            {
                "id": (
                    Annotated[str, Field(strict=True, min_length=1)],
                    Field(description=f"Id of the {item_model.__name__} node to remove"),
                )
            },
        ),
    )
    return [
        ArtifactToolSpec(
            name="add_node",
            description=(
                f"Add one validated {item_model.__name__} to `{list_field}`. "
                "Pass parent_id to attach under an existing node; omit it for a root node. "
                "Rejected nodes are not stored."
            ),
            parameter_model=add_args,
            kind="add_node",
            list_field=list_field,
            node_model=item_model,
        ),
        ArtifactToolSpec(
            name="replace_node",
            description=(
                f"Replace an existing {item_model.__name__} in `{list_field}` by id. "
                "Use this to correct content after a finish rejection. "
                "Does not change parent/child attachment."
            ),
            parameter_model=replace_args,
            kind="replace_node",
            list_field=list_field,
            node_model=item_model,
        ),
        ArtifactToolSpec(
            name="remove_node",
            description=(
                f"Remove an existing {item_model.__name__} from `{list_field}` by id, "
                "including its descendant subtree."
            ),
            parameter_model=remove_args,
            kind="remove_node",
            list_field=list_field,
            node_model=item_model,
        ),
    ]


def _node_parameter_model(
    item_model: type[BaseModel],
    *,
    include_parent_id: bool,
) -> type[BaseModel]:
    remaining: dict[str, tuple[object, object]] = {}
    if include_parent_id:
        remaining["parent_id"] = (
            str | None,
            Field(default=None, description="Parent node id, or null for a root node"),
        )
    for name, field_info in item_model.model_fields.items():
        if name == "children":
            continue
        remaining[name] = (field_info.annotation, field_info)
    suffix = "AddNodeArgs" if include_parent_id else "ReplaceNodeArgs"
    return create_model(
        f"{item_model.__name__}{suffix}",
        **cast(dict[str, Any], remaining),
    )


def _list_item_model(annotation: object) -> type[BaseModel] | None:
    unwrapped = _unwrap(annotation)
    origin = get_origin(unwrapped)
    if origin is not list:
        return None
    args = get_args(unwrapped)
    if not args:
        return None
    item = _unwrap(args[0])
    if isinstance(item, type) and issubclass(item, BaseModel):
        return item
    return None


def _is_host_owned_field(field_info: FieldInfo) -> bool:
    extra = field_info.json_schema_extra
    return isinstance(extra, dict) and extra.get("x_host_owned") is True


def _is_recursive_node(item_model: type[BaseModel]) -> bool:
    for field_info in item_model.model_fields.values():
        nested = _list_item_model(field_info.annotation)
        if nested is item_model:
            return True
    return False


def _unwrap(annotation: object) -> object:
    origin = get_origin(annotation)
    if origin is Annotated:
        return _unwrap(get_args(annotation)[0])
    if origin in {Union, UnionType}:
        args = [argument for argument in get_args(annotation) if argument is not type(None)]
        if len(args) == 1:
            return _unwrap(args[0])
    return annotation


def _singularize(name: str) -> str:
    if name.endswith("ies"):
        return f"{name[:-3]}y"
    if name.endswith("sses"):
        return name[:-2]
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name


def _snake_case(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name.lstrip("_")).lower()
